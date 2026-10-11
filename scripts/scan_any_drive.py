#!/usr/bin/env python3
"""通用 Windows 盘只读存储扫描器（支持系统盘与非系统盘）。

补充 scan.py 的能力：scan.py 专为 C 盘系统目录设计（硬编码 SystemDrive、
Program Files、Windows 等），本脚本面向「任意盘符」的用户数据场景，
回答四个问题：
    1. 空间被谁占了（大文件，按体积倒序）      -> large_files
    2. 哪些东西很久没碰过了（按最后访问时间）  -> stale_files
    3. 哪些是临时/垃圾产物                     -> temp_files
    4. 哪些可能是重复文件（近似，非精确）      -> duplicate_groups

单次全盘遍历同时完成上述四项 + 一级目录体积统计（避免二次遍历翻倍耗时）。

STRICTLY READ-ONLY：只调用 os.scandir / os.stat / os.path.getsize /
os.path.getatime，绝不创建、移动、修改、删除被扫描的任何文件。
唯一的写操作是 `--out` 指定的结果落盘。

Usage:
    python scan_any_drive.py --drive D: --out D:\\...\\scan.json
    python scan_any_drive.py                    # 不带 --drive 时扫系统盘

输出 JSON 结构（供 Agent 分级与 server.py 生成网页清单）:
{
  "generated_at": "2026-10-11 12:00:00",
  "scan_seconds": 123.4,
  "readonly": true,
  "target_drive": "D:\\\\",
  "non_system_drive": true,
  "disk": {"total_h": "752.0 GB", "used_h": "649.0 GB",
            "free_h": "103.0 GB", "free_pct": 13.7},
  "system": {...},
  "params": {...},
  "top_dirs": [{name, path, size_kb, size_h, files, mtime}, ...],
  "large_files": [{path, name, size_kb, size_h, ext, mtime, atime,
                   age_days, last_access_days}, ...],
  "stale_files": [...],          # 同结构，按「距上次访问天数」降序（最久未用在前）
  "temp_files": [{path, name, size_kb, size_h, ext, mtime, reason}, ...],
  "duplicate_groups": [{
      "size_h": "5.0 GB", "size_kb": 5242880, "count": 2,
      "exact": false, "method": "size + head-1MB-sha256",
      "note": "近似判定，非精确：仅比对体积与文件头部 1MB 指纹……",
      "files": [{path, size_h, mtime}, ...]}],
  "scanned": {"files": 3650316, "denied": 2053, "elapsed": 123.4,
              "truncated": false}
}
"""
import argparse
import hashlib
import heapq
import json
import os
import platform
import shutil
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")

# ── 默认参数 ────────────────────────────────────────────────────────────────
DEFAULT_MIN_FILE_MB = 200# 「大文件」阈值
DEFAULT_TOP_LARGE = 120         # large_files 返回条数
DEFAULT_TOP_DIRS = 40           # top_dirs 返回条数
DEFAULT_STALE_DAYS = 180        # 「很久没用」阈值
DEFAULT_TOP_STALE = 120
DEFAULT_MIN_DUP_MB = 100        # 重复检测最小体积
DEFAULT_FP_SIZE = 1 << 20       # 指纹取文件头 1MB
DEFAULT_MAX_FILES = 5_000_000# 遍历文件数上限（安全阀，默认远高于真实盘文件数）
DEFAULT_MAX_BIG = 200_000       # 大文件候选池上限（按体积保留最大的）
DEFAULT_MAX_TEMPS = 50_000      # 临时文件候选池上限（按体积保留最大的）
DEFAULT_MAX_DUP_GROUPS = 60
DEFAULT_MAX_DUP_MEMBERS = 8     # 每组最多取几个成员做指纹

# 临时/垃圾文件特征：扩展名 -> 判定理由
TEMP_EXTS = {
    ".tmp": "临时文件", ".temp": "临时文件", ".bak": "备份残留",
    ".old": "旧版残留", ".orig": "原始文件残留", ".swp": "编辑器交换文件",
    ".dmp": "崩溃转储", ".chk": "磁盘检查残留", ".log": "日志文件",
    ".nib": "安装包残留", ".partial": "未完成下载", ".crdownload": "未完成下载",
    ".part": "分片残留", ".download": "未完成下载", ".cache": "缓存文件",
}
TEMP_NAME_PATTERNS = ["~", "thumbs.db", "desktop.ini", ".ds_store"]

# 受保护目录名（按「路径分段」精确匹配，大小写不敏感，不绑定盘符）。
# 这些目录不得进入清理候选清单：工作区、笔记库、WorkBuddy 数据、系统关键目录。
# server.py 侧另有一道无条件拒绝作为硬保证（纵深防御，非唯一防线）。
PROTECTED_DIR_NAMES = {
    "devsource",# D:\DevSource   —— 代码工作区
    "思源",                          # D:\思源      —— 笔记唯一真源
    ".workbuddy",                # D:\.workbuddy —— WorkBuddy 数据（注意前导点）
    "workbuddy",                      # D:\WorkBuddy
    "claude-mem-data",                # D:\claude-mem-data
    "system volume information",      # 系统还原点
    "windowsapps",                    # UWP 应用
    "wpsystem",                       # UWP 系统数据
    "$recycle.bin",                   # 回收站
    "recovery",                        # 恢复分区数据
    "$windows.~bt",               # 升级残留
}


def human(kb):
    """KB -> 人类可读串。"""
    n = float(kb) * 1024
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit not in ("B", "KB") else f"{int(n)} {unit}"
        n /= 1024


def normalize_drive(d):
    """把 'd' / 'D:' / 'D:\\' 统一成 'D:\\'；缺省回落到系统盘。"""
    d = (d or "").strip().strip('"')
    if not d:
        return os.environ.get("SystemDrive", "C:") + "\\"
    letter = d[0].upper()
    if not os.path.exists(f"{letter}:\\"):
        raise SystemExit(f"盘符不存在: {letter}:\\")
    return f"{letter}:\\"


def is_protected(path):
    """判断路径是否落在受保护目录内。

    按路径分段（目录名）精确匹配，而非裸子串——避免 `D:\\备份\\DevSource\\x`
    这类盘根外同名目录漏保护，同时保留大小写不敏感。
    """
    parts = path.replace("/", "\\").split("\\")
    return any(p.lower() in PROTECTED_DIR_NAMES for p in parts)


def temp_reason(name, ext):
    """判定临时文件特征，返回理由；非临时返回 None。"""
    r = TEMP_EXTS.get(ext)
    if r:
        return r
    low = name.lower()
    for pat in TEMP_NAME_PATTERNS:
        if pat in low:
            return f"命名含 '{pat}'"
    return None


def scan_drive(root, min_bytes, max_files, max_big, max_temps):
    """单次全盘遍历。

    返回 (top_dirs, big_records, temp_records, state)：
      - top_dirs  : 盘根直接子项的体积/文件数统计（全量，不受 max_files 影响）
      - big/temps : 以最小堆维护的 top-N 候选池（按体积），内存可控
    """
    big_heap = []   # (size, seq, record)
    temp_heap = []  # (size, seq, record)
    dir_stat = {}   # 顶层名 -> {"size": bytes, "files": n, "path": str}
    state = {"files": 0, "denied": 0, "truncated": False}
    seq = 0

    def bump_top(name, path, size):
        st = dir_stat.get(name)
        if st is None:
            st = dir_stat[name] = {"size": 0, "files": 0, "path": path}
        st["size"] += size
        st["files"] += 1

    def push_big(rec):
        nonlocal seq
        seq += 1
        if len(big_heap) < max_big:
            heapq.heappush(big_heap, (rec["_size"], seq, rec))
        elif rec["_size"] > big_heap[0][0]:
            heapq.heapreplace(big_heap, (rec["_size"], seq, rec))

    def push_temp(rec):
        nonlocal seq
        seq += 1
        if len(temp_heap) < max_temps:
            heapq.heappush(temp_heap, (rec["_size"], seq, rec))
        elif rec["_size"] > temp_heap[0][0]:
            heapq.heapreplace(temp_heap, (rec["_size"], seq, rec))

    stack = [(root, None)]
    while stack:
        cur, top = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        name = e.name
                        child_top = name if cur == root else top
                        if e.is_dir(follow_symlinks=False):
                            stack.append((e.path, child_top))
                            # 目录自身的体积在遍历其内部文件时累加（空目录记 0）
                            dir_stat.setdefault(child_top, {"size": 0, "files": 0,
                                                             "path": e.path})
                            continue
                        if not e.is_file(follow_symlinks=False):
                            continue
                        state["files"] += 1
                        if state["files"] > max_files:
                            state["truncated"] = True
                            break
                        st = e.stat(follow_symlinks=False)
                        size = st.st_size
                        ext = os.path.splitext(name)[1].lower()
                        if child_top:
                            bump_top(child_top, os.path.join(root, child_top), size)
                        # 大文件候选（受保护路径不入候选）
                        if size >= min_bytes and not is_protected(e.path):
                            push_big({
                                "path": e.path, "name": name,
                                "size_kb": size // 1024,
                                "size_h": human(size // 1024), "ext": ext,
                                "mtime": time.strftime("%Y-%m-%d",
                                                       time.localtime(st.st_mtime)),
                                "atime": time.strftime("%Y-%m-%d",
                                                       time.localtime(st.st_atime)),
                                "_mtime": st.st_mtime, "_atime": st.st_atime,
                                "_size": size,
                            })
                        # 临时文件候选
                        reason = temp_reason(name, ext)
                        if reason and size >= 1024 and not is_protected(e.path):
                            push_temp({
                                "path": e.path, "name": name,
                                "size_kb": size // 1024,
                                "size_h": human(size // 1024), "ext": ext,
                                "mtime": time.strftime("%Y-%m-%d",
                                                       time.localtime(st.st_mtime)),
                                "reason": reason, "_size": size,
                            })
                    except (OSError, PermissionError):
                        state["denied"] += 1
        except (OSError, PermissionError):
            state["denied"] += 1

    top_dirs = []
    for name, st in dir_stat.items():
        kb = st["size"] // 1024
        top_dirs.append({
            "name": name, "path": st["path"], "size_kb": kb,
            "size_h": human(kb), "files": st["files"],
            "mtime": _safe_mtime(st["path"]),
        })
    top_dirs.sort(key=lambda r: r["size_kb"], reverse=True)

    big = [r[2] for r in sorted(big_heap, key=lambda x: x[0], reverse=True)]
    temps = [r[2] for r in sorted(temp_heap, key=lambda x: x[0], reverse=True)]
    return top_dirs[:DEFAULT_TOP_DIRS], big, temps, state


def _safe_mtime(path):
    try:
        return time.strftime("%Y-%m-%d", time.localtime(os.path.getmtime(path)))
    except (OSError, PermissionError):
        return "?"


def fingerprint(path, size):
    """文件指纹：体积 + 头部 1MB 的 sha256。用于**近似**重复判定。"""
    h = hashlib.sha256()
    h.update(str(size).encode())
    try:
        with open(path, "rb") as f:
            remaining = DEFAULT_FP_SIZE
            while remaining > 0:
                chunk = f.read(min(65536, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
    except OSError:
        return None
    return h.hexdigest()


def find_duplicates(files, min_dup_bytes):
    """近似重复检测：先按体积分组，组内成员 >=2 才取头部指纹比对。

    去重：同一文件可能被多个同体积组收编（不同组内其余成员头部指纹不同），
    会导致它在清单中重复出现、虚增可回收空间。故此处按 path 全局去重，
    每个文件只归入「可回收空间最大」的那一组。
    """
    by_size = {}
    for f in files:
        if f["_size"] < min_dup_bytes:
            continue
        by_size.setdefault(f["_size"], []).append(f)

    # 先按体积分桶，同体积内按头部指纹细分
    groups = []
    for size, members in by_size.items():
        if len(members) < 2:
            continue
        cand = members[:DEFAULT_MAX_DUP_MEMBERS]
        buckets = {}
        for m in cand:
            fp = fingerprint(m["path"], m["_size"])
            if fp is None:
                continue
            buckets.setdefault(fp, []).append(m)
        for _fp, same in buckets.items():
            if len(same) < 2:
                continue
            groups.append({
                "size_h": human(size // 1024), "size_kb": size // 1024,
                "count": len(same), "exact": False,
                "method": "size + head-1MB-sha256",
                "note": "近似判定，非精确：仅比对体积与文件头部 1MB 指纹，"
                        "同体积同头部但内容不同的文件会被误判为重复，"
                        "删除前请人工确认",
                "files": [{"path": m["path"], "name": m["name"],
                           "size_h": m["size_h"], "mtime": m["mtime"],
                           "atime": m["atime"]} for m in same],
            })

    # 全局去重：同一文件只保留在「可回收空间最大」的组中
    claimed = set()
    deduped = []
    for g in sorted(groups, key=lambda g: g["size_kb"] * (g["count"] - 1),
                    reverse=True):
        keep_paths = []
        for m in g["files"]:
            if m["path"] in claimed:
                continue
            claimed.add(m["path"])
            keep_paths.append(m)
        if len(keep_paths) < 2:
            continue          # 去重后不足2 个文件，不再构成重复
        g["files"] = keep_paths
        g["count"] = len(keep_paths)
        deduped.append(g)
        if len(deduped) >= DEFAULT_MAX_DUP_GROUPS:
            break
    return deduped



def clean_records(records):
    """剥离内部字段 _size/_mtime/_atime（不进入报告 JSON）。"""
    return [{k: v for k, v in r.items() if not k.startswith("_")} for r in records]


def main():
    ap = argparse.ArgumentParser(description="Windows 任意盘只读存储扫描器")
    ap.add_argument("--drive", default="", help="目标盘符，如 D:；缺省=系统盘")
    ap.add_argument("--out", default="", help="输出 JSON 路径；缺省=stdout")
    ap.add_argument("--min-file-mb", type=int, default=DEFAULT_MIN_FILE_MB,
                    help=f"大文件阈值 MB（默认 {DEFAULT_MIN_FILE_MB}）")
    ap.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS,
                    help=f"陈旧阈值天数（默认 {DEFAULT_STALE_DAYS}）")
    ap.add_argument("--min-dup-mb", type=int, default=DEFAULT_MIN_DUP_MB,
                    help=f"重复检测最小体积 MB（默认 {DEFAULT_MIN_DUP_MB}）")
    ap.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES,
                    help=f"遍历文件数上限（默认 {DEFAULT_MAX_FILES}）")
    args = ap.parse_args()

    if not sys.platform.startswith("win"):
        print(json.dumps({"error": "unsupported_platform"}, ensure_ascii=False))
        return

    target = normalize_drive(args.drive)
    sysdrive = os.environ.get("SystemDrive", "C:").upper()
    non_system = not target.upper().startswith(sysdrive)

    started = time.time()
    print(f"正在扫描 {target} （只读，单次遍历）...", file=sys.stderr, flush=True)

    t, u, f = shutil.disk_usage(target)
    disk = {"total_h": human(t // 1024), "used_h": human(u // 1024),
            "free_h": human(f // 1024),
            "free_pct": round(100 * f / (t or 1), 1)}

    min_bytes = args.min_file_mb * 1024 * 1024
    top_dirs, big, temps, state = scan_drive(
        target, min_bytes, args.max_files, DEFAULT_MAX_BIG, DEFAULT_MAX_TEMPS)
    print(f"  遍历 {state['files']} 文件（拒绝访问 {state['denied']}"
          f"{'，已截断' if state['truncated'] else ''}），"
          f"大文件候选 {len(big)}，临时文件候选 {len(temps)}",
          file=sys.stderr, flush=True)

    # R1：从大到小倒序
    now = time.time()
    for r in big:
        r["age_days"] = int((now - r["_mtime"]) / 86400)
        r["last_access_days"] = int((now - r["_atime"]) / 86400)
    large_files = clean_records(big[:DEFAULT_TOP_LARGE])

    # R2/R4：久未使用（距上次访问天数降序 = 最久没碰的在前）
    stale_pool = [r for r in big if r["last_access_days"] >= args.stale_days]
    stale_pool.sort(key=lambda r: r["last_access_days"], reverse=True)
    stale_files = clean_records(stale_pool[:DEFAULT_TOP_STALE])

    # R5：临时文件
    temp_files = clean_records(temps[:DEFAULT_TOP_LARGE])

    # R3：近似重复（用全部大文件候选做池，比只截 top 更准）
    print("  重复检测（近似：体积 + 头部 1MB 指纹）...", file=sys.stderr, flush=True)
    dup_groups = find_duplicates(big, args.min_dup_mb * 1024 * 1024)
    print(f"  疑似重复组: {len(dup_groups)}", file=sys.stderr, flush=True)

    elapsed = round(time.time() - started, 1)
    data = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_seconds": elapsed,
        "readonly": True,
        "target_drive": target,
        "non_system_drive": non_system,
        "disk": disk,
        "system": {
            "os": platform.system() + " " + platform.release(),
            "arch": os.environ.get("PROCESSOR_ARCHITECTURE", platform.machine()),
            "user": os.environ.get("USERNAME", ""),
            "home": os.environ.get("USERPROFILE", ""),
        },
        "params": {
            "min_file_mb": args.min_file_mb, "stale_days": args.stale_days,
            "min_dup_mb": args.min_dup_mb, "max_files": args.max_files,
        },
        "top_dirs": top_dirs,
        "large_files": large_files,
        "stale_files": stale_files,
        "temp_files": temp_files,
        "duplicate_groups": dup_groups,
        "scanned": {"files": state["files"], "denied": state["denied"],
                    "elapsed": elapsed, "truncated": state["truncated"]},
    }

    if args.out:
        out_dir = os.path.dirname(os.path.abspath(args.out))
        os.makedirs(out_dir, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        print(f"已写入 {args.out}（耗时 {elapsed}s）", file=sys.stderr)
    else:
        json.dump(data, sys.stdout, ensure_ascii=False, indent=2)
        print(f"\n扫描完成，耗时 {elapsed}s", file=sys.stderr)


if __name__ == "__main__":
    main()