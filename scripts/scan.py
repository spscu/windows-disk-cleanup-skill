#!/usr/bin/env python3
"""Windows C盘只读存储扫描器。

专门扫描 Windows C盘的存储占用情况，收集磁盘信息、各目录大小，
输出 JSON 供 Agent 分析分级。

STRICTLY READ-ONLY: 只读取大小/列表/元信息。绝不创建、移动或删除任何文件。

输出 JSON 结构:
{
  "generated_at": "2026-06-13 14:00:00",
  "scan_seconds": 42.1,
  "system": {
    os, build, arch, user, home, filesystem,
    disk_total, disk_used, disk_free,
    disk_name: "C:\\",
    disks: [{name, total, used, free}]  # 所有盘符
  },
  "groups": {
    "<group>": [{name, path, size_kb, size_h, denied?}], ...
  }
}
"""
import json
import os
import platform
import shutil
import string
import sys
import time

HOME = os.environ.get("USERPROFILE", os.path.expanduser("~"))
SYSDRIVE = os.environ.get("SystemDrive", "C:") + "\\"


def human(kb):
    """KB 数值 -> 人类可读字符串，如 '12.3 GB'。"""
    n = float(kb) * 1024
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit not in ("B", "KB") else f"{int(n)} {unit}"
        n /= 1024


def dir_size_bytes(path):
    """递归计算目录大小（字节）。使用 os.scandir，跳过符号链接和不可读目录。"""
    total = 0
    try:
        with os.scandir(path) as it:
            for e in it:
                try:
                    if e.is_symlink():
                        continue
                    if e.is_file(follow_symlinks=False):
                        total += e.stat(follow_symlinks=False).st_size
                    elif e.is_dir(follow_symlinks=False):
                        total += dir_size_bytes(e.path)
                except (PermissionError, OSError):
                    continue
    except (PermissionError, OSError):
        pass
    return total


def scandir_children(path, min_kb=51200, limit=40):
    """列出目录子项并按大小降序排列，过滤小于 min_kb 的项。"""
    if not path or not os.path.isdir(path):
        return []
    results = []
    try:
        entries = sorted(os.listdir(path))
    except PermissionError:
        return [{"name": "(permission denied)", "path": path,
                 "size_kb": 0, "size_h": "?", "denied": True}]
    for name in entries:
        child = os.path.join(path, name)
        if os.path.islink(child):
            continue
        try:
            kb = (os.path.getsize(child) if os.path.isfile(child)
                  else dir_size_bytes(child)) // 1024
        except (PermissionError, OSError):
            continue
        if kb < min_kb:
            continue
        results.append({"name": name, "path": child, "size_kb": kb, "size_h": human(kb)})
    results.sort(key=lambda r: r["size_kb"], reverse=True)
    return results[:limit]


def list_drives():
    """枚举所有盘符及其容量信息。"""
    drives = []
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        if os.path.exists(root):
            try:
                t, u, f = shutil.disk_usage(root)
                drives.append({"name": root, "total": human(t // 1024),
                               "used": human(u // 1024), "free": human(f // 1024)})
            except Exception:
                continue
    return drives


def system_info():
    """收集 Windows 系统信息和 C盘容量数据。"""
    info = {}
    info["os"] = platform.system() + " " + platform.release()
    info["build"] = platform.version()
    info["arch"] = os.environ.get("PROCESSOR_ARCHITECTURE", platform.machine())
    info["user"] = os.environ.get("USERNAME", "")
    info["home"] = HOME
    total, used, free = "?", "?", "?"
    try:
        t, u, f = shutil.disk_usage(SYSDRIVE)
        total, used, free = human(t // 1024), human(u // 1024), human(f // 1024)
    except Exception:
        pass
    info["disk_total"], info["disk_used"], info["disk_free"] = total, used, free
    info["filesystem"] = "NTFS"
    info["purgeable"] = ""
    info["disk_name"] = SYSDRIVE
    info["disks"] = list_drives()
    return info


def scan_c_drive_root():
    """扫描 C盘根目录的顶层大目录和文件。"""
    results = []
    denied = []
    try:
        entries = os.listdir(SYSDRIVE)
    except PermissionError:
        return [{"name": "(permission denied)", "path": SYSDRIVE,
                 "size_kb": 0, "size_h": "?", "denied": True}], denied
    for name in sorted(entries):
        child = os.path.join(SYSDRIVE, name)
        if os.path.islink(child):
            continue
        try:
            if os.path.isfile(child):
                kb = os.path.getsize(child) // 1024
            elif os.path.isdir(child):
                kb = dir_size_bytes(child) // 1024
            else:
                continue
        except (PermissionError, OSError):
            denied.append(child)
            continue
        if kb < 102400:  # 100MB 阈值
            continue
        results.append({"name": name, "path": child, "size_kb": kb, "size_h": human(kb)})
    results.sort(key=lambda r: r["size_kb"], reverse=True)
    return results[:30], denied


def scan_user_profile():
    """扫描用户配置文件目录（%USERPROFILE%）。"""
    return scandir_children(HOME, min_kb=102400, limit=40)


def scan_appdata_local():
    """扫描本地应用数据（%LOCALAPPDATA%）—— 浏览器缓存、应用数据的主要位置。"""
    local = os.environ.get("LOCALAPPDATA", os.path.join(HOME, "AppData", "Local"))
    return scandir_children(local, min_kb=51200, limit=40)


def scan_appdata_roaming():
    """扫描漫游应用数据（%APPDATA%）。"""
    roaming = os.environ.get("APPDATA", os.path.join(HOME, "AppData", "Roaming"))
    return scandir_children(roaming, min_kb=51200, limit=40)


def scan_temp():
    """扫描临时文件目录（%TEMP% 和 C:\\Windows\\Temp）。"""
    temp_user = os.environ.get("TEMP", os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.join(HOME, "AppData", "Local")), "Temp"))
    temp_system = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp")

    results = []
    # 用户临时目录
    user_items = scandir_children(temp_user, min_kb=10240, limit=20)
    for item in user_items:
        item["source"] = "user_temp"
    results.extend(user_items)

    # 系统临时目录
    sys_items = scandir_children(temp_system, min_kb=10240, limit=20)
    for item in sys_items:
        item["source"] = "system_temp"
    results.extend(sys_items)

    # 计算临时目录总大小
    total_kb = 0
    for p in [temp_user, temp_system]:
        if os.path.isdir(p):
            try:
                total_kb += dir_size_bytes(p) // 1024
            except (PermissionError, OSError):
                pass

    results.sort(key=lambda r: r["size_kb"], reverse=True)
    return results[:30], total_kb


def scan_browser_caches():
    """专项扫描浏览器缓存（Chrome、Edge、Firefox）。"""
    local = os.environ.get("LOCALAPPDATA", os.path.join(HOME, "AppData", "Local"))
    browsers = [
        ("Chrome", os.path.join(local, "Google", "Chrome", "User Data")),
        ("Edge", os.path.join(local, "Microsoft", "Edge", "User Data")),
        ("Firefox", os.path.join(local, "Mozilla", "Firefox")),
    ]
    results = []
    for browser_name, profile_dir in browsers:
        if not os.path.isdir(profile_dir):
            continue
        # 总大小
        try:
            total_kb = dir_size_bytes(profile_dir) // 1024
        except (PermissionError, OSError):
            continue
        if total_kb < 51200:
            continue

        # 缓存子目录大小
        cache_dirs = []
        for profile in os.listdir(profile_dir) if os.path.isdir(profile_dir) else []:
            profile_path = os.path.join(profile_dir, profile)
            if not os.path.isdir(profile_path):
                continue
            for cache_name in ("Cache", "Code Cache", "GPUCache", "Service Worker",
                               "ShaderCache", "GrShaderCache", "DawnCache"):
                cache_path = os.path.join(profile_path, cache_name)
                if os.path.isdir(cache_path):
                    try:
                        kb = dir_size_bytes(cache_path) // 1024
                    except (PermissionError, OSError):
                        continue
                    if kb >= 10240:
                        cache_dirs.append({
                            "name": f"{browser_name}/{profile}/{cache_name}",
                            "path": cache_path, "size_kb": kb, "size_h": human(kb)
                        })

        results.append({
            "name": browser_name,
            "path": profile_dir,
            "size_kb": total_kb,
            "size_h": human(total_kb),
            "cache_dirs": sorted(cache_dirs, key=lambda r: r["size_kb"], reverse=True)
        })
    results.sort(key=lambda r: r["size_kb"], reverse=True)
    return results


def scan_dev_caches():
    """扫描开发工具缓存目录。"""
    local = os.environ.get("LOCALAPPDATA", os.path.join(HOME, "AppData", "Local"))
    dev_paths = [
        (os.path.join(HOME, ".cache"), ".cache"),
        (os.path.join(HOME, ".npm"), ".npm"),
        (os.path.join(HOME, ".gradle"), ".gradle"),
        (os.path.join(HOME, ".m2"), ".m2 (Maven)"),
        (os.path.join(HOME, ".nuget", "packages"), ".nuget/packages"),
        (os.path.join(HOME, ".cargo"), ".cargo"),
        (os.path.join(HOME, ".rustup"), ".rustup"),
        (os.path.join(HOME, ".conda", "pkgs"), ".conda/pkgs"),
        (os.path.join(HOME, ".android", "avd"), ".android/avd (模拟器)"),
        (os.path.join(local, "pip", "Cache"), "pip Cache"),
        (os.path.join(local, "Yarn"), "Yarn"),
        (os.path.join(local, "uv"), "uv"),
        (os.path.join(local, "ms-playwright"), "Playwright 浏览器"),
        (os.path.join(local, "go-build"), "Go build cache"),
        (os.path.join(local, "pnpm-store"), "pnpm store"),
        (os.path.join(local, "pnpm", "store"), "pnpm store v3+"),
        (os.path.join(HOME, "go", "pkg"), "Go pkg"),
        (os.path.join(HOME, ".docker"), ".docker"),
    ]
    results = []
    for path, label in dev_paths:
        if not os.path.isdir(path):
            continue
        try:
            kb = dir_size_bytes(path) // 1024
        except (PermissionError, OSError):
            continue
        if kb < 51200:
            continue
        results.append({"name": label, "path": path, "size_kb": kb, "size_h": human(kb)})
    results.sort(key=lambda r: r["size_kb"], reverse=True)
    return results


def scan_downloads():
    """扫描下载文件夹，重点标记安装包残留（.exe, .msi, .zip 等大文件）。"""
    downloads = os.path.join(HOME, "Downloads")
    if not os.path.isdir(downloads):
        return [], 0

    items = scandir_children(downloads, min_kb=51200, limit=30)

    # 统计安装包文件
    installer_exts = {".exe", ".msi", ".msix", ".appx", ".iso"}
    installer_total_kb = 0
    installer_files = []
    try:
        with os.scandir(downloads) as it:
            for e in it:
                try:
                    if e.is_file(follow_symlinks=False):
                        ext = os.path.splitext(e.name)[1].lower()
                        if ext in installer_exts:
                            kb = e.stat(follow_symlinks=False).st_size // 1024
                            if kb >= 10240:  # 10MB+
                                installer_files.append({
                                    "name": e.name, "path": e.path,
                                    "size_kb": kb, "size_h": human(kb)
                                })
                                installer_total_kb += kb
                except (PermissionError, OSError):
                    continue
    except (PermissionError, OSError):
        pass
    installer_files.sort(key=lambda r: r["size_kb"], reverse=True)

    total_kb = 0
    if os.path.isdir(downloads):
        try:
            total_kb = dir_size_bytes(downloads) // 1024
        except (PermissionError, OSError):
            pass

    return items, total_kb, installer_total_kb, installer_files[:20]


def scan_windows_system_cleanable():
    """扫描 Windows 系统中可安全清理的项（只读，不执行任何清理）。"""
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    results = []

    # Windows Update 下载缓存
    wu_cache = os.path.join(sysroot, "SoftwareDistribution", "Download")
    if os.path.isdir(wu_cache):
        try:
            kb = dir_size_bytes(wu_cache) // 1024
            if kb >= 51200:
                results.append({"name": "Windows Update 缓存",
                                "path": wu_cache, "size_kb": kb, "size_h": human(kb),
                                "clean_cmd": "以管理员运行: 设置 > 系统 > 存储 > 临时文件 > Windows 更新清理"})
        except (PermissionError, OSError):
            pass

    # Windows 预取文件
    prefetch = os.path.join(sysroot, "Prefetch")
    if os.path.isdir(prefetch):
        try:
            kb = dir_size_bytes(prefetch) // 1024
            if kb >= 10240:
                results.append({"name": "预取文件 (Prefetch)",
                                "path": prefetch, "size_kb": kb, "size_h": human(kb)})
        except (PermissionError, OSError):
            pass

    # Windows 错误报告/崩溃转储
    crash_dumps = [
        os.path.join(HOME, "AppData", "Local", "CrashDumps"),
        os.path.join(sysroot, "Minidump"),
        os.path.join(sysroot, "MEMORY.DMP"),
    ]
    for dump_path in crash_dumps:
        if os.path.exists(dump_path):
            try:
                if os.path.isfile(dump_path):
                    kb = os.path.getsize(dump_path) // 1024
                else:
                    kb = dir_size_bytes(dump_path) // 1024
                if kb >= 10240:
                    results.append({"name": f"崩溃转储 ({os.path.basename(dump_path)})",
                                    "path": dump_path, "size_kb": kb, "size_h": human(kb)})
            except (PermissionError, OSError):
                pass

    # Windows 日志
    logs_dir = os.path.join(sysroot, "Logs")
    if os.path.isdir(logs_dir):
        try:
            kb = dir_size_bytes(logs_dir) // 1024
            if kb >= 51200:
                results.append({"name": "Windows 日志",
                                "path": logs_dir, "size_kb": kb, "size_h": human(kb)})
        except (PermissionError, OSError):
            pass

    # C盘根目录系统文件大小估算
    sys_files = {
        "pagefile.sys": "虚拟内存页面文件（系统管理，不要手动删）",
        "hiberfil.sys": "休眠文件（可用 powercfg /hibernate off 关闭休眠释放）",
        "swapfile.sys": "UWP 应用交换文件（系统管理）",
    }
    for fname, desc in sys_files.items():
        fpath = os.path.join(SYSDRIVE, fname)
        if os.path.exists(fpath):
            try:
                kb = os.path.getsize(fpath) // 1024
                if kb >= 102400:
                    results.append({"name": fname, "path": fpath,
                                    "size_kb": kb, "size_h": human(kb),
                                    "note": desc, "system_file": True})
            except (PermissionError, OSError):
                pass

    results.sort(key=lambda r: r["size_kb"], reverse=True)
    return results


def scan_recycle_bin():
    """估算回收站大小。"""
    recycle_bin = os.path.join(SYSDRIVE, "$Recycle.Bin")
    if not os.path.isdir(recycle_bin):
        return None
    try:
        kb = dir_size_bytes(recycle_bin) // 1024
        if kb >= 51200:
            return {"name": "回收站 ($Recycle.Bin)", "path": recycle_bin,
                    "size_kb": kb, "size_h": human(kb)}
    except (PermissionError, OSError):
        pass
    return None


def scan_program_files():
    """扫描已安装程序目录，按大小排列。"""
    results = []
    for env_key, default in [("ProgramFiles", r"C:\Program Files"),
                              ("ProgramFiles(x86)", r"C:\Program Files (x86)")]:
        pf_dir = os.environ.get(env_key, default)
        if not os.path.isdir(pf_dir):
            continue
        items = scandir_children(pf_dir, min_kb=102400, limit=20)
        for item in items:
            item["install_dir"] = pf_dir
        results.extend(items)
    results.sort(key=lambda r: r["size_kb"], reverse=True)
    return results[:30]


def main():
    if not sys.platform.startswith("win"):
        print(json.dumps({"error": "unsupported_platform", "platform": sys.platform,
                          "message": "scan.py 仅支持 Windows 系统。"},
                         ensure_ascii=False))
        return

    started = time.time()
    print("正在扫描 C盘存储...（可能需要几分钟）", file=sys.stderr)

    system = system_info()

    groups = {}
    all_denied = []

    # C盘根目录
    print("  扫描 C:\\ 根目录...", file=sys.stderr)
    root_items, root_denied = scan_c_drive_root()
    groups["c_drive_root"] = root_items
    all_denied.extend(root_denied)

    # 用户配置文件
    print("  扫描用户配置文件...", file=sys.stderr)
    groups["user_profile"] = scan_user_profile()

    # AppData
    print("  扫描 AppData\\Local...", file=sys.stderr)
    groups["appdata_local"] = scan_appdata_local()

    print("  扫描 AppData\\Roaming...", file=sys.stderr)
    groups["appdata_roaming"] = scan_appdata_roaming()

    # 临时文件
    print("  扫描临时文件...", file=sys.stderr)
    temp_items, temp_total_kb = scan_temp()
    groups["temp"] = temp_items
    groups["_temp_total_kb"] = temp_total_kb

    # 浏览器缓存
    print("  扫描浏览器缓存...", file=sys.stderr)
    groups["browser_caches"] = scan_browser_caches()

    # 开发缓存
    print("  扫描开发工具缓存...", file=sys.stderr)
    groups["dev_caches"] = scan_dev_caches()

    # 下载文件夹
    print("  扫描下载文件夹...", file=sys.stderr)
    dl_result = scan_downloads()
    if dl_result:
        dl_items, dl_total_kb, installer_kb, installer_files = dl_result
        groups["downloads"] = dl_items
        groups["_downloads_total_kb"] = dl_total_kb
        groups["_downloads_installer_kb"] = installer_kb
        groups["_downloads_installer_files"] = installer_files

    # 已安装程序
    print("  扫描已安装程序...", file=sys.stderr)
    groups["program_files"] = scan_program_files()

    # Windows 系统可清理项
    print("  扫描 Windows 系统可清理项...", file=sys.stderr)
    groups["windows_system"] = scan_windows_system_cleanable()

    # 回收站
    recycle = scan_recycle_bin()
    if recycle:
        groups["recycle_bin"] = recycle

    elapsed = round(time.time() - started, 1)
    print(f"扫描完成，耗时 {elapsed}s", file=sys.stderr)

    data = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_seconds": elapsed,
        "system": system,
        "groups": groups,
        "denied": all_denied,
    }
    print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
