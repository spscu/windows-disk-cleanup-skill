#!/usr/bin/env python3
"""为存储报告提供本地 HTTP 服务 + 安全删除 API（Windows 专用）。

启动在 127.0.0.1 + 随机端口 + 随机 token，服务交互式报告并暴露
POST /action 端点，支持 trash（移到回收站）和 rm（直接删除）操作。
用完 Ctrl+C 停止。

Usage:
    python server.py <analysis.json> [port]

    port 省略时使用随机端口；指定则固定该端口（便于收藏/自动化验收）。

安全模型（修改前必读）:
- 白名单: 只有报告中 green 项的 trash_paths 能被 rm，green+yellow 的 trash_paths
  能被 trash。所有请求路径经 realpath 校验，必须在白名单中且在【授权根】内。
- 授权根（allowed_roots）: 优先从 analysis JSON 顶层 `allowed_roots` 字段读取；
  若该字段缺失，回退到 %USERPROFILE%（保持旧分析 JSON 兼容 C 盘场景）。
  授权根必须由 agent 在生成分析时【显式列举具体子目录】，禁止写盘根（如 "D:\\"）。
- 硬红线: PROTECTED_DIR_NAMES 中的目录（工作区/笔记库/WorkBuddy 数据/系统目录）
  无论是否在白名单内一律拒绝——这是纵深防御的最后一道闸门。
- 非系统盘保护: analysis JSON 含 non_system_drive=true 时，只开放 trash（移回收站，
  可逆），永不开放 rm（直接删除），因为非系统盘数据不可再生性高于系统盘缓存。
- 绑定 127.0.0.1 仅本地访问; 每个 POST 需要 session token; Host 头必须是
  127.0.0.1（防止 DNS 重绑定攻击）。
- trash: 调用 SHFileOperationW(FOF_ALLOWUNDO) 移到回收站，可逆。
- rm: 立即删除，不可恢复。浏览器在发送前会弹 confirm 确认框。
"""
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "..", "assets", "report_template.html")
HOME = os.path.realpath(os.environ.get("USERPROFILE", os.path.expanduser("~")))
TOKEN = secrets.token_urlsafe(24)

# 硬红线：这些目录名出现在路径任一分段中，一律拒绝任何操作。
# 与 scan_any_drive.PROTECTED_DIR_NAMES 保持一致——纵深防御，不是唯一防线。
PROTECTED_DIR_NAMES = {
    "devsource", "思源", ".workbuddy", "workbuddy", "claude-mem-data",
    "system volume information", "windowsapps", "wpsystem", "$recycle.bin",
    "recovery", "$windows.~bt",
}

DATA = {}
TPL = ""
RM_ALLOW = set()
TRASH_ALLOW = set()
OPEN_ALLOW = set()
ALLOWED_ROOTS = []
NON_SYSTEM_DRIVE = False


def is_protected(path):
    """路径是否落在硬红线目录内（按分段精确匹配，大小写不敏感）。"""
    parts = os.path.realpath(path).replace("/", "\\").split("\\")
    return any(p.lower() in PROTECTED_DIR_NAMES for p in parts)


def expand(p):
    """规范化路径：展开用户变量 + realpath。"""
    return os.path.realpath(os.path.expandvars(os.path.expanduser(p)))


def load_roots(data):
    """确定授权根。

    优先读 analysis JSON 的 allowed_roots；缺失时回退 %USERPROFILE%（向后兼容）。
    盘根被拒绝：授权根必须具体到子目录，避免「整盘可删」。

    安全取向：若 allowed_roots 存在但**全部条目都是盘根**（即全部被丢弃），
    说明调用方的意图本身有问题。此时**不再回退到 %USERPROFILE%**（那等于授予
    整个用户主目录，方向是放宽而非收紧），而是直接拒绝授权——宁可不给删除能力，
    也不能因为配置错误而静默获得超出预期的删除范围。
    """
    raw = data.get("allowed_roots")
    if isinstance(raw, list) and raw:
        roots = [expand(r) for r in raw if r]
        clean = []
        for r in roots:
            _drive, rest = os.path.splitdrive(r)
            if rest.strip("\\") == "":
                continue          # 拒绝盘根
            clean.append(r)
        if clean:
            return clean
        # allowed_roots 存在但全部非法（都是盘根）→ 不放宽，直接拒绝
        print("⚠️ allowed_roots 中全部为盘根，已全部拒绝；本次不授予任何删除范围。",
              file=sys.stderr)
        return []
    return [HOME]



def load(src):
    """加载分析 JSON，构建三套白名单。"""
    with open(src, encoding="utf-8") as f:
        data = json.load(f)
    with open(TEMPLATE, encoding="utf-8") as f:
        tpl = f.read()

    # 三套白名单，权限从严到宽：
    #   rm    = 仅绿灯 trash_paths（可直接删的纯缓存）
    #   trash = 绿灯 + 橙灯 trash_paths（橙灯只准移回收站，不准直接删）
    #   open  = trash 全集 + 橙灯 path + 红灯 app_paths（仅"在资源管理器打开"，非破坏性）
    rm_allow, trash_allow, open_allow = set(), set(), set()

    for it in data.get("green", []):
        for p in (it.get("trash_paths") or []):
            rp = expand(p)
            rm_allow.add(rp)
            trash_allow.add(rp)
            open_allow.add(rp)

    for it in data.get("yellow", []):
        for p in (it.get("trash_paths") or []):
            rp = expand(p)
            trash_allow.add(rp)
            open_allow.add(rp)
        if it.get("path"):
            rp = expand(it["path"])
            if os.path.exists(rp):
                open_allow.add(rp)

    for it in data.get("red", []):
        for p in (it.get("app_paths") or []):
            rp = expand(p)
            if os.path.exists(rp):
                open_allow.add(rp)

    # 非系统盘：清空 rm 白名单，只保留 trash（可逆）。
    if data.get("non_system_drive"):
        rm_allow.clear()

    return data, tpl, rm_allow, trash_allow, open_allow


def move_to_trash(path):
    """将文件/目录移到 Windows 回收站（使用 SHFileOperationW + FOF_ALLOWUNDO）。"""
    _trash_windows(path)


def _trash_windows(path):
    """通过 ctypes 调用 SHFileOperationW 将文件移到回收站。
    FOF_ALLOWUNDO 标志确保操作可逆（可从回收站恢复）。

    ⚠️ 实测（本机 2026-10-11）：SHFileOperationW 在删除成功时也可能返回非 0
    （如 rc=2），且 fAnyOperationsAborted=0（未中止）——文件确已移入回收站。
    因此**不以返回码判定成败**，而以「文件是否仍存在于原路径」为准，
    否则会把成功操作误报为失败，让用户误以为删除无效而重复点击。
    """
    import ctypes
    from ctypes import wintypes

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_uint16),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    FO_DELETE = 3
    FOF_ALLOWUNDO = 0x0040
    FOF_NOCONFIRMATION = 0x0010
    FOF_SILENT = 0x0004

    existed = os.path.exists(path)
    op = SHFILEOPSTRUCTW()
    op.wFunc = FO_DELETE
    # pFrom 需要双 null 结尾的字符串列表
    op.pFrom = os.path.abspath(path) + "\x00\x00"
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT

    ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))

    if op.fAnyOperationsAborted:
        raise OSError(f"操作被中止，路径: {path}")

    # 判定标准：原先存在的文件，现在应当已不在原路径
    if existed and os.path.exists(path):
        raise OSError(f"移到回收站失败（返回码被忽略，文件仍在原处），路径: {path}")


def hard_delete(path):
    """直接删除文件或目录（不可恢复）。"""
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.remove(path)


def open_in_explorer(path):
    """在 Windows 资源管理器中打开指定路径。"""
    target = path if os.path.isdir(path) else os.path.dirname(path)
    subprocess.Popen(["explorer", target])


class Handler(BaseHTTPRequestHandler):
    """HTTP 请求处理器。"""

    def log_message(self, *a):
        pass  # 静默日志

    def _send(self, code, body, ctype="application/json"):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            blob = json.dumps(DATA, ensure_ascii=False)
            cfg = json.dumps({"token": TOKEN, "endpoint": "/action"})
            html = TPL.replace("__REPORT_DATA__", blob).replace("__DELETE_CONFIG__", cfg)
            self._send(200, html, "text/html; charset=utf-8")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        if self.path != "/action":
            self._send(404, json.dumps({"ok": False, "error": "not found"}))
            return

        # DNS 重绑定防护：只接受本地 Host
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost"):
            self._send(403, json.dumps({"ok": False, "error": "Host 不被允许"}))
            return

        n = int(self.headers.get("Content-Length", 0))
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            self._send(400, json.dumps({"ok": False, "error": "请求格式错误"}))
            return

        # Token 验证
        if req.get("token") != TOKEN:
            self._send(403, json.dumps({"ok": False, "error": "token 校验失败"}))
            return

        mode = req.get("mode")
        allow = {"rm": RM_ALLOW, "trash": TRASH_ALLOW, "open": OPEN_ALLOW}.get(mode)
        if allow is None:
            self._send(400, json.dumps({"ok": False, "error": "未知操作"}))
            return

        done = []
        for p in (req.get("paths") or []):
            rp = expand(p)

            # 白名单校验
            if rp not in allow:
                self._send(403, json.dumps(
                    {"ok": False, "error": f"路径不在白名单: {p}"}))
                return

            # 硬红线：受保护目录无条件拒绝（纵深防御的最后闸门）
            if is_protected(rp):
                self._send(403, json.dumps(
                    {"ok": False, "error": f"路径命中受保护目录，禁止操作: {p}"}))
                return

            # 路径边界校验：必须在授权根内
            if not any(rp == root or rp.startswith(root + os.sep)
                       for root in ALLOWED_ROOTS):
                # open 模式额外允许 Program Files（只读展示，非破坏性）
                if mode == "open":
                    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
                    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
                    if not (rp.startswith(pf + os.sep) or rp.startswith(pf86 + os.sep)
                            or rp == pf or rp == pf86):
                        self._send(403, json.dumps(
                            {"ok": False, "error": f"路径越界: {p}"}))
                        return
                else:
                    self._send(403, json.dumps(
                        {"ok": False, "error": f"路径越界: {p}"}))
                    return

            try:
                if mode == "open":
                    open_in_explorer(rp)
                elif not os.path.exists(rp):
                    pass  # 已不存在，视为成功
                elif mode == "trash":
                    move_to_trash(rp)
                else:
                    hard_delete(rp)
                done.append(p)
            except Exception as e:
                self._send(500, json.dumps({"ok": False, "error": str(e)}))
                return

        self._send(200, json.dumps({"ok": True, "done": done}))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    if not sys.platform.startswith("win"):
        print("警告: server.py 专为 Windows 设计，当前系统可能不完全兼容。", file=sys.stderr)

    global DATA, TPL, RM_ALLOW, TRASH_ALLOW, OPEN_ALLOW
    global ALLOWED_ROOTS, NON_SYSTEM_DRIVE
    DATA, TPL, RM_ALLOW, TRASH_ALLOW, OPEN_ALLOW = load(sys.argv[1])
    ALLOWED_ROOTS = load_roots(DATA)
    NON_SYSTEM_DRIVE = bool(DATA.get("non_system_drive"))

    # 可选固定端口：server.py <analysis.json> [port]
    port = 0
    if len(sys.argv) > 2:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print(f"端口参数无效: {sys.argv[2]}，改用随机端口", file=sys.stderr)

    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}/"

    target = DATA.get("target_drive") or DATA.get("system", {}).get("disk_name", "目标盘")
    print("=" * 50)
    print(f"存储分析报告服务已启动: {url}")
    print(f"扫描目标盘: {target}"
          f"{'（非系统盘：只开放「移到回收站」，不开放「直接删除」）' if NON_SYSTEM_DRIVE else ''}")
    print("=" * 50)
    print(f"授权根（可操作范围）: {len(ALLOWED_ROOTS)} 个")
    for r in ALLOWED_ROOTS:
        print(f"    {r}")
    print("-" * 50)
    print(f"可移回收站: {len(TRASH_ALLOW)} 个路径")
    print(f"可一键删除: {len(RM_ALLOW)} 个路径")
    print(f"可打开查看: {len(OPEN_ALLOW)} 个路径")
    if not ALLOWED_ROOTS:
        print("-" * 50)
        print("⚠️ 当前未授予任何可操作范围（授权根为空），删除按钮将全部返回 403。")
        print("   请检查 analysis JSON 的 allowed_roots 是否误写成了盘符根目录。")
    print("=" * 50)
    print("⚠️ 移到回收站不会立即释放磁盘空间——需清空回收站后才真正释放。")
    print("   每次操作都有二次确认；受保护目录（工作区/笔记库）一律禁止操作。")
    print("   用完按 Ctrl+C 停止服务（服务关掉后按钮即失效）。")


    webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止服务。所有删除按钮已失效。")


if __name__ == "__main__":
    main()
