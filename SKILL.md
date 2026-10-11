---
name: windows-disk-cleanup
description: >
  Windows 硬盘只读存储分析与安全清理助手，支持**任意盘符**（系统盘 C: 与非系统盘 D:/E: 等）。
  扫描磁盘占用，产出四类清单：体积倒序的大文件、长期未访问的陈旧文件、疑似重复文件、临时/垃圾文件；
  把每一项分成 🟢可自动清理 / 🟡需人工判断 / 🔴谨慎清理 三级并给出可执行处置方案，
  生成排版精美、可折叠、命令可一键复制的交互式 HTML 报告，并可起本地服务在网页上
  一键删除（移回收站/直接删）。扫描全程只读，删除操作需二次确认。务必在以下场景使用：
  用户说"C盘满了""D盘满了""C盘清理""D盘清理""磁盘清理""清理C盘""清理D盘""空间不够""磁盘空间不足"
  "清理磁盘""哪些东西占C盘""哪些东西占D盘""帮我看看C盘""帮我看看D盘""硬盘满了" "disk cleanup" "drive full"
  "storage analysis""清缓存""清理垃圾""找重复文件""找大文件""找临时文件"； 或用户抱怨某盘没空间、
  想知道什么东西吃硬盘、想要清理建议时。
  选扫描器：C盘等系统盘走 scan.py（系统目录专项），非系统盘走 scan_any_drive.py（用户数据专项）。
---

# Windows 硬盘存储分析与安全清理

对 Windows 任意盘做一次只读存储分析，产出交互式 HTML 报告，并支持网页上一键安全清理。
流程：扫描 → 分析分级 → 生成网页 → 打开 → 可交互清理。

## 先选扫描器（关键分流）

| 场景 | 扫描器 | 理由 |
|---|---|---|
| 系统盘 C:（用户说"C盘"） | `scripts/scan.py` | 覆盖 Windows 系统目录、WinSxS、浏览器/开发缓存等C 盘专项 |
| **非系统盘 D:/E: 等** | `scripts/scan_any_drive.py` | 面向用户数据：大文件、陈旧文件、重复文件、临时文件四类清单 |

不确定盘符性质时，先跑 `scan_any_drive.py`（它也能扫 C 盘，但不含 C 盘系统专项）。
两个脚本都只读，产出 JSON 结构不同：前者产出 `groups`，后者产出
`top_dirs` / `large_files` / `stale_files` / `temp_files` / `duplicate_groups`。

## 铁律

- **全程只读扫描。** 只能跑扫描/统计/列目录/读元信息（os.scandir、shutil.disk_usage、dir、powershell Get-ChildItem）。绝对禁止 rm、del、rmdir、清空回收站、改权限等任何写操作。
- **删除操作双重确认。** 网页上的删除按钮点击后，浏览器先弹出 confirm 确认框，用户点确认后才执行。绿灯项给「移到回收站」(可逆) +「直接删除」(不可逆)；黄灯项只给「在资源管理器打开」+（有安全子路径时）「移到回收站」；红灯项只给「在资源管理器打开」，不给任何删除按钮。
- **非系统盘只给可逆操作。** analysis JSON 含 `non_system_drive: true` 时，`server.py` 自动清空 rm 白名单，网页上**只出现「移到回收站」**。非系统盘是用户数据，不可再生性高于系统盘缓存，不开放直接删除。
- **安全白名单机制。** `server.py` 从 analysis JSON 的 `allowed_roots` 读取授权根（缺失时回退 `%USERPROFILE%`，兼容旧文件）；所有请求路径须经 realpath 校验、落在授权根内、且不命中受保护目录；token + Host 校验防 DNS 重绑定。
- **受保护目录无条件拒绝。** `DevSource` / `思源` / `.workbuddy` / `workbuddy` / `claude-mem-data` / `System Volume Information` / `WindowsApps` / `WpSystem` 等目录，按路径分段匹配（大小写不敏感、不绑定盘符），命中即403。它们**不得**进入 `allowed_roots` 或任何 `trash_paths`。
- **授权根不得写盘根。** `allowed_roots` 必须具体到子目录（如 `D:\\09.Download`）。写盘根（`D:\\`）等于授权整盘删除，`server.py` 会直接丢弃该项。
- **估算标注清楚。** 涉及"可释放空间"一律说明是估算值。
- **路径、命令保留原文不翻译。** Windows 路径使用反斜杠格式。


## 执行流程

### Step 1 扫描（只读）

```powershell
python scripts/scan.py > %TEMP%\storage_scan.json
```

`scan.py` 专为 Windows C盘设计，扫描以下关键区域：

| 扫描区域 | 路径 | 说明 |
|---------|------|------|
| 用户配置文件 | `%USERPROFILE%` | 用户主目录下的大文件夹 |
| 本地应用数据 | `%LOCALAPPDATA%` | 浏览器缓存、应用数据最大头 |
| 漫游应用数据 | `%APPDATA%` | 应用配置/数据 |
| 临时文件 | `%TEMP%` / `%LOCALAPPDATA%\Temp` | 临时文件 |
| 下载文件夹 | `%USERPROFILE%\Downloads` | 安装包残留 |
| 程序文件 | `C:\Program Files` / `C:\Program Files (x86)` | 安装的应用 |
| Windows 临时目录 | `C:\Windows\Temp` | 系统临时文件 |
| 开发缓存 | `.npm/.gradle/.nuget/pip/uv` 等 | 开发工具缓存 |
| C盘根目录大文件 | `C:\*.sys` / `C:\` 顶层目录 | 休眠文件/页面文件等 |

输出 JSON 包含：`system`（系统/磁盘信息，含所有盘符）+ `groups`（各组子目录大小，已降序、过滤 50MB 以下）。扫描较慢（C盘内容多可能需要几分钟），耐心等待。读不到的目录标 `denied`，需在报告里列出并提示遗漏体量。

### Step 1-B 非系统盘扫描（只读）

```powershell
python scripts/scan_any_drive.py --drive D: --out "%TEMP%\d_scan.json"
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--drive` | 系统盘 | 目标盘符，如 `D:`；**不传则扫系统盘** |
| `--out` | stdout | 输出 JSON 路径 |
| `--min-file-mb` | 200 | 大文件阈值 |
| `--stale-days` | 180 | 陈旧阈值（按**最后访问时间**判定，本机 atime 未禁用故可用） |
| `--min-dup-mb` | 100 | 重复检测最小体积 |

单次全盘遍历同时产出五类数据（D 盘 365 万文件实测约 133 秒）：

| 字段 | 内容 | 排序 |
|---|---|---|
| `top_dirs` | 盘根子项体积 | 体积降序 |
| `large_files` | 大文件 | **体积降序（从大到小）** |
| `stale_files` | 超期未访问 | **距上次访问天数降序（最久未用在前）** |
| `temp_files` | 临时/垃圾文件（`.tmp/.bak/.log/.dmp/.crdownload` 等） | 体积降序 |
| `duplicate_groups` | 疑似重复组 | 可回收空间降序 |

⚠️ **重复检测是近似算法，非精确**：只比对**体积 + 文件头部 1MB 的 sha256**。同一文件已全局去重（只归入可回收空间最大的那一组），不会重复计入。报告中必须原样带上 `note` 字段的「近似，非精确」说明，不得断言「已确认重复」。

⚠️ **受保护目录不入候选**：`DevSource`、`思源`、`.workbuddy` 等目录下的文件不会出现在 `large_files`/`temp_files` 中。但 `top_dirs` 仍会统计它们的总体积（仅供了解占用，不构成清理建议）。


### Step 2 分析与分级

C 盘读 [references/windows-c-drive.md](references/windows-c-drive.md) 了解 Windows C盘数据布局参考（东西存在哪、怎么辨认、归哪一级）；非系统盘读 [references/windows-any-drive.md](references/windows-any-drive.md) 了解 D 盘等用户数据盘的典型占用与判据。

然后读扫描 JSON 做这几件事：

1. **挑 Top 5** 占用大户，判定类型（系统资产/应用本体/应用数据/应用缓存/开发缓存/用户文件/媒体内容/下载内容/虚拟机镜像/回收站/其他）。
2. **识别"神秘大目录"**：UUID 命名的目录、不明的隐藏目录，要追查它属于哪个 App、装的是什么。必要时深入一层看清楚，但仍只读。
3. **三级分类 = 清理决策清单，不是全盘点。** 只把"存在'要不要动它'这个决策"的项放进三灯：
   - 🟢 **可自动清理**：纯缓存、临时文件、安装包残留、明确可再生且不影响功能（pip/uv/npm/nuget 缓存、浏览器缓存、Windows Temp、下载文件夹中的 exe/msi 安装包、崩溃转储文件）。
   - 🟡 **需人工判断**：含用户数据或有判断成本（离线视频、文档、项目 node_modules、聊天记录、设计稿、浏览器用户数据非缓存部分）。给内容画像 + 至少 3 句处置路径（应用内清理 / 系统工具 / 资源管理器手动审查）。
   - 🔴 **谨慎清理**：你可能想动、但建议别手删的具体项——重复安装的应用、想卸载的大应用、运行中应用的核心数据、系统文件（WinSxS、pagefile.sys、hiberfil.sys）。给"为什么不建议手删" + 具体卸载/释放步骤。

每个 🟢 项要给：预估释放空间、清理前需关闭的进程、可一键复制的清理命令（优先用 PowerShell 命令或移回收站方式，谨慎用 `rd /s /q`）。

**非系统盘额外要求**：
- `duplicate_groups` 的每一组都要给出「保留哪一个、删哪几个」的明确建议（优先保留位于工作目录、且修改时间最新的那份），并把 `note` 里的「近似，非精确」说明原样带上。
- 陈旧文件（`stale_files`）要说清「距上次访问 N 天」，并区分「内容陈旧但可能仍需要」（如项目交付物 → 🟡）与「纯缓存/中间产物」（→ 🟢）。
- 工作资料、聊天记录、交付物一律不低于 🟡。**非系统盘没有 🟢 的「直接删除」**，最宽松也给到 🟡 的「移到回收站」。
- 若发现同一数据的新旧两份副本（如微信新旧客户端目录），必须先取证再下结论：仅凭「同名同体积」不足为凭，要比对头部指纹 + 检查旧目录是否仍在被写入（旧目录仍在写入 = 仍是活动副本，不可删）。

**大小字段写干净**：`size` / `size_estimate` 用"约 14 GB""合计约 8.6 GB"即可。

### Step 3 生成交互报告

把分析结果写成 analysis JSON（schema 见 `scripts/build_report.py` 顶部注释）。

**🟢 项必须带 `trash_paths`**（具体可删的绝对路径数组）——这是网页删除按钮的前提。

**必须显式声明 `allowed_roots`**：列出允许操作的**具体子目录**数组，如`["D:\\09.Download", "D:\\录屏"]`。
-禁止写盘根（`"D:\\"`）—— `server.py` 会丢弃该项并回退 `%USERPROFILE%`。
- 禁止把 `DevSource`、`思源`、`.workbuddy` 等受保护目录写进去。
- 字段缺失时 `server.py` 回退 `%USERPROFILE%`（旧 C 盘分析 JSON 仍可用）。

**非系统盘必须置 `non_system_drive: true`**：这会让 `server.py` 清空 rm 白名单，网页上只剩「移到回收站」。

**默认用一键删除模式（`server.py`）打开报告**：
```powershell
python scripts/server.py %TEMP%\storage_analysis.json
```
`server.py` 起在 127.0.0.1 + 随机端口 + 随机 token。系统盘：🟢 项给「移到回收站」(可逆) +「直接删除」(立即释放)；🟡 项给「在资源管理器打开」+（有安全子路径时）「移到回收站」。**非系统盘：只有「移到回收站」。**

**安全模型——三套白名单，权限从严到宽**：
- `rm` 只允许绿灯 `trash_paths`（非系统盘为空集）
- `trash` 允许绿灯+橙灯 `trash_paths`（非系统盘橙灯也不能 rm）
- `open`（在资源管理器打开，非破坏性）允许上述全部 + 橙灯真实 `path`

校验链：token → Host(127.0.0.1) → 白名单 → **受保护目录硬拒绝** → 授权根边界。

⚠️ **移到回收站不释放磁盘空间**，必须清空回收站才真正释放。报告与网页都要写明这一点，不要让用户误以为点完就腾出空间。

**安全模型——三套白名单，权限从严到宽**：
- `rm` 只允许绿灯 `trash_paths`
- `trash` 允许绿灯+橙灯 `trash_paths`（橙灯永远不能 rm）
- `open`（在资源管理器打开，非破坏性）允许上述全部 + 橙灯真实 `path`

所有请求 realpath 校验 + 必须在 `%USERPROFILE%` 内 + token + Host 校验。

Windows 回收站使用 `ctypes` 调 `SHFileOperationW`（FOF_ALLOWUNDO），标准库实现。

仅当用户明确只想要一份只读文件时，才用静态模式：
```powershell
python scripts/build_report.py %TEMP%\storage_analysis.json %USERPROFILE%\Desktop\storage-report.html
```

### Step 4 对话里给摘要

报告生成后，在对话里用一段话给结论先行的摘要：总可释放估算、最该先清的 2-3 项、风险最高的一项。细节让用户看网页。

## 核心函数模块

### 1. 扫描模块 (scan.py)
- `dir_size_bytes(path)`: 递归计算目录大小（os.scandir，跳过符号链接和不可读目录）
- `scandir_children(path, min_kb, limit)`: 列出目录子项并按大小排序
- `list_drives_windows()`: 枚举所有盘符及其容量
- `system_info_windows()`: 收集系统信息（OS版本、架构、用户、磁盘使用率）
- `scan_c_drive_root()`: 扫描C盘根目录顶层大目录/文件
- `scan_windows_temp()`: 扫描Windows临时目录（%TEMP%、C:\Windows\Temp）
- `scan_windows_system()`: 扫描Windows系统可清理项（WinSxS估算、更新缓存等）
- `scan_dev_caches()`: 扫描开发工具缓存（npm/nuget/pip/gradle等）
- `scan_browser_caches()`: 扫描浏览器缓存（Chrome/Edge/Firefox）
- `scan_downloads()`: 扫描下载文件夹中的安装包残留

### 2. 分析分级模块（Agent 执行）
- 读取 scan.py 输出的 JSON
- 参考 references/windows-c-drive.md 做三级分类
- 生成 analysis JSON（含 top5、green、yellow、red、summary）

### 3. 报告生成模块 (build_report.py)
- 将 analysis JSON 注入 HTML 模板
- 生成独立可分享的静态 HTML 文件

### 4. 本地服务模块 (server.py)
- `ThreadingHTTPServer` 起在 127.0.0.1 + 随机端口
- `POST /action` 端点处理 trash/rm/open 三种操作
- `_trash_windows(path)`: 调用 `SHFileOperationW` 移到回收站
- `hard_delete(path)`: shutil.rmtree 直接删除
- `open_in_explorer(path)`: 在资源管理器中打开
- 安全校验：token + Host + realpath + %USERPROFILE% 边界

## 依赖与运行前提

- **Python 3 标准库**，零第三方依赖（不用 pip install）。
- Windows 默认可能没装 Python——需先装 Python 3.8+。
- 命令为 `python`（不是 `python3`）。
- 本 skill 是 **agent 驱动**：扫描出数据后由 agent 做分级分析，不是双击即用的独立 App。
- 需要管理员权限才能扫描某些系统目录（如 C:\Windows），建议以管理员身份运行终端。

## 与原始方案的关系

本技能参考了 [KKKKhazix/storage-analyzer](https://github.com/KKKKhazix/khazix-skills/tree/main/storage-analyzer) 的架构设计理念，针对 Windows C盘做了以下增强：

1. **专用扫描器**：针对 Windows C盘目录结构优化扫描路径，增加 C盘根目录扫描、Windows 系统目录扫描、浏览器缓存专项扫描
2. **PowerShell 命令**：清理命令同时提供 CMD 和 PowerShell 两种格式
3. **Windows 特有清理**：增加 Windows Update 缓存、预取文件、崩溃转储、Windows 日志等系统级清理建议
4. **多盘符处理**：聚焦C盘分析，其他盘符仅展示容量信息
5. **安全加固**：路径校验使用 Windows 规范路径（ntpath.realpath），白名单限制在 %USERPROFILE% 内

## 长期优化建议素材（写进报告 summary.long_term）

- 开启**存储感知**：设置 > 系统 > 存储 > 存储感知（自动清理临时文件和回收站）
- 运行**磁盘清理**：`cleanmgr /d C:` 或扩展清理 `cleanmgr /d C: /sageset:1`
- 清理 WinSxS：`DISM /Online /Cleanup-Image /StartComponentCleanup`（以管理员运行）
- 清理 Windows 更新缓存：设置 > 系统 > 存储 > 临时文件 > Windows 更新清理
- 大文件/项目迁移到 D盘或其他盘符
- 定期清理浏览器缓存和下载文件夹
- 卸载不常用应用：设置 > 应用 > 已安装的应用 > 按大小排序

## 使用示例

**User:** `帮我看看C盘`
**Assistant:** (运行 scan.py → 分析 JSON → 生成报告 → 打开浏览器)
已生成C盘存储分析报告，发现约 45 GB 可安全清理。最大占用是 Chrome 缓存（12 GB）和 npm 缓存（8 GB）。详细报告已在浏览器打开，你可以直接在网页上一键清理。

**User:** `C盘满了怎么办`
**Assistant:** (同上流程)
C盘目前只剩 8.2 GB 可用。建议优先清理：1) 临时文件约 6 GB 2) 开发缓存约 15 GB 3) 下载文件夹安装包约 3 GB。报告已打开，绿色项可以放心一键清理。

**User:** `清理一下磁盘`
**Assistant:** (同上流程)
