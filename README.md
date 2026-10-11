# windows-disk-cleanup

> Windows 磁盘清理提效技能：先看清楚，再动手。
> 只读扫描 + 三级风险分类 + 交互式网页报告 + 网页一键安全清理。

当你说「C 盘满了」「D 盘满了」「清理磁盘」「找大文件」「找重复文件」时，这个技能会先帮你
**看清**硬盘到底被什么吃掉了，再给一份可点可删的网页清单——而不是稀里糊涂地乱删。

## 它解决什么问题

很多人磁盘爆满的第一反应是「用某大师一键清理」，但那往往：

- 看不清到底哪些东西占空间；
- 容易误删不可再生的个人数据；
- 清理范围黑盒，删完也不知道腾出来多少。

这个技能反其道而行：**先分析、后清理**，且删除全部需要你二次确认。

## 核心特性

- **任意盘符**：系统盘 `C:` 走 `scan.py`（系统目录专项），非系统盘 `D:/E:` 走 `scan_any_drive.py`（用户数据专项）。
- **四类清单**：体积倒序的大文件、长期未访问的陈旧文件、疑似重复文件、临时/垃圾文件。
- **三级风险分类**：
  - 🟢 可自动清理（纯缓存、临时文件、安装包残留等可再生项）
  - 🟡 需人工判断（含用户数据、有判断成本的项）
  - 🔴 谨慎清理（系统文件、运行中应用核心数据等，只建议、不给删除按钮）
- **交互式 HTML 报告**：排版清晰、可折叠、命令一键复制；并在网页上提供「移到回收站 / 直接删除」按钮。
- **安全模型**：全程只读扫描；删除双重确认；非系统盘只给可逆的「移到回收站」；受保护目录（如 `DevSource`、`思源`、`.workbuddy`）硬拒绝。

> ⚠️ 免责声明：本技能**本身不直接删除任何文件**，只做只读存储分析并生成处置建议。
> 网页上的删除操作由用户主动点击并二次确认，删除责任与后果由用户自行承担。

## 安装（WorkBuddy 技能）

本技能面向 [WorkBuddy](https://www.workbuddy.cn) 智能体运行环境，安装方式二选一：

### 方式一：复制目录（推荐，零依赖）

```powershell
# 假设仓库已克隆到 D:\DevSource\windows-disk-cleanup-skill
$skillSrc = "D:\DevSource\windows-disk-cleanup-skill"
$skillDst = "$env:USERPROFILE\.workbuddy\skills\windows-disk-cleanup"
New-Item -ItemType Directory -Force -Path $skillDst | Out-Null
Copy-Item "$skillSrc\*" $skillDst -Recurse -Force
```

### 方式二：符号链接（便于跟随仓库更新）

```powershell
# 用 junction 软链，省去重复复制，跟随 Git 更新
cmd /c mklink /J "$env:USERPROFILE\.workbuddy\skills\windows-disk-cleanup" "D:\DevSource\windows-disk-cleanup-skill"
```

安装完成后，在 WorkBuddy 里对智能体说「C 盘满了」「帮我看看 D 盘」等即可触发。

## 运行前提

- **Python 3.8+**（Windows 默认可能未安装，需自行先装；命令是 `python` 而非 `python3`）。
- **零第三方依赖**：仅使用 Python 标准库，无需 `pip install`。
- 扫描部分系统目录（如 `C:\Windows`）建议**以管理员身份**运行终端。
- 本技能是 **agent 驱动**：扫描出数据后由智能体做分级分析，不是双击即用的独立 App。

## 目录结构

```
windows-disk-cleanup/
├── SKILL.md                      # 技能说明与执行流程（智能体读取）
├── _user_meta.json               # 用户元信息
├── assets/
│   └── report_template.html      # 报告 HTML 模板
├── references/
│   ├── windows-c-drive.md        # C 盘数据布局参考
│   └── windows-any-drive.md      # 非系统盘数据布局参考
└── scripts/
    ├── scan.py                   # C 盘专用扫描器（只读）
    ├── scan_any_drive.py         # 非系统盘扫描器（只读）
    ├── build_report.py           # 静态 HTML 报告生成
    └── server.py                 # 本地服务 + 网页交互清理（127.0.0.1 + 随机 token）
```

## 典型用法（供智能体参考）

```powershell
# 系统盘 C 盘扫描
python scripts/scan.py > $env:TEMP\storage_scan.json

# 非系统盘 D 盘扫描
python scripts/scan_any_drive.py --drive D: --out "$env:TEMP\d_scan.json"

# 生成可交互网页报告（默认，支持一键清理）
python scripts/server.py $env:TEMP\storage_analysis.json

# 仅生成静态只读 HTML（用户只要一份文件时）
python scripts/build_report.py $env:TEMP\storage_analysis.json $env:USERPROFILE\Desktop\storage-report.html
```

## 安全说明

- 扫描全程只读，不执行任何写操作。
- 删除操作均经 token + Host + realpath 校验，并限制在授权根目录内。
- 受保护目录（个人工作资料、笔记库、智能体数据等）无条件拒绝任何删除请求。
- 「移到回收站」不会立即释放空间，需手动清空回收站才真正释放。

## 致谢

技能架构设计理念参考 [KKKKhazix/storage-analyzer](https://github.com/KKKKhazix/khazix-skills/tree/main/storage-analyzer)，
并针对 Windows 多盘符、系统目录与安全模型做了增强。

---

📮 想看效果演示与完整讲解？见作者公众号文章（仓库地址已附于文中）。
本仓库为**无偿开源分享**，欢迎 Star 与 Issue。
