# Windows C盘数据布局与分级参考

分析 Windows C盘扫描结果时读这份。讲"东西存在哪、怎么辨认、归哪一级"。

## 多盘符

Windows 通常有多个盘（C:、D:…）。磁盘总览会列出所有盘，但**分析和清理聚焦系统盘 C:**——缓存、AppData、临时文件几乎都在 C:。其他盘（D: 等）一般是用户自存的资料/游戏，归 🟡 让用户自己判断，不要自动给删除按钮。

## 关键目录

| 目录（环境变量） | 装什么 | 典型分级 |
|---|---|---|
| `%LOCALAPPDATA%`（`C:\Users\<u>\AppData\Local`） | 浏览器缓存、应用数据、Temp，最大头 | 缓存 🟢 / 应用数据 🟡 |
| `%LOCALAPPDATA%\Temp`、`%TEMP%` | 临时文件 | 🟢 |
| `%APPDATA%`（Roaming） | 应用配置/数据 | 🟡 |
| 浏览器缓存 `%LOCALAPPDATA%\Google\Chrome\User Data\*\Cache`、Edge 同构 | 浏览器缓存 | 🟢 |
| 浏览器 `User Data\<Profile>`（非 Cache 部分） | 书签/登录态/扩展数据 | 🟡 |
| `%USERPROFILE%\.cache`、`.npm`、`.gradle`、`.m2`、`.nuget\packages`、`%LOCALAPPDATA%\pip\Cache`、Yarn | 开发缓存 | 🟢 |
| `C:\Program Files`、`Program Files (x86)` | 应用本体 | 🔴 仅重复/想卸时上灯，否则归蓝色 |
| `%USERPROFILE%\Downloads` 的安装包（.exe/.msi/.iso） | 安装包残留 | 🟢 |
| `C:\$Recycle.Bin` | 回收站 | 🟡 提示用户清空 |

## 系统占用（不上灯，归蓝色"系统及其他"，间接释放写 long_term）

| 路径 | 说明 | 释放方式 |
|---|---|---|
| `C:\Windows\WinSxS` | 组件存储，**绝不能手删** | `DISM /Online /Cleanup-Image /StartComponentCleanup`（管理员） |
| `C:\Windows\SoftwareDistribution\Download` | Windows Update 缓存 | 设置 > 系统 > 存储 > 临时文件 > Windows 更新清理 |
| `C:\Windows\Temp` | 系统临时文件 | 🟢 可清，但某些正在使用的文件可能跳过 |
| `C:\Windows\Prefetch` | 预取文件（加速启动） | 🟢 可清，但会临时减慢启动速度 |
| `C:\Windows\Logs` | Windows 日志 | 🟢 可清，不影响系统 |
| `pagefile.sys` | 虚拟内存页面文件 | 系统管理，别手动删 |
| `hiberfil.sys` | 休眠文件 | `powercfg /hibernate off` 可关闭休眠释放 |
| `swapfile.sys` | UWP 应用交换文件 | 系统管理，别手动删 |

**间接释放技巧**（写进 long_term）：
- 设置 > 系统 > 存储 > **存储感知**：自动清理临时文件和回收站
- `cleanmgr /d C:` 磁盘清理工具
- `cleanmgr /d C: /sageset:1` 扩展磁盘清理（可选 Windows 更新清理）
- DISM 清理 WinSxS 组件

## C盘根目录扫描注意事项

C盘根目录有一些特殊目录和文件需要注意：

| 路径 | 说明 | 处理方式 |
|---|---|---|
| `C:\Users` | 用户配置文件 | 深入扫描 %USERPROFILE% |
| `C:\Program Files` / `C:\Program Files (x86)` | 安装的应用 | 🔴 仅上灯想卸载的 |
| `C:\ProgramData` | 应用共享数据 | 🟡 通常不手动删 |
| `C:\Windows` | 系统目录 | 蓝色，不手删 |
| `C:\$Recycle.Bin` | 回收站 | 🟡 提示清空 |
| `C:\System Volume Information` | 系统还原点/索引 | 红色，不可访问 |
| `C:\Recovery` | 恢复分区数据 | 红色，不要动 |
| `C:\PerfLogs` | 性能日志 | 蓝色，通常很小 |

## 浏览器缓存详细识别

### Google Chrome
- 缓存位置：`%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache`
- 代码缓存：`%LOCALAPPDATA%\Google\Chrome\User Data\Default\Code Cache`
- GPU 缓存：`%LOCALAPPDATA%\Google\Chrome\User Data\Default\GPUCache`
- Service Worker：`%LOCALAPPDATA%\Google\Chrome\User Data\Default\Service Worker`
- 清理命令：`chrome://settings/clearBrowserData` 或关闭 Chrome 后删除 Cache 目录

### Microsoft Edge
- 缓存位置：`%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache`
- 结构与 Chrome 相同（同内核）

### Firefox
- 缓存位置：`%LOCALAPPDATA%\Mozilla\Firefox\Profiles\<profile>\cache2`
- 清理命令：`about:preferences#privacy` > 清除数据

## 开发工具缓存详细识别

| 工具 | 缓存路径 | 清理命令 |
|---|---|---|
| npm | `%USERPROFILE%\.npm\_cacache` | `npm cache clean --force` |
| pnpm | `%LOCALAPPDATA%\pnpm-store` | `pnpm store prune` |
| yarn | `%LOCALAPPDATA%\Yarn\Cache` | `yarn cache clean` |
| pip | `%LOCALAPPDATA%\pip\Cache` | `pip cache purge` |
| uv | `%LOCALAPPDATA%\uv\cache` | `uv cache clean` |
| nuget | `%USERPROFILE%\.nuget\packages` | 手动删除（注意项目依赖） |
| gradle | `%USERPROFILE%\.gradle\caches` | 手动删除（项目会自动重建） |
| maven | `%USERPROFILE%\.m2\repository` | 手动删除（按需重新下载） |
| cargo | `%USERPROFILE%\.cargo\registry` | `cargo cache --autoclean` |
| conda | `%USERPROFILE%\.conda\pkgs` | `conda clean --all` |
| Docker | `%USERPROFILE%\.docker` | `docker system prune -a` |
| Playwright | `%LOCALAPPDATA%\ms-playwright` | `npx playwright uninstall --all` |
| Go | `%LOCALAPPDATA%\go-build` | `go clean -cache` |

## 常见"神秘大目录"识别

| 特征 | 可能属于 | 说明 |
|---|---|---|
| `%LOCALAPPDATA%\Packages\<AppX.*>` | UWP/Microsoft Store 应用 | 应用沙盒数据 |
| `%LOCALAPPDATA%\<UUID>` | 各种应用的容器目录 | 需 `ls` 查看内部确认 |
| `%APPDATA%\<app-name>` | 桌面应用配置 | 常见：VSCode、Discord、Slack 等 |
| `%LOCALAPPDATA%\Docker` | Docker Desktop | 镜像和容器数据 |
| `%LOCALAPPDATA%\JetBrains` | JetBrains IDE | 缓存、索引、日志 |
| `%LOCALAPPDATA%\Microsoft\VisualStudio` | Visual Studio | 组件缓存 |
| `%USERPROFILE%\.android` | Android SDK/模拟器 | AVD 镜像文件可能很大 |
| `%USERPROFILE%\AppData\Local\Packages` | UWP 应用数据 | 部分应用缓存 |

## 删除机制

`server.py` 在 Windows 用 ctypes 调 `SHFileOperationW`(FOF_ALLOWUNDO) 送进回收站；纯标准库。
- 🟢 项的 `trash_paths` 应在 `%USERPROFILE%` 目录内，便于白名单与 HOME 越界校验通过
- 对于 `%LOCALAPPDATA%` 下的缓存，`trash_paths` 指向具体可删的子目录（如 `Cache`、`_cacache`），不要指向整个应用目录
- 直接删除（rm）使用 `shutil.rmtree`，仅对绿灯项开放

## Windows 特有清理命令参考

```powershell
# 清理 Windows 临时文件（PowerShell）
Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

# 清理 Windows 系统临时文件（需管理员）
Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

# 运行磁盘清理
cleanmgr /d C:

# 扩展磁盘清理（可选择 Windows 更新清理等）
cleanmgr /d C: /sageset:1

# 清理 WinSxS 组件（需管理员）
DISM /Online /Cleanup-Image /StartComponentCleanup

# 关闭休眠释放 hiberfil.sys（需管理员，慎重）
powercfg /hibernate off

# 清空回收站
Clear-RecycleBin -Force

# 清理 npm 缓存
npm cache clean --force

# 清理 pip 缓存
pip cache purge
```

## 安全注意事项

1. **永远不要手动删除 `C:\Windows` 下的任何文件或目录**
2. **不要删除 `pagefile.sys`、`hiberfil.sys`、`swapfile.sys`**（系统管理）
3. **不要在 `Program Files` 目录下手动删除应用**（走正规卸载）
4. **清理浏览器缓存前确保关闭所有浏览器窗口**
5. **开发工具缓存清理后，下次使用时会自动重建**（可能需重新下载依赖）
6. **回收站移到回收站的文件需要清空回收站才真正释放空间**
