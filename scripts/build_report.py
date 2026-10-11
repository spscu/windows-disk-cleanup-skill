#!/usr/bin/env python3
"""将分析 JSON 注入 HTML 模板 -> 生成独立可分享的静态报告。

Usage:
    build_report.py <analysis.json> [output.html]

analysis JSON schema（除 system 外均可选）：

{
  "generated_at": "2026-06-13 14:00:00",
  "scan_seconds": 42.1,
  "system": {
    "os": "Windows 11",
    "build": "10.0.22631",
    "arch": "AMD64",
    "user": "username",
    "home": "C:\\\\Users\\\\username",
    "filesystem": "NTFS",
    "disk_total": "约 500 GB",
    "disk_used": "约 420 GB",
    "disk_free": "约 80 GB",
    "disk_name": "C:\\\\",
    "disks": [{"name":"C:\\\\", ...}, {"name":"D:\\\\", ...}]
  },
  "top5": [
    {"rank":1, "tier":"green", "size":"约 15 GB", "type":"浏览器缓存",
     "name":"Chrome Cache", "path":"C:\\\\Users\\\\...\\\\Cache", "note":"纯缓存可安全清理"}
  ],
  "green": [
    {
      "name": "npm 缓存",
      "path": "C:\\\\Users\\\\...\\\\.npm",
      "size_estimate": "约 8 GB",
      "kill_processes": ["node"],
      "trash_paths": ["C:\\\\Users\\\\...\\\\.npm\\\\_cacache"],
      "commands": [{"label":"清理 npm 缓存", "cmd":"npm cache clean --force"}]
    }
  ],
  "yellow": [
    {
      "name": "B站离线视频",
      "path": "C:\\\\Users\\\\...\\\\bilibili",
      "size": "约 30 GB",
      "content_profile": "B站客户端下载的离线视频缓存",
      "why_manual": "包含用户主动下载的视频内容，需确认是否还需要观看",
      "disposal": "建议在B站客户端内清理；或在资源管理器中打开审查后手动删除",
      "risk": "删除后离线视频不可播放，需重新下载",
      "trash_paths": ["C:\\\\Users\\\\...\\\\bilibili\\\\.Downloads"],
      "open_note": "App 内部格式文件名不易辨认，建议优先在 B站客户端内清理"
    }
  ],
  "red": [
    {
      "name": "Visual Studio",
      "path": "C:\\\\Program Files\\\\Microsoft Visual Studio",
      "size": "约 25 GB",
      "why_keep": "开发环境核心文件，手动删除会破坏安装",
      "indirect_release": "通过 设置 > 应用 > 已安装的应用 正规卸载；或使用 Visual Studio Installer 修改安装组件",
      "auto_reclaim": "否",
      "app_paths": ["C:\\\\Program Files\\\\Microsoft Visual Studio"]
    }
  ],
  "denied": ["C:\\\\System Volume Information"],
  "summary": {
    "overview": "C盘最大占用来自浏览器缓存和开发工具缓存，可安全释放约 45 GB",
    "tier_stats": {"green": "约 27 GB", "yellow": "约 50 GB", "red": "约 25 GB"},
    "priority": [
      "优先清理浏览器缓存（约 15 GB），关闭浏览器后一键清理",
      "清理开发工具缓存（npm/pip/nuget 约 20 GB）"
    ],
    "long_term": [
      "开启存储感知：设置 > 系统 > 存储 > 存储感知",
      "定期运行磁盘清理：cleanmgr /d C:"
    ]
  }
}
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "..", "assets", "report_template.html")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    src = sys.argv[1]
    default_output = os.path.join(
        os.environ.get("USERPROFILE", os.path.expanduser("~")),
        "Desktop", "storage-report.html")
    out = sys.argv[2] if len(sys.argv) > 2 else default_output

    with open(src, "r", encoding="utf-8") as f:
        data = json.load(f)
    with open(TEMPLATE, "r", encoding="utf-8") as f:
        tpl = f.read()

    blob = json.dumps(data, ensure_ascii=False)
    # 静态报告不带删除能力（DELETE=null），删除按钮只在 server.py 服务时出现
    html = tpl.replace("__REPORT_DATA__", blob).replace("__DELETE_CONFIG__", "null")

    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"报告已生成: {out}")
    print(f"在浏览器中打开即可查看（静态模式，无删除按钮）")


if __name__ == "__main__":
    main()
