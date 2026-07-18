# Freally Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = 取消
button-confirm = 确认
button-save = 保存
button-close = 关闭
button-scan-now = 立即扫描
button-pause = 暂停
button-resume = 继续
button-stop = 停止
button-retry = 重试
button-export-bundle = 导出诊断包

## Navigation

nav-scan = 扫描
nav-history = 历史记录
nav-quarantine = 隔离区
nav-exclusions = 排除项
nav-realtime = 实时防护
nav-usb-devices = USB 设备
nav-settings = 设置

## Scan page

scan-title = 扫描
scan-status-idle = 空闲
scan-status-running = 正在扫描…
scan-status-paused = 已暂停
scan-status-cancelled = 已取消
scan-status-completed = 已完成
scan-files-visited = 已检查 { $count } 个文件
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = 未发现威胁
scan-findings-summary-one = 发现 1 项威胁
scan-findings-summary-other = 发现 { $count } 项威胁

## Real-time

realtime-mode-fsevents-observe = FSEvents（监视）
realtime-mode-fanotify-full = fanotify（完整）
realtime-mode-fanotify-observe = fanotify（监视）
realtime-mode-audit-fallback = audit 回退（仅监视）
realtime-mode-inotify-fallback = inotify 回退（仅监视）
realtime-shields-on = 实时防护：开启
realtime-shields-off = 实时防护：关闭

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = 诊断包
settings-about-bundle-help = 导出一个 zip 文件，包含最近的引擎日志和您的运行时配置。在写入诊断包之前会移除扫描路径。报告问题时请将其附加到 GitHub issue。

## Settings — scheduler (TASK-086)

settings-scheduler-title = 计划扫描
settings-scheduler-empty = 暂无计划扫描。
settings-scheduler-add = 添加计划
settings-scheduler-frequency-daily = 每天
settings-scheduler-frequency-weekly = 每周
settings-scheduler-frequency-monthly = 每月
settings-scheduler-frequency-oneshot = 一次
settings-scheduler-idle-only = 仅在空闲 { $seconds } 秒后运行
settings-scheduler-disabled = 已禁用

# More Freally apps (Central inside panel)
more-apps-menu = 更多 Freally 应用
more-apps-title = 更多 Freally 应用
