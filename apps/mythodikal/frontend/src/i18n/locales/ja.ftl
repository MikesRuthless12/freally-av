# Mythodikal Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = キャンセル
button-confirm = 確定
button-save = 保存
button-close = 閉じる
button-scan-now = 今すぐスキャン
button-pause = 一時停止
button-resume = 再開
button-stop = 停止
button-retry = 再試行
button-export-bundle = 診断バンドルをエクスポート

## Navigation

nav-scan = スキャン
nav-history = 履歴
nav-quarantine = 隔離
nav-exclusions = 除外設定
nav-realtime = リアルタイム
nav-usb-devices = USBデバイス
nav-settings = 設定

## Scan page

scan-title = スキャン
scan-status-idle = 待機中
scan-status-running = スキャン中…
scan-status-paused = 一時停止中
scan-status-cancelled = キャンセル済み
scan-status-completed = 完了
scan-files-visited = { $count } 件のファイルを確認しました
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = 検出なし
scan-findings-summary-one = 1 件の検出
scan-findings-summary-other = { $count } 件の検出

## Real-time

realtime-mode-fsevents-observe = FSEvents（監視）
realtime-mode-fanotify-full = fanotify（完全）
realtime-mode-fanotify-observe = fanotify（監視）
realtime-mode-audit-fallback = audit フォールバック（監視のみ）
realtime-mode-inotify-fallback = inotify フォールバック（監視のみ）
realtime-shields-on = リアルタイム保護: 有効
realtime-shields-off = リアルタイム保護: 無効

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = 診断バンドル
settings-about-bundle-help = 最近のエンジンログと実行時設定を含む zip をエクスポートします。バンドルの書き出し前にスキャンパスは削除されます。不具合を報告する際は GitHub の issue に添付してください。

## Settings — scheduler (TASK-086)

settings-scheduler-title = スケジュールスキャン
settings-scheduler-empty = スケジュールされたスキャンはまだありません。
settings-scheduler-add = スケジュールを追加
settings-scheduler-frequency-daily = 毎日
settings-scheduler-frequency-weekly = 毎週
settings-scheduler-frequency-monthly = 毎月
settings-scheduler-frequency-oneshot = 1回のみ
settings-scheduler-idle-only = アイドル状態が { $seconds } 秒続いた後にのみ実行
settings-scheduler-disabled = 無効
