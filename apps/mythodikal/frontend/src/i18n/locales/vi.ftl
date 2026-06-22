# Mythodikal Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = Hủy
button-confirm = Xác nhận
button-save = Lưu
button-close = Đóng
button-scan-now = Quét ngay
button-pause = Tạm dừng
button-resume = Tiếp tục
button-stop = Dừng
button-retry = Thử lại
button-export-bundle = Xuất gói chẩn đoán

## Navigation

nav-scan = Quét
nav-history = Lịch sử
nav-quarantine = Cách ly
nav-exclusions = Loại trừ
nav-realtime = Thời gian thực
nav-usb-devices = Thiết bị USB
nav-settings = Cài đặt

## Scan page

scan-title = Quét
scan-status-idle = Chờ
scan-status-running = Đang quét…
scan-status-paused = Đã tạm dừng
scan-status-cancelled = Đã hủy
scan-status-completed = Hoàn tất
scan-files-visited = Đã quét { $count } tệp
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = Không phát hiện
scan-findings-summary-one = 1 phát hiện
scan-findings-summary-other = { $count } phát hiện

## Real-time

realtime-mode-fsevents-observe = FSEvents (theo dõi)
realtime-mode-fanotify-full = fanotify (đầy đủ)
realtime-mode-fanotify-observe = fanotify (theo dõi)
realtime-mode-audit-fallback = dự phòng audit (chỉ theo dõi)
realtime-mode-inotify-fallback = dự phòng inotify (chỉ theo dõi)
realtime-shields-on = Bảo vệ thời gian thực: BẬT
realtime-shields-off = Bảo vệ thời gian thực: TẮT

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = Gói chẩn đoán
settings-about-bundle-help = Xuất một tệp zip chứa nhật ký engine gần đây và cấu hình thời gian chạy của bạn. Đường dẫn quét được loại bỏ trước khi ghi gói. Đính kèm vào một báo cáo lỗi trên GitHub khi báo lỗi.

## Settings — scheduler (TASK-086)

settings-scheduler-title = Quét theo lịch
settings-scheduler-empty = Chưa có lịch quét nào.
settings-scheduler-add = Thêm lịch
settings-scheduler-frequency-daily = Hằng ngày
settings-scheduler-frequency-weekly = Hằng tuần
settings-scheduler-frequency-monthly = Hằng tháng
settings-scheduler-frequency-oneshot = Một lần
settings-scheduler-idle-only = Chỉ chạy sau { $seconds }s không hoạt động
settings-scheduler-disabled = Đã tắt
