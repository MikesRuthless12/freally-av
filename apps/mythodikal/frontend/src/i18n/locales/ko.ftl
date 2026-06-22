# Mythodikal Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = 취소
button-confirm = 확인
button-save = 저장
button-close = 닫기
button-scan-now = 지금 검사
button-pause = 일시정지
button-resume = 다시 시작
button-stop = 중지
button-retry = 다시 시도
button-export-bundle = 진단 번들 내보내기

## Navigation

nav-scan = 검사
nav-history = 기록
nav-quarantine = 격리
nav-exclusions = 제외 항목
nav-realtime = 실시간
nav-usb-devices = USB 장치
nav-settings = 설정

## Scan page

scan-title = 검사
scan-status-idle = 대기 중
scan-status-running = 검사 중…
scan-status-paused = 일시정지됨
scan-status-cancelled = 취소됨
scan-status-completed = 완료됨
scan-files-visited = 검사한 파일 { $count }개
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = 발견된 항목 없음
scan-findings-summary-one = 발견 항목 1개
scan-findings-summary-other = 발견 항목 { $count }개

## Real-time

realtime-mode-fsevents-observe = FSEvents (관찰)
realtime-mode-fanotify-full = fanotify (전체)
realtime-mode-fanotify-observe = fanotify (관찰)
realtime-mode-audit-fallback = audit 폴백 (관찰 전용)
realtime-mode-inotify-fallback = inotify 폴백 (관찰 전용)
realtime-shields-on = 실시간 보호: 켜짐
realtime-shields-off = 실시간 보호: 꺼짐

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = 진단 번들
settings-about-bundle-help = 최근 엔진 로그와 런타임 설정이 담긴 zip 파일을 내보냅니다. 번들을 만들기 전에 검사 경로는 제거됩니다. 버그를 보고할 때 GitHub 이슈에 첨부하세요.

## Settings — scheduler (TASK-086)

settings-scheduler-title = 예약 검사
settings-scheduler-empty = 예약된 검사가 아직 없습니다.
settings-scheduler-add = 일정 추가
settings-scheduler-frequency-daily = 매일
settings-scheduler-frequency-weekly = 매주
settings-scheduler-frequency-monthly = 매월
settings-scheduler-frequency-oneshot = 한 번
settings-scheduler-idle-only = { $seconds }초 동안 유휴 상태일 때만 실행
settings-scheduler-disabled = 비활성화됨
