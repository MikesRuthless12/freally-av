# Freally Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = रद्द करें
button-confirm = पुष्टि करें
button-save = सहेजें
button-close = बंद करें
button-scan-now = अभी स्कैन करें
button-pause = रोकें
button-resume = फिर से शुरू करें
button-stop = बंद करें
button-retry = पुनः प्रयास करें
button-export-bundle = डायग्नोस्टिक बंडल निर्यात करें

## Navigation

nav-scan = स्कैन
nav-history = इतिहास
nav-quarantine = क्वारंटाइन
nav-exclusions = बहिष्करण
nav-realtime = रीयल-टाइम
nav-usb-devices = USB डिवाइस
nav-settings = सेटिंग्स

## Scan page

scan-title = स्कैन
scan-status-idle = निष्क्रिय
scan-status-running = स्कैन हो रहा है…
scan-status-paused = रोका गया
scan-status-cancelled = रद्द किया गया
scan-status-completed = पूर्ण
scan-files-visited = { $count } फ़ाइलें जाँची गईं
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = कोई परिणाम नहीं
scan-findings-summary-one = 1 परिणाम
scan-findings-summary-other = { $count } परिणाम

## Real-time

realtime-mode-fsevents-observe = FSEvents (निरीक्षण)
realtime-mode-fanotify-full = fanotify (पूर्ण)
realtime-mode-fanotify-observe = fanotify (निरीक्षण)
realtime-mode-audit-fallback = audit फ़ॉलबैक (केवल निरीक्षण)
realtime-mode-inotify-fallback = inotify फ़ॉलबैक (केवल निरीक्षण)
realtime-shields-on = रीयल-टाइम सुरक्षा: चालू
realtime-shields-off = रीयल-टाइम सुरक्षा: बंद

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = डायग्नोस्टिक बंडल
settings-about-bundle-help = हाल के इंजन लॉग और आपके रनटाइम कॉन्फ़िगरेशन के साथ एक zip निर्यात करें। बंडल लिखे जाने से पहले स्कैन पथ हटा दिए जाते हैं। किसी बग की रिपोर्ट करते समय इसे GitHub इश्यू के साथ संलग्न करें।

## Settings — scheduler (TASK-086)

settings-scheduler-title = निर्धारित स्कैन
settings-scheduler-empty = अभी तक कोई निर्धारित स्कैन नहीं।
settings-scheduler-add = एक शेड्यूल जोड़ें
settings-scheduler-frequency-daily = दैनिक
settings-scheduler-frequency-weekly = साप्ताहिक
settings-scheduler-frequency-monthly = मासिक
settings-scheduler-frequency-oneshot = एक बार
settings-scheduler-idle-only = केवल { $seconds } सेकंड निष्क्रिय रहने के बाद चलाएँ
settings-scheduler-disabled = अक्षम
