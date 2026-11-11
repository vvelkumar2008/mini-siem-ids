import re
import time
from collections import defaultdict
from datetime import datetime

LOG_FILE = "/var/log/auth.log"
WINDOW = 60        # seconds
THRESHOLD = 5      # failed logins from one IP
COOLDOWN = 60      # seconds before alerting the same IP again

PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})"
)

fails = defaultdict(list)
last_alert = {}

def follow(path):
    with open(path, "r") as f:
        f.seek(0, 2)              # jump to the end of the file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

print(f"Watching {LOG_FILE} ... press Ctrl+C to stop")
for line in follow(LOG_FILE):
    m = PATTERN.search(line)
    if m:
        user, ip = m.groups()
        now = time.time()
        fails[ip] = [t for t in fails[ip] if now - t < WINDOW]
        fails[ip].append(now)
        if len(fails[ip]) >= THRESHOLD and now - last_alert.get(ip, 0) > COOLDOWN:
            print(f"{datetime.now():%H:%M:%S} [ALERT] SSH brute force from {ip} "
                  f"({len(fails[ip])} failed logins, last user: {user})")
            last_alert[ip] = now
            fails[ip].clear()
