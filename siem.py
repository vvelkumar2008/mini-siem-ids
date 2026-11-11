import re
import json
import time
import subprocess
from collections import defaultdict
from datetime import datetime

LOG_FILE = "/var/log/auth.log"
EVENTS_FILE = "alerts.log"
WINDOW = 60
THRESHOLD = 5
WHITELIST = {"127.0.0.1", "192.168.1.1"}

PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})"
)

fails = defaultdict(list)
blocked = set()

def save_event(kind, ip, detail):
    event = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": kind,
        "ip": ip,
        "detail": detail,
    }
    print(event)
    with open(EVENTS_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

def block(ip):
    subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    blocked.add(ip)
    save_event("BLOCKED", ip, "dropped by iptables")

def follow(path):
    with open(path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

print(f"Watching {LOG_FILE} ... press Ctrl+C to stop")
for line in follow(LOG_FILE):
    m = PATTERN.search(line)
    if not m:
        continue
    user, ip = m.groups()
    if ip in WHITELIST or ip in blocked:
        continue
    now = time.time()
    fails[ip] = [t for t in fails[ip] if now - t < WINDOW]
    fails[ip].append(now)
    if len(fails[ip]) >= THRESHOLD:
        save_event("SSH_BRUTE_FORCE", ip,
                   f"{len(fails[ip])} failed logins, last user: {user}")
        block(ip)
        fails[ip].clear()
