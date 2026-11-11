import json
from collections import Counter
from flask import Flask, render_template_string

app = Flask(__name__)
EVENTS_FILE = "alerts.log"

PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>Mini SIEM Dashboard</title>
<style>
 body{font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px}
 .cards{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}
 .card{background:#1e293b;padding:16px 24px;border-radius:10px;min-width:160px}
 .num{font-size:32px;font-weight:bold}
 table{width:100%;border-collapse:collapse;background:#1e293b;margin-bottom:24px}
 th,td{padding:10px;text-align:left;border-bottom:1px solid #334155}
 th{background:#334155}
 .BLOCKED{color:#f87171;font-weight:bold}
 .SSH_BRUTE_FORCE{color:#fbbf24;font-weight:bold}
 .PORT_SCAN{color:#60a5fa;font-weight:bold}
</style>
</head>
<body>
<h1>Mini SIEM Dashboard</h1>
<div class="cards">
 <div class="card"><div class="num">{{ total }}</div>Total events</div>
 <div class="card"><div class="num">{{ blocked }}</div>IPs blocked</div>
 <div class="card"><div class="num">{{ unique }}</div>Unique attackers</div>
</div>
<h2>Top attackers</h2>
<table>
 <tr><th>IP</th><th>Events</th></tr>
 {% for ip, n in attackers %}<tr><td>{{ ip }}</td><td>{{ n }}</td></tr>{% endfor %}
</table>
<h2>Recent events</h2>
<table>
 <tr><th>Time</th><th>Type</th><th>IP</th><th>Detail</th></tr>
 {% for e in events %}
 <tr><td>{{ e.time }}</td><td class="{{ e.type }}">{{ e.type }}</td><td>{{ e.ip }}</td><td>{{ e.detail }}</td></tr>
 {% endfor %}
</table>
</body></html>
"""

def load_events():
    events = []
    try:
        with open(EVENTS_FILE) as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    return events

@app.route("/")
def home():
    events = load_events()
    counts = Counter(e["ip"] for e in events)
    return render_template_string(
        PAGE,
        total=len(events),
        blocked=sum(1 for e in events if e["type"] == "BLOCKED"),
        unique=len(counts),
        attackers=counts.most_common(5),
        events=list(reversed(events))[:20],
    )

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
