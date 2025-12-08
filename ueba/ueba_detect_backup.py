from elasticsearch import Elasticsearch
from datetime import datetime
from collections import defaultdict

es = Elasticsearch("http://localhost:9200")

def fetch_recent_events(hours=24):
    query = {
        "query": {
            "range": {
                "timestamp": {
                    "gte": f"now-{hours}h",
                    "lte": "now"
                }
            }
        },
        "size": 10000
    }
    resp = es.search(index="user-activity-*", body=query)
    hits = resp.get("hits", {}).get("hits", [])
    events = [h["_source"] for h in hits]
    return events

def build_user_baseline(events):
    baseline = defaultdict(lambda: {
        "total_events": 0,
        "file_read": 0,
        "file_write": 0,
        "cmd": 0,
        "net_conn_bytes": 0,
        "hours_active": set()
    })

    for ev in events:
        user = ev.get("user", "unknown")
        action = ev.get("action", "unknown")
        ts = ev.get("timestamp")
        bytes_ = ev.get("bytes", 0) or 0

        baseline[user]["total_events"] += 1

        if action == "file_read":
            baseline[user]["file_read"] += 1
        elif action == "file_write":
            baseline[user]["file_write"] += 1
        elif action == "cmd":
            baseline[user]["cmd"] += 1
        elif action == "net_conn":
            baseline[user]["net_conn_bytes"] += int(bytes_)

        if ts:
            try:
                dt = datetime.fromisoformat(ts)
                baseline[user]["hours_active"].add(dt.hour)
            except Exception:
                pass

    return baseline

def detect_anomalies(baseline):
    """
    Simple rule-based UEBA:
    - High file_read
    - High cmd
    - High net_conn_bytes
    """
    alerts = []

    for user, stats in baseline.items():
        reasons = []
        score = 0

        if stats["file_read"] > 15:
            reasons.append(f"High file_read: {stats['file_read']}")
            score += 1

        if stats["cmd"] > 10:
            reasons.append(f"High cmd count: {stats['cmd']}")
            score += 1

        if stats["net_conn_bytes"] > 10_000_000:
            reasons.append(f"High net_conn_bytes: {stats['net_conn_bytes']}")
            score += 1

        # You can add more rules later (off-hours, etc.)

        if score > 0:
            alert = {
                "timestamp": datetime.utcnow().isoformat(),
                "user": user,
                "score": score,
                "reasons": reasons,
                "metrics": {
                    "total_events": stats["total_events"],
                    "file_read": stats["file_read"],
                    "file_write": stats["file_write"],
                    "cmd": stats["cmd"],
                    "net_conn_bytes": stats["net_conn_bytes"],
                    "hours_active": sorted(list(stats["hours_active"]))
                }
            }
            alerts.append(alert)

    return alerts

def index_alerts(alerts):
    for alert in alerts:
        es.index(index="ueba-alerts", body=alert)

if __name__ == "__main__":
    print("[*] Fetching recent events...")
    events = fetch_recent_events(hours=24)
    print(f"[*] Got {len(events)} events")
    baseline = build_user_baseline(events)

    print("[*] Running rule-based anomaly detection...")
    alerts = detect_anomalies(baseline)
    print(f"[*] Detected {len(alerts)} suspicious users")

    for a in alerts:
        print(f"User: {a['user']}, score={a['score']}, reasons={a['reasons']}")

    if alerts:
        print("[*] Indexing alerts into ueba-alerts index...")
        index_alerts(alerts)
        print("[*] Done.")
    else:
        print("[*] No anomalies found.")
