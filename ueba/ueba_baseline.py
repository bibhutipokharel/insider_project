from elasticsearch import Elasticsearch
from datetime import datetime
from collections import defaultdict

# Connect to Elasticsearch
es = Elasticsearch("http://localhost:9200")

def fetch_recent_events(hours=24):
    """
    Fetch events from the last `hours` hours from user-activity-* index.
    """
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

def print_baseline(baseline):
    print("\n=== USER BASELINE (last 24h) ===\n")
    for user, stats in baseline.items():
        hours = sorted(list(stats["hours_active"]))
        print(f"User: {user}")
        print(f"  Total events      : {stats['total_events']}")
        print(f"  file_read         : {stats['file_read']}")
        print(f"  file_write        : {stats['file_write']}")
        print(f"  cmd               : {stats['cmd']}")
        print(f"  net_conn bytes    : {stats['net_conn_bytes']}")
        print(f"  Active hours      : {hours}")
        print("-" * 40)

if __name__ == "__main__":
    print("[*] Fetching recent events from Elasticsearch...")
    events = fetch_recent_events(hours=24)
    print(f"[*] Fetched {len(events)} events")

    baseline = build_user_baseline(events)
    print_baseline(baseline)
