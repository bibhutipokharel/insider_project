"""
UEBA anomaly detection module.

This script:
- Fetches recent user activity events from Elasticsearch (user-activity-* index)
- Builds a per-user behavior baseline (file reads/writes, commands, network bytes, hours active)
- Applies real-world style UEBA rules to detect suspicious behavior
- Assigns a risk score and severity to each user
- Indexes alerts into the 'ueba-alerts' index in Elasticsearch
"""

from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Any

from elasticsearch import Elasticsearch

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

ES_URL = "http://localhost:9200"
SOURCE_INDEX = "user-activity-*"
ALERT_INDEX = "ueba-alerts"

# "Business hours" for off-hours detection
BUSINESS_HOUR_START = 8   # 08:00
BUSINESS_HOUR_END = 18    # 18:00

# Rule thresholds (these can be tuned based on testing)
FILE_READ_HIGH = 20              # many file reads in time window
CMD_HIGH = 15                    # many commands
SUSPICIOUS_CMD_HIGH = 3          # many suspicious commands
NET_BYTES_HIGH = 10_000_000      # 10 MB in our synthetic data (tune as needed)


SUSPICIOUS_COMMANDS = [
    "scp",
    "wget",
    "curl",
    "rm",
    "chmod 777",
    "python script.py",
    "tar -cf backup.tar",
]


# -------------------------------------------------------------------
# Elasticsearch helpers
# -------------------------------------------------------------------

def get_es_client() -> Elasticsearch:
    """
    Return an Elasticsearch client instance.
    """
    return Elasticsearch(ES_URL)


def fetch_recent_events(es: Elasticsearch, hours: int = 24) -> List[Dict[str, Any]]:
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

    # Note: 'body' is deprecated but fine for lab usage
    resp = es.search(index=SOURCE_INDEX, body=query)
    hits = resp.get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]


# -------------------------------------------------------------------
# Baseline building
# -------------------------------------------------------------------

def build_user_baseline(events: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Build a per-user baseline with aggregated statistics:

    - total_events
    - file_read
    - file_write
    - cmd
    - suspicious_cmds
    - net_conn_bytes
    - hours_active
    - off_hours_activity
    """
    baseline: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "total_events": 0,
        "file_read": 0,
        "file_write": 0,
        "cmd": 0,
        "suspicious_cmds": 0,
        "net_conn_bytes": 0,
        "hours_active": set(),
        "off_hours_activity": False,
    })

    for ev in events:
        user = ev.get("user", "unknown")
        action = ev.get("action", "unknown")
        ts = ev.get("timestamp")
        bytes_ = ev.get("bytes", 0) or 0
        cmd = ev.get("cmd")

        user_stats = baseline[user]
        user_stats["total_events"] += 1

        # Action-specific counters
        if action == "file_read":
            user_stats["file_read"] += 1
        elif action == "file_write":
            user_stats["file_write"] += 1
        elif action == "cmd":
            user_stats["cmd"] += 1

            # Check if command is suspicious
            if cmd:
                for bad in SUSPICIOUS_COMMANDS:
                    if bad in cmd:
                        user_stats["suspicious_cmds"] += 1
                        break

        elif action == "net_conn":
            try:
                user_stats["net_conn_bytes"] += int(bytes_)
            except (TypeError, ValueError):
                pass

        # Time-based info
        if ts:
            try:
                dt = datetime.fromisoformat(ts)
                hour = dt.hour
                user_stats["hours_active"].add(hour)

                # Off-hours activity if outside business hour window
                if hour < BUSINESS_HOUR_START or hour > BUSINESS_HOUR_END:
                    user_stats["off_hours_activity"] = True
            except Exception:
                # In case timestamp format is weird, we ignore it
                pass

    # Convert sets to sorted lists for easier indexing / viewing
    for stats in baseline.values():
        stats["hours_active"] = sorted(list(stats["hours_active"]))

    return baseline


# -------------------------------------------------------------------
# Detection logic
# -------------------------------------------------------------------

def severity_from_score(score: int) -> str:
    """
    Map a numeric score to a severity label.
    """
    if score >= 4:
        return "critical"
    elif score == 3:
        return "high"
    elif score == 2:
        return "medium"
    elif score == 1:
        return "low"
    else:
        return "none"


def detect_anomalies(baseline: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Apply rule-based UEBA detection on the per-user baseline.

    Rules:
    - High file_read
    - High command count
    - High suspicious command count
    - High network bytes (possible exfiltration)
    - Off-hours activity
    """
    alerts: List[Dict[str, Any]] = []

    for user, stats in baseline.items():
        reasons: List[str] = []
        score = 0

        file_read = stats["file_read"]
        cmd = stats["cmd"]
        suspicious_cmds = stats["suspicious_cmds"]
        net_bytes = stats["net_conn_bytes"]
        off_hours = stats["off_hours_activity"]

        # Rule 1: High file_read volume
        if file_read > FILE_READ_HIGH:
            reasons.append(f"High file_read count: {file_read} (> {FILE_READ_HIGH})")
            score += 1

        # Rule 2: Many command executions
        if cmd > CMD_HIGH:
            reasons.append(f"High cmd count: {cmd} (> {CMD_HIGH})")
            score += 1

        # Rule 3: Suspicious commands used
        if suspicious_cmds > 0:
            reasons.append(f"Suspicious commands used: {suspicious_cmds}")
            score += 1

        # Rule 4: High network bytes (possible data exfiltration)
        if net_bytes > NET_BYTES_HIGH:
            reasons.append(f"High net_conn_bytes: {net_bytes} (> {NET_BYTES_HIGH})")
            score += 2  # weight this slightly higher

        # Rule 5: Off-hours activity
        if off_hours:
            reasons.append("Activity outside business hours")
            score += 1

        # Only generate alert if there is some suspicious behavior
        if score > 0:
            severity = severity_from_score(score)
            alert = {
                "timestamp": datetime.utcnow().isoformat(),
                "user": user,
                "score": score,
                "severity": severity,
                "reasons": reasons,
                "metrics": {
                    "total_events": stats["total_events"],
                    "file_read": file_read,
                    "file_write": stats["file_write"],
                    "cmd": cmd,
                    "suspicious_cmds": suspicious_cmds,
                    "net_conn_bytes": net_bytes,
                    "hours_active": stats["hours_active"],
                    "off_hours_activity": off_hours,
                },
            }
            alerts.append(alert)

    return alerts


# -------------------------------------------------------------------
# Indexing alerts
# -------------------------------------------------------------------

def index_alerts(es: Elasticsearch, alerts: List[Dict[str, Any]]) -> None:
    """
    Index all generated alerts into the ALERT_INDEX.
    """
    for alert in alerts:
        es.index(index=ALERT_INDEX, body=alert)


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

if __name__ == "__main__":
    es = get_es_client()

    print("[*] Fetching recent events from Elasticsearch...")
    events = fetch_recent_events(es, hours=24)
    print(f"[*] Got {len(events)} events")

    if not events:
        print("[!] No events found in the last 24 hours. Exiting.")
        exit(0)

    print("[*] Building user baseline...")
    baseline = build_user_baseline(events)

    print("[*] Running UEBA rule-based anomaly detection...")
    alerts = detect_anomalies(baseline)
    print(f"[*] Detected {len(alerts)} users with suspicious behavior.")

    for alert in alerts:
        print(
            f"User: {alert['user']}, "
            f"score={alert['score']}, "
            f"severity={alert['severity']}, "
            f"reasons={alert['reasons']}"
        )

    if alerts:
        print(f"[*] Indexing {len(alerts)} alerts into index '{ALERT_INDEX}'...")
        index_alerts(es, alerts)
        print("[*] Done.")
    else:
        print("[*] No anomalies found. No alerts indexed.")

