import time
import requests
from datetime import datetime, timezone

from email_alert import send_alert

ES = "http://localhost:9200"
ES_USER = "elastic"
ES_PASS = "C7cmrEkygq9=JTU7HTAu"

SOURCE_INDEX = "user-activity-*"
DEST_INDEX = "ueba-alerts"

# Prevent duplicate alert indexing + emailing
SEEN_EVENTS = set()
EMAILED = set()

SEEN_LIMIT = 5000


def now_iso():
    return datetime.now(timezone.utc).isoformat()


from requests.auth import HTTPBasicAuth

def fetch_recent(minutes=5, size=2000):
    query = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "range": {"@timestamp": {"gte": f"now-{minutes}m"}}
        }
    }

    r = requests.get(
        f"{ES}/{SOURCE_INDEX}/_search",
        json=query,
        headers={
            "Content-Type": "application/json"
        },
        auth=HTTPBasicAuth(ES_USER, ES_PASS),
        timeout=10
    )

    r.raise_for_status()
    hits = r.json().get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]


def score_event(e):
    score = 0
    reasons = []

    # Base suspicious flag
    if e.get("is_suspicious"):
        r = e.get("suspicious_reason")
        if isinstance(r, list):
            reasons.extend(r)
        elif r:
            reasons.append(r)
        else:
            reasons.append("suspicious_flag")
        score += 40

    # Network exfiltration
    if e.get("action") == "net_conn" and (e.get("bytes_sent") or 0) > 5_000_000:
        score += 30
        reasons.append("high_bytes_sent")

    # Dangerous commands
    if e.get("action") == "cmd" and e.get("command"):
        if any(x in e["command"] for x in ["rm -rf", "scp", "wget"]):
            score += 30
            reasons.append("dangerous_command")

    # Suspicious websites
    if e.get("action") == "web_access" and e.get("url"):
        if any(x in e["url"] for x in ["mega.nz", "dropbox.com", "pastebin.com", "anonfiles.com", ".onion"]):
            score += 25
            reasons.append("suspicious_website")

    # Role sensitivity
    if e.get("role") in ["Intern", "Contractor"] and score > 0:
        score += 15
        reasons.append("high_risk_role")

    # Deduplicate reasons safely (handles list values too)
    clean = []
    for r in reasons:
        if isinstance(r, list):
            for x in r:
                if x not in clean:
                    clean.append(x)
        else:
            if r not in clean:
                clean.append(r)

    return score, clean


def risk_level(score):
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "normal"


def index_alert(doc):
    r = requests.post(
        f"{ES}/{DEST_INDEX}/_doc",
        json=doc,
        auth=(ES_USER, ES_PASS),
        timeout=10
    )
    r.raise_for_status()


def remember_event(event_id):
    """Return True if already seen, else remember it and return False."""
    if not event_id:
        return False

    if event_id in SEEN_EVENTS:
        return True

    SEEN_EVENTS.add(event_id)

    # Keep memory bounded
    if len(SEEN_EVENTS) > SEEN_LIMIT:
        for _ in range(SEEN_LIMIT // 10):
            SEEN_EVENTS.pop()

    return False


def main():
    print("[+] UEBA scoring started (Ctrl+C to stop)")

    while True:
        try:
            events = fetch_recent(minutes=5, size=2000)

            for e in events:
                eid = e.get("event_id")

                # Avoid duplicate processing
                if remember_event(eid):
                    continue

                s, reasons = score_event(e)

                # Store only notable alerts
                if s >= 40:
                    doc = {
                        "@timestamp": now_iso(),
                        "user": e.get("user"),
                        "role": e.get("role"),
                        "action": e.get("action"),
                        "risk_score": s,
                        "risk_level": risk_level(s),
                        "reasons": reasons,
                        "event_id": eid,
                    }

                    # Index to Elasticsearch for dashboards
                    index_alert(doc)

                    # Send email immediately for HIGH risk (only once per event)
                    if doc["risk_level"] == "high" and eid and eid not in EMAILED:
                        subject = f"[UEBA ALERT] HIGH - {doc.get('user')} - {doc.get('action')}"
                        body = (
                            f"Time: {doc.get('@timestamp')}\n"
                            f"User: {doc.get('user')}\n"
                            f"Role: {doc.get('role')}\n"
                            f"Action: {doc.get('action')}\n"
                            f"Risk Score: {doc.get('risk_score')}\n"
                            f"Reasons: {doc.get('reasons')}\n"
                            f"Event ID: {doc.get('event_id')}\n"
                        )
                        send_alert(subject, body)
                        EMAILED.add(eid)

            time.sleep(10)

        except KeyboardInterrupt:
            print("\n[!] Stopped by user")
            break
        except Exception as ex:
            print(f"[!] Error: {ex}")
            time.sleep(5)


if __name__ == "__main__":
    main()

