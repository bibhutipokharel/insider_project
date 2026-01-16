import time
import requests
from datetime import datetime, timezone
from email_alert import send_alert

# ====== Elasticsearch / Kibana basic ======
ES = "http://localhost:9200"
ES_USER = "elastic"
ES_PASS = "ChangeMeStrong123!"

# Read REAL logs from filebeat (system auth)
SOURCE_INDEX = "filebeat-*"

DEST_INDEX = "ueba-alerts"


EMAILED = set()
USER_ROLES = {
    "hr_alice": "HR",
    "finance_bob": "Finance",
    "it_carol": "IT",
    "dev_dave": "Developer",
    "sec_trent": "Security",
    "intern_eve": "Intern",
}

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def fetch_recent(minutes=10, size=200):
    # Pull recent auth events only (su/sudo/ssh/login failures)
    query = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "_source": True,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                    # system auth dataset (works on Filebeat system module)
                    {"term": {"event.dataset": "system.auth"}}
                ]
            }
        }
    }
    r = requests.get(
        f"{ES}/{SOURCE_INDEX}/_search",
        json=query,
        auth=(ES_USER, ES_PASS),
        timeout=10
    )
    r.raise_for_status()
    hits = r.json().get("hits", {}).get("hits", [])
    return hits

def extract_username(src: dict):
    # Try common locations in filebeat auth events
    for key_path in [
        ("user", "name"),
        ("user",),
        ("source", "user", "name"),
        ("destination", "user", "name"),
    ]:
        cur = src
        ok = True
        for k in key_path:
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                ok = False
                break
        if ok and isinstance(cur, str) and cur.strip():
            return cur.strip()
    return None

def score_auth_event(src: dict):
    """
    Simple, explainable UEBA scoring for REAL auth logs.
    We treat ANY user as normal until suspicious activity occurs.
    """
    score = 0
    reasons = []

    msg = (src.get("message") or "").lower()
    event_action = (src.get("event", {}).get("action") or "").lower()

    # Failed login attempts (very common insider / brute force sign)
    if "failed password" in msg or "authentication failure" in msg or "failed" in event_action:
        score += 50
        reasons.append("failed_login")

    # sudo usage (privilege attempt)
    if "sudo" in msg or "sudo" in event_action:
        score += 35
        reasons.append("sudo_usage")

    # su usage (user switching)
    if "session opened for user" in msg and "su" in msg:
        score += 25
        reasons.append("user_switch_su")

    # If user is unknown (not in our staff list) -> suspicious
    user = extract_username(src)
    if user and user not in USER_ROLES:
        score += 20
        reasons.append("unknown_user")

    # Intern/Contractor roles are higher risk if they do privileged actions
    role = USER_ROLES.get(user)
    if role in ["Intern", "Contractor"] and ("sudo_usage" in reasons or "failed_login" in reasons):
        score += 15
        reasons.append("high_risk_role")

    return score, list(dict.fromkeys(reasons)), user, role

def risk_level(score: int):
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "normal"

def index_alert(doc: dict):
    requests.post(
        f"{ES}/{DEST_INDEX}/_doc",
        json=doc,
        auth=(ES_USER, ES_PASS),
        timeout=10
    ).raise_for_status()

def main():
    print("[+] UEBA (REAL USERS) started. Monitoring filebeat system auth logs...")
    seen_doc_ids = set()

    while True:
        hits = fetch_recent(minutes=10, size=200)

        for h in hits:
            doc_id = h.get("_id")
            src = h.get("_source", {})

            # Avoid re-processing same filebeat event repeatedly
            if doc_id in seen_doc_ids:
                continue
            seen_doc_ids.add(doc_id)

            score, reasons, user, role = score_auth_event(src)
            if score < 40:
                continue

            alert_doc = {
                "@timestamp": now_iso(),
                "source_index": SOURCE_INDEX,
                "source_doc_id": doc_id,
                "user": user or "unknown",
                "role": role or "unknown",
                "action": (src.get("event", {}).get("action") or "auth_event"),
                "risk_score": score,
                "risk_level": risk_level(score),
                "reasons": reasons,
                "raw_message": src.get("message"),
            }

            # Store alert in Elasticsearch
            index_alert(alert_doc)
            print("[ALERT]", alert_doc["risk_level"], alert_doc["user"], alert_doc["reasons"])
            if alert_doc["risk_level"] == "high" and doc_id not in EMAILED:
                EMAILED.add(doc_id)
                try:
                    send_alert(alert_doc) 
                    print("📧 Email sent:", alert_doc["user"], alert_doc["reasons"])
                except Exception as e:
                    print("Email failed:", e)

        time.sleep(10)

if __name__ == "__main__":
    main()
