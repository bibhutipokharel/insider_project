import time
import random
import json
import socket
import uuid
from datetime import datetime

USERS = ["alice", "bob", "carol", "dave", "eve"]
ACTIONS = ["login", "logout", "file_read", "file_write", "cmd", "net_conn"]

def random_event():
    user = random.choice(USERS)
    action = random.choices(ACTIONS, weights=[10,10,30,10,20,20])[0]

    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "user": user,
        "action": action,
        "file": None,
        "cmd": None,
        "bytes": None,
        "source_ip": f"10.0.0.{random.randint(2,254)}"
    }

    if action in ("file_read", "file_write"):
        event["file"] = f"/home/{user}/docs/file_{random.randint(1,20)}.txt"

    if action == "cmd":
        event["cmd"] = random.choice(["cat", "scp", "wget", "rm", "python script.py", "chmod 777", "tar -cf backup.tar"])

    if action == "net_conn":
        event["bytes"] = random.randint(1000, 5000000)

    return event

def send_to_logstash(host="localhost", port=5044):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    print("[*] Sending logs to Logstash... Press Ctrl + C to stop.")

    try:
        while True:
            ev = random_event()
            data = json.dumps(ev) + "\n"
            s.sendall(data.encode())
            print("Sent:", ev)
            time.sleep(random.uniform(0.3, 2.0))
    except KeyboardInterrupt:
        print("Stopped log sending.")
        s.close()

if __name__ == "__main__":
    send_to_logstash()
