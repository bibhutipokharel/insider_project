import socket, json, uuid, time
from datetime import datetime
import random

USER = random.choice(["alice", "bob", "carol", "dave", "eve"])

def send(ev):
    s = socket.socket()
    s.connect(("localhost", 5044))
    s.sendall((json.dumps(ev) + "\n").encode())
    s.close()

print("[*] Simulating data exfiltration (high network bytes)...")

for i in range(10):
    ev = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "user": USER,
        "action": "net_conn",
        "bytes": random.randint(5_000_000, 25_000_000),
        "file": None,
        "cmd": None,
        "source_ip": f"10.0.0.{random.randint(2,254)}"
    }
    print("Sending exfil packet:", ev["bytes"])
    send(ev)
    time.sleep(0.5)

print("[*] Data exfiltration attack complete.")
