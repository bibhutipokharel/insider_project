import socket, json, uuid, time
from datetime import datetime
import random

USER = random.choice(["alice", "bob", "carol", "dave", "eve"])

def send(ev):
    s = socket.socket()
    s.connect(("localhost", 5044))
    s.sendall((json.dumps(ev) + "\n").encode())
    s.close()

print("[*] Simulating massive file read spike...")

for i in range(50):
    ev = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "user": USER,
        "action": "file_read",
        "file": f"/home/{USER}/docs/secret_{i}.txt",
        "cmd": None,
        "bytes": None,
        "source_ip": f"10.0.0.{random.randint(2,254)}"
    }
    print("File read:", ev["file"])
    send(ev)
    time.sleep(0.2)

print("[*] File access spike simulation complete.")
