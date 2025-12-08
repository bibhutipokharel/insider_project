import socket
import json
import time
import uuid
import random
from datetime import datetime

USERS = ["alice", "bob", "carol", "dave", "eve"]

def simulate_file_access_spike(host="localhost", port=5044):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    user = random.choice(USERS)
    print(f"[*] Simulating massive file access spike for: {user}")

    try:
        for i in range(50):  # simulate 50 files accessed quickly
            event = {
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat(),
                "user": user,
                "action": "file_read",
                "file": f"/home/{user}/docs/file_{random.randint(1,20)}.txt",
                "cmd": None,
                "bytes": None,
                "source_ip": f"10.0.0.{random.randint(2,254)}"
            }

            s.sendall((json.dumps(event) + "\n").encode())
            print(f"Sent file access event {i+1}/50")

            time.sleep(0.05)  # rapid access (abnormal)
    finally:
        s.close()
        print("[*] File access spike simulation complete.")


if __name__ == "__main__":
    simulate_file_access_spike()
