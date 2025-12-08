import socket
import json
import uuid
import time
import random
from datetime import datetime

USERS = ["alice", "bob", "carol", "dave", "eve"]

def simulate_network_exfil(host="localhost", port=5044):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    user = random.choice(USERS)
    print(f"[*] Simulating LARGE data exfiltration for user: {user}")

    try:
        for i in range(30):  # 30 rapid large transfers
            bytes_sent = random.randint(5_000_000, 25_000_000)

            event = {
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat(),
                "user": user,
                "action": "net_conn",
                "file": None,
                "cmd": None,
                "bytes": bytes_sent,
                "source_ip": f"10.0.0.{random.randint(2,254)}"
            }

            s.sendall((json.dumps(event) + "\n").encode())
            print(f"Sent network transfer {i+1}/30 → {bytes_sent} bytes")

            time.sleep(0.05)  # very fast → abnormal
    finally:
        s.close()
        print("[*] Network exfiltration simulation complete.")


if __name__ == "__main__":
    simulate_network_exfil()
