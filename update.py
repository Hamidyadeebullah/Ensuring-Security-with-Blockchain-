import requests
import json
import time
import rsa
import uuid  # <-- Added: Needed to generate unique transaction IDs

BASE = "http://127.0.0.1:5000"

def json_dumps_canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))

if __name__ == "__main__":
    # 1. Load your identity (Keys)
    with open("private.pem", "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    with open("public.pem", "rb") as f:
        public_key_pem = f.read().decode('utf-8')

    # 2. Create the payload
    payload = {
        "tx_id": str(uuid.uuid4()),  # <-- Added: Replay Protection! Guarantees a unique ID.
        "course": "Web Programming",
        "term": "Fall 2025",
        "action": "update_schedule",
        "lessons": [
            {"day": "Sat", "time": "12:00", "room": "A3"},
            {"day": "Wed", "time": "12:00", "room": "A3"}
        ],
        "last_update": int(time.time()) # Sync timestamp with server
    }

    # 3. Sign the payload mathematically
    canonical_payload = json_dumps_canonical(payload)
    signature = rsa.sign(canonical_payload.encode('utf-8'), private_key, 'SHA-256')
    signature_hex = signature.hex()

    # 4. Transmit data + proof of identity
    transmission_data = {
        "payload": payload,
        "signature": signature_hex,
        "public_key": public_key_pem
    }

    print("Sending digitally signed payload to server...")
    res = requests.post(f"{BASE}/api/data", json=transmission_data)
    print(res.json())