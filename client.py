import requests
import hashlib
import json
import rsa

# You can point this to Node A (5000), Node B (5001), or Node C (5002)
BASE = "http://127.0.0.1:5000"
DIFFICULTY = 4


def json_dumps_canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def compute_block_hash(block):
    block_copy = block.copy()
    if "block_hash" in block_copy:
        del block_copy["block_hash"]
    return hashlib.sha256(json_dumps_canonical(block_copy).encode()).hexdigest()


def verify_locally(chain):
    if not chain:
        return False, "empty_chain"

    seen_tx_ids = set()

    for i in range(len(chain)):
        curr = chain[i]

        # 1. Verify Index Consistency
        if curr.get("index") != i:
            return False, f"invalid_index_at_block_{i}"

        # 2. Verify Proof of Work (Immutability)
        if not curr.get("block_hash", "").startswith("0" * DIFFICULTY):
            return False, f"invalid_pow_at_{i}"

        # 3. Verify Block Integrity (Tampering)
        if compute_block_hash(curr) != curr.get("block_hash"):
            return False, f"bad_block_hash_at_{i}"

        if i > 0:
            prev = chain[i - 1]

            # 4. Verify Links
            if curr["previous_hash"] != prev["block_hash"]:
                return False, f"bad_link_at_{i}"

            # 5. Verify Time Flow (No time travel)
            if curr["timestamp"] < prev["timestamp"]:
                return False, f"time_travel_detected_at_block_{i}"

            # 6. Verify Replay Protection (Duplicate tx_id)
            if isinstance(curr.get("payload"), dict) and "tx_id" in curr["payload"]:
                tx_id = curr["payload"]["tx_id"]
                if tx_id in seen_tx_ids:
                    return False, f"replay_attack_detected_at_block_{i}"
                seen_tx_ids.add(tx_id)

            # 7. Verify Digital Signatures (Transmission Security)
            try:
                if curr["signature"] != "None" and curr["public_key"] != "None":
                    pub_key = rsa.PublicKey.load_pkcs1(curr["public_key"].encode('utf-8'))
                    canonical_payload = json_dumps_canonical(curr["payload"])
                    rsa.verify(canonical_payload.encode('utf-8'), bytes.fromhex(curr["signature"]), pub_key)
            except Exception:
                return False, f"invalid_signature_at_block_{i}"

    return True, "ok"


if __name__ == "__main__":
    print(f"Fetching blockchain from {BASE}...")
    try:
        chain = requests.get(f"{BASE}/api/chain").json()
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the node. Is the server running?")
        exit()

    ok, reason = verify_locally(chain)
    print(f"Cryptographic Audit: {ok} ({reason})")

    if ok and len(chain) > 1:
        # Extract the latest valid schedule
        latest_data = chain[-1]["payload"]

        # Remove the tx_id and last_update just for a cleaner printout
        display_data = latest_data.copy()
        display_data.pop("tx_id", None)
        display_data.pop("last_update", None)

        print("\n🔒 100% Verified Current Schedule:")
        print(json.dumps(display_data, indent=2))
    elif ok and len(chain) == 1:
        print("\nChain is valid, but currently empty (Only Genesis block exists).")