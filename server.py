import json
import os
import time
import hashlib
import rsa
import sys
import requests
from typing import List, Dict, Any
from flask import Flask, jsonify, request
from urllib.parse import urlparse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
CHAIN_FILE = f"blockchain_{PORT}.json"
DIFFICULTY = 4

app = Flask(__name__)
peer_nodes = set()
seen_tx_ids = set()  # Memory bank for Replay Protection

# ---- FEATURE 2: NODE AUTHENTICATION WHITELIST ----
AUTHORIZED_PEERS = {
    "127.0.0.1:5000",
    "127.0.0.1:5001",
    "127.0.0.1:5002",
    "localhost:5000"
}


def json_dumps_canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def load_chain() -> List[Dict[str, Any]]:
    if not os.path.exists(CHAIN_FILE) or os.path.getsize(CHAIN_FILE) == 0:
        return []
    try:
        with open(CHAIN_FILE, "r", encoding="utf-8") as f:
            chain = json.load(f)
            # Re-populate our memory bank of used Transaction IDs on startup
            for block in chain:
                if isinstance(block.get("payload"), dict) and "tx_id" in block["payload"]:
                    seen_tx_ids.add(block["payload"]["tx_id"])
            return chain
    except json.JSONDecodeError:
        return []


def save_chain(chain: List[Dict[str, Any]]):
    with open(CHAIN_FILE, "w", encoding="utf-8") as f:
        json.dump(chain, f, indent=2)


def compute_block_hash(block: Dict[str, Any]) -> str:
    block_copy = block.copy()
    if "block_hash" in block_copy:
        del block_copy["block_hash"]
    return hashlib.sha256(json_dumps_canonical(block_copy).encode()).hexdigest()


def mine_block(block: Dict[str, Any]) -> Dict[str, Any]:
    block["nonce"] = 0
    while True:
        block_hash = compute_block_hash(block)
        if block_hash.startswith("0" * DIFFICULTY):
            block["block_hash"] = block_hash
            return block
        block["nonce"] += 1


def create_genesis_block() -> Dict[str, Any]:
    # ---- FEATURE 1: HARDCODED GENESIS BLOCK ----
    # By using a fixed timestamp (1700000000), every node generates the exact same root block!
    block = {
        "index": 0,
        "timestamp": 1700000000,
        "payload": "GENESIS",
        "signature": "None",
        "public_key": "None",
        "previous_hash": "0" * 64,
    }
    return mine_block(block)


def ensure_chain_initialized():
    if not load_chain():
        save_chain([create_genesis_block()])


def append_block(payload: Any, signature: str, public_key: str) -> Dict[str, Any]:
    chain = load_chain()
    last = chain[-1]
    block = {
        "index": last["index"] + 1,
        "timestamp": int(time.time()),
        "payload": payload,
        "signature": signature,
        "public_key": public_key,
        "previous_hash": last["block_hash"],
    }
    mined_block = mine_block(block)
    chain.append(mined_block)
    save_chain(chain)
    return mined_block


def valid_chain(chain: List[Dict[str, Any]]) -> bool:
    if not chain: return False

    chain_txs = set()  # Track transactions in this incoming chain

    for i in range(1, len(chain)):
        curr = chain[i]
        prev = chain[i - 1]

        if curr["index"] != i: return False
        if curr["timestamp"] < prev["timestamp"]: return False
        if not curr.get("block_hash", "").startswith("0" * DIFFICULTY): return False
        if curr["previous_hash"] != prev["block_hash"]: return False
        if compute_block_hash(curr) != curr.get("block_hash"): return False

        # Replay Protection Check for Incoming Chains
        if isinstance(curr.get("payload"), dict) and "tx_id" in curr["payload"]:
            tx_id = curr["payload"]["tx_id"]
            if tx_id in chain_txs:
                print(f"❌ [SECURITY] Block {i} rejected: Duplicate tx_id found in chain!")
                return False
            chain_txs.add(tx_id)

        try:
            if curr["signature"] != "None" and curr["public_key"] != "None":
                pub_key = rsa.PublicKey.load_pkcs1(curr["public_key"].encode('utf-8'))
                rsa.verify(json_dumps_canonical(curr["payload"]).encode('utf-8'), bytes.fromhex(curr["signature"]),
                           pub_key)
        except Exception:
            return False

    print("✅ [NETWORK] Incoming chain passed all security audits!")
    return True


def resolve_conflicts() -> bool:
    neighbors = peer_nodes
    new_chain = None
    max_length = len(load_chain())

    for node in neighbors:
        try:
            response = requests.get(f"http://{node}/api/chain")
            if response.status_code == 200:
                chain = response.json()
                length = len(chain)

                if length > max_length and valid_chain(chain):
                    max_length = length
                    new_chain = chain
        except requests.exceptions.RequestException:
            continue

    if new_chain:
        save_chain(new_chain)
        # Update our known transactions
        for block in new_chain:
            if isinstance(block.get("payload"), dict) and "tx_id" in block["payload"]:
                seen_tx_ids.add(block["payload"]["tx_id"])
        return True
    return False


@app.route("/api/data", methods=["POST"])
def api_update_data():
    ensure_chain_initialized()
    data = request.get_json(force=True)
    payload, signature_hex, public_key_pem = data["payload"], data["signature"], data["public_key"]

    # ---- FEATURE 3: REPLAY PROTECTION ----
    tx_id = payload.get("tx_id")
    if not tx_id:
        return jsonify({"error": "missing_tx_id"}), 400

    if tx_id in seen_tx_ids:
        return jsonify({"error": "replay_attack_detected_transaction_already_processed"}), 403

    canonical_payload = json_dumps_canonical(payload)

    try:
        pub_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode('utf-8'))
        rsa.verify(canonical_payload.encode('utf-8'), bytes.fromhex(signature_hex), pub_key)
    except rsa.VerificationError:
        return jsonify({"error": "invalid_signature"}), 401

    seen_tx_ids.add(tx_id)  # Log it so it can never be used again
    new_block = append_block(payload, signature_hex, public_key_pem)
    return jsonify({"ok": True, "message": "Block added", "block": new_block})


@app.route("/api/chain", methods=["GET"])
def api_get_chain():
    ensure_chain_initialized()
    return jsonify(load_chain())


@app.route("/api/nodes/register", methods=["POST"])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    registered_nodes = []
    for node in nodes:
        parsed_url = urlparse(node)
        netloc = parsed_url.netloc or parsed_url.path

        # Check against our whitelist
        if netloc in AUTHORIZED_PEERS:
            peer_nodes.add(netloc)
            registered_nodes.append(netloc)
        else:
            print(f"⚠️ [WARNING] Unauthorized node attempted to register: {netloc}")

    return jsonify({"message": "Authorized nodes added", "total_nodes": list(peer_nodes)}), 201


@app.route("/api/nodes/resolve", methods=["GET"])
def consensus():
    replaced = resolve_conflicts()
    if replaced:
        return jsonify({"message": "Our chain was replaced by the network consensus", "new_chain": load_chain()})
    else:
        return jsonify({"message": "Our chain is authoritative", "chain": load_chain()})


if __name__ == "__main__":
    ensure_chain_initialized()
    app.run(host="127.0.0.1", port=PORT, debug=True)