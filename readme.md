# Blockchain-Based Data Integrity Verification (Minimal)


This project augments a basic integrity check with a tiny blockchain ledger to make tampering evident. No consensus/mining — just hash chaining.


## Run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python server.py
# new terminal
python client.py