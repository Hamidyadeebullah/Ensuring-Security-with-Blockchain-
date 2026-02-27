# register.py
import requests

node_a_url = "http://127.0.0.1:5000"

# Tell Node B about Node A
print("Registering Node A with Node B...")
res_b = requests.post("http://127.0.0.1:5001/api/nodes/register", json={"nodes": [node_a_url]})
print("Node B says:", res_b.json())

# Tell Node C about Node A
print("\nRegistering Node A with Node C...")
res_c = requests.post("http://127.0.0.1:5002/api/nodes/register", json={"nodes": [node_a_url]})
print("Node C says:", res_c.json())