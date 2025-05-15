import socket
import threading
import sys
import time
import json

import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from crypto.rsa import rsa_generate_keys, rsa_encrypt, rsa_decrypt

# Configuration
CLIENTS = {
    'client1': ('127.0.0.1', 9001),
    'client2': ('127.0.0.1', 9002),
    'client3': ('127.0.0.1', 9003),
}

BUFFER_SIZE = 1024
RETRY_ATTEMPTS = 5
RETRY_DELAY = 1  # seconds


class SecureClient:
    def __init__(self, name):
        self.name = name
        self.host, self.port = CLIENTS[name]
        self.public_key, self.private_key = rsa_generate_keys(128)
        self.known_peers = {k: v for k, v in CLIENTS.items() if k != name}
        self.peer_keys = {}

    def start(self):
        threading.Thread(target=self.start_server, daemon=True).start()
        time.sleep(1)
        self.broadcast_public_key()
        self.cli_loop()

    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"[{self.name}] Listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_connection, args=(conn,), daemon=True).start()

    def handle_connection(self, conn):
        with conn:
            try:
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    return
                msg = json.loads(data.decode())

                if msg["type"] == "key":
                    sender = msg["from"]
                    pubkey = tuple(msg["data"])
                    self.peer_keys[sender] = pubkey
                    print(f"[{self.name}] Received public key from {sender}")
                elif msg["type"] == "message":
                    sender = msg["from"]
                    cipher_int = int(msg["data"])
                    plain = rsa_decrypt(cipher_int, self.private_key)
                    print(f"\n[{self.name}] Encrypted message from {sender}: {plain} ('{chr(plain)}')\n> ", end='')
            except Exception as e:
                print(f"[{self.name}] Error handling connection: {e}")

    def broadcast_public_key(self):
        for peer_name in self.known_peers:
            self.send_data(peer_name, {
                "type": "key",
                "from": self.name,
                "data": list(self.public_key)
            })

    def send_data(self, peer_name, data):
        host, port = CLIENTS[peer_name]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((host, port))
                sock.sendall(json.dumps(data).encode())
        except Exception as e:
            print(f"[{self.name}] Could not send to {peer_name}: {e}")

    def cli_loop(self):
        print(f"[{self.name}] Ready. Known peers: {list(self.known_peers.keys())}")
        while True:
            try:
                command = input("> ").strip()
                if command.lower() in ['quit', 'exit']:
                    print("Exiting...")
                    break
                parts = command.split(" ", 1)
                if len(parts) != 2:
                    print("Usage: <target_client> <message>")
                    continue
                target, msg = parts
                if target == self.name:
                    print("Can't send to self.")
                    continue
                if target not in self.peer_keys:
                    print(f"No public key for {target} yet.")
                    continue
                plaintext = ord(msg[0])  # just send first char for simplicity
                encrypted = rsa_encrypt(plaintext, self.peer_keys[target])
                self.send_data(target, {
                    "type": "message",
                    "from": self.name,
                    "data": str(encrypted)
                })
                print(f"[{self.name}] Sent encrypted '{msg[0]}' to {target}")
            except KeyboardInterrupt:
                print("Exiting...")
                break

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python secure_client.py <client1|client2|client3>")
        sys.exit(1)
    client_name = sys.argv[1]
    if client_name not in CLIENTS:
        print("Unknown client. Choose from:", list(CLIENTS.keys()))
        sys.exit(1)
    SecureClient(client_name).start()