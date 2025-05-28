import socket
import threading
import sys
import time
import json
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from crypto.rsa import rsa_generate_keys, rsa_decrypt
from aes.aes_encrypt import aes_encryption
from aes.aes_decrypt import aes_decryption

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9000 # Server's dedicated port

CLIENT_NAMES = ['client1', 'client2', 'client3']

class SecureClient:
    MAX_CONN_RETRIES = 5
    CONN_RETRY_DELAY = 2  # seconds

    def __init__(self, name):
        self.name = name
        self.public_key, self.private_key = rsa_generate_keys(128)
        self.server_connection = None # The persistent connection to the server
        self.server_aes_key = None    # AES key shared with the server
        self.lock = threading.Lock() # Protects shared resources like server_aes_key

        print(f"[{self.name}] Initializing...")

    def start(self):
        """Starts the client: connects to server, exchanges keys, and starts CLI."""
        self.connect_to_server()
        if not self.server_connection:
            print(f"[{self.name}] Failed to connect to server. Exiting.")
            sys.exit(1)

        # Start a separate thread to continuously receive messages from the server
        threading.Thread(target=self.receive_messages_from_server, daemon=True).start()

        # Wait for the AES key from the server
        self.wait_for_server_aes_key()

        self.cli_loop()

    def connect_to_server(self):
        """Establishes and maintains the connection to the SecureServer."""
        print(f"[{self.name}] Connecting to server at {SERVER_HOST}:{SERVER_PORT}...")
        for attempt in range(self.MAX_CONN_RETRIES):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0) # Set a timeout for connection
                sock.connect((SERVER_HOST, SERVER_PORT))
                sock.settimeout(None) # Remove timeout after connection

                self.server_connection = sock
                print(f"[{self.name}] Successfully connected to server on attempt {attempt + 1}.")

                # Send public key to server immediately
                self.send_data_to_server({
                    "type": "key",
                    "from": self.name,
                    "data": list(self.public_key)
                })
                print(f"[{self.name}] Sent public key to server.")
                return True
            except (ConnectionRefusedError, socket.timeout, OSError) as e:
                print(f"[{self.name}] Connection to server failed on attempt {attempt + 1}/{self.MAX_CONN_RETRIES}: {e}")
                sock.close()
                if attempt < self.MAX_CONN_RETRIES - 1:
                    print(f"[{self.name}] Retrying in {self.CONN_RETRY_DELAY} seconds...")
                    time.sleep(self.CONN_RETRY_DELAY)
                else:
                    print(f"[{self.name}] Failed to connect to server after {self.MAX_CONN_RETRIES} attempts.")
                    return False
            except Exception as e:
                print(f"[{self.name}] Unexpected error connecting to server: {e}")
                sock.close()
                return False

    def recv_full(self, conn):
        """Helper to receive a full message given its length prefix."""
        try:
            raw_len = conn.recv(4)
            if not raw_len: return None
            msg_len = int.from_bytes(raw_len, 'big')
            data = b''
            conn.settimeout(10.0) # Longer timeout for server
            while len(data) < msg_len:
                packet = conn.recv(msg_len - len(data))
                if not packet:
                    conn.settimeout(None)
                    return None
                data += packet
            conn.settimeout(None)
            return data
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[{self.name}] Error in recv_full from server: {e}")
            return None

    def send_data_to_server(self, data):
        """Sends JSON data to the server over the persistent connection."""
        if not self.server_connection:
            print(f"[{self.name}] No active connection to server. Cannot send data.")
            return False
        try:
            message_bytes = json.dumps(data).encode('utf-8')
            msg_len_bytes = len(message_bytes).to_bytes(4, 'big')
            self.server_connection.sendall(msg_len_bytes + message_bytes)
            return True
        except Exception as e:
            print(f"[{self.name}] Error sending data to server: {e}")
            self.server_connection.close()
            self.server_connection = None
            self.server_aes_key = None # Invalidate key on connection loss
            print(f"[{self.name}] Server connection lost. Please restart client.")
            return False

    def receive_messages_from_server(self):
        """Dedicated thread to continuously receive and process messages from the server."""
        while self.server_connection:
            try:
                data = self.recv_full(self.server_connection)
                if not data:
                    print(f"[{self.name}] Server disconnected.")
                    with self.lock:
                        if self.server_connection:
                            self.server_connection.close()
                            self.server_connection = None
                            self.server_aes_key = None
                    print(f"[{self.name}] Server connection lost. Please restart client.")
                    break # Exit thread

                try:
                    msg = json.loads(data.decode())
                except json.JSONDecodeError:
                    print(f"[{self.name}] Received malformed JSON from server.")
                    continue

                msg_type = msg.get("type")

                if msg_type == "shared_aes_offer":
                    sender_name = msg.get("from")
                    encrypted_shared_aes = msg["data"]
                    if sender_name == "server": # Expecting AES key from server
                        try:
                            decrypted_shared_aes_bytes = bytes(
                                [rsa_decrypt(c, self.private_key) for c in encrypted_shared_aes])
                            with self.lock:
                                self.server_aes_key = decrypted_shared_aes_bytes
                            print(f"[{self.name}] Received and stored shared AES key from server.")
                        except Exception as e:
                            print(f"[{self.name}] Failed to decrypt/store shared AES key from server: {e}")
                    else:
                        print(f"[{self.name}] Unexpected AES offer from {sender_name}. Discarding.")

                elif msg_type == "message":
                    sender = msg.get("from")
                    recipient = msg.get("recipient")
                    ciphertext = bytes(msg["data"])

                    with self.lock:
                        if not self.server_aes_key:
                            print(f"[{self.name}] No SHARED AES key with server yet. Cannot decrypt message from {sender}")
                            continue
                        try:
                            plaintext_padded = aes_decryption(ciphertext, self.server_aes_key)
                            plaintext_str = plaintext_padded.decode('utf-8', errors='replace').rstrip('\x00')
                            print(f"\n[{self.name}] Encrypted message from {sender} (for {recipient or self.name}): '{plaintext_str}'\n> ", end='')
                        except Exception as e:
                            print(f"\n[{self.name}] Error decrypting/decoding message from {sender}: {e}\n> ", end='')

                else:
                    print(f"[{self.name}] Unknown message type from server: {msg_type}")

            except Exception as e:
                print(f"[{self.name}] Error in receive_messages_from_server: {e}")
                break # Break loop if error occurs


    def wait_for_server_aes_key(self):
        """Pauses execution until the AES key with the server is established."""
        print(f"[{self.name}] Waiting for AES key from server...")
        while True:
            with self.lock:
                if self.server_aes_key:
                    break
            print(f"[{self.name}] Still waiting for AES key from server...")
            time.sleep(1)
        print(f"[{self.name}] Shared AES key with server established!")


    def cli_loop(self):
        print(f"[{self.name}] Ready. Known peers (via server): {CLIENT_NAMES}")
        while True:
            try:
                command = input("> ").strip()
                if command.lower() in ['quit', 'exit']:
                    print(f"[{self.name}] Exiting...")
                    if self.server_connection:
                        self.server_connection.close() # Close connection cleanly
                    break
                parts = command.split(" ", 1)
                if len(parts) != 2:
                    print("Usage: <target_client> <message>")
                    continue

                target, msg_text = parts
                if target == self.name: print("Can't send to self."); continue
                if target not in CLIENT_NAMES: print(f"Unknown target: {target}. Known: {CLIENT_NAMES}"); continue

                with self.lock:
                    if not self.server_aes_key:
                        print(f"[{self.name}] No SHARED AES key with server. Cannot send.")
                        continue

                msg_bytes = msg_text.encode("utf-8")
                block_size = 16
                msg_bytes_padded = msg_bytes.ljust(block_size, b'\0')

                with self.lock:
                    ciphertext = aes_encryption(msg_bytes_padded, self.server_aes_key)

                message_payload = {
                    "type": "message",
                    "from": self.name,
                    "recipient": target, # Indicate final recipient to the server
                    "data": list(ciphertext)
                }

                if self.send_data_to_server(message_payload):
                    print(f"[{self.name}] Sent AES-encrypted message to server for {target}")
                else:
                    print(f"[{self.name}] Failed to send message to server.")

            except KeyboardInterrupt:
                print(f"\n[{self.name}] Exiting...")
                if self.server_connection:
                    self.server_connection.close()
                break
            except Exception as e:
                print(f"[{self.name}] Error in CLI loop: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client.py <client1|client2|client3>")
        sys.exit(1)
    client_name_arg = sys.argv[1]
    if client_name_arg not in CLIENT_NAMES:
        print(f"Unknown client: {client_name_arg}. Choose from: {CLIENT_NAMES}")
        sys.exit(1)
    SecureClient(client_name_arg).start()