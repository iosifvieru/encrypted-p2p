import socket
import threading
import json
import secrets
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from crypto.rsa import rsa_encrypt
from aes.aes_encrypt import aes_encryption
from aes.aes_decrypt import aes_decryption

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9000 # Dedicated port for the server

class SecureServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        # Store connected clients: {'client_name': {'conn': socket_obj, 'pub_key': (e, n), 'aes_key': bytes}}
        self.connected_clients = {}
        self.client_lock = threading.Lock() # Protects access to self.connected_clients

        print(f"[Server] Initializing on {self.host}:{self.port}")

    def start(self):
        """Starts the server, listening for incoming client connections."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            print(f"[Server] Listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client_connection, args=(conn, addr), daemon=True).start()

    def recv_full(self, conn):
        """Helper to receive a full message given its length prefix."""
        try:
            raw_len = conn.recv(4)
            if not raw_len: return None
            msg_len = int.from_bytes(raw_len, 'big')
            data = b''
            conn.settimeout(10.0) # Increased timeout for server
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
            print(f"[Server] Error in recv_full: {e}")
            return None

    def send_data_direct(self, conn_socket, data):
        """Sends data over an already established socket connection."""
        try:
            message_bytes = json.dumps(data).encode('utf-8')
            msg_len_bytes = len(message_bytes).to_bytes(4, 'big')
            conn_socket.sendall(msg_len_bytes + message_bytes)
        except Exception as e:
            print(f"[Server] Error sending data directly to client: {e}")
            raise # Re-raise to let calling function know connection might be bad

    def handle_client_connection(self, conn, addr):
        """Handles initial handshake and then continuously receives messages from a connected client."""
        client_name = None
        try:
            # Step 1: Receive public key from client to identify them
            initial_data = self.recv_full(conn)
            if not initial_data:
                conn.close()
                return

            msg = json.loads(initial_data.decode())
            if msg.get("type") == "key" and "from" in msg and "data" in msg:
                client_name = msg["from"]
                client_pubkey = tuple(msg["data"])

                with self.client_lock:
                    self.connected_clients[client_name] = {
                        'conn': conn,
                        'pub_key': client_pubkey,
                        'aes_key': None # AES key will be generated and shared later
                    }
                print(f"[Server] Client {client_name} connected. Public key received.")

                # Step 2: Generate and send shared AES key to this client
                # The server generates AES key for each client independently
                shared_aes_key = secrets.token_bytes(16)
                with self.client_lock:
                    self.connected_clients[client_name]['aes_key'] = shared_aes_key

                encrypted_shared_aes = [rsa_encrypt(b, client_pubkey) for b in shared_aes_key]
                self.send_data_direct(conn, {
                    "type": "shared_aes_offer",
                    "from": "server", # The server is the sender
                    "data": encrypted_shared_aes
                })
                print(f"[Server] Sent shared AES key to {client_name}.")

            else:
                print(f"[Server] Invalid initial handshake from {addr}: {msg}")
                conn.close()
                return

            # Step 3: Continuously receive and process messages from this client
            while True:
                data = self.recv_full(conn)
                if not data: # Connection closed by client
                    print(f"[Server] Client {client_name} disconnected.")
                    with self.client_lock:
                        if client_name in self.connected_clients and self.connected_clients[client_name]['conn'] == conn:
                            del self.connected_clients[client_name]
                    break

                try:
                    msg = json.loads(data.decode())
                except json.JSONDecodeError:
                    print(f"[Server] Malformed JSON from {client_name}.")
                    continue

                if msg.get("type") == "message" and "from" in msg and "recipient" in msg and "data" in msg:
                    sender = msg["from"]
                    recipient = msg["recipient"]
                    ciphertext = bytes(msg["data"])

                    if sender != client_name: # Sanity check
                        print(f"[Server] Warning: Message 'from' field '{sender}' does not match connected client '{client_name}'. Discarding.")
                        continue

                    with self.client_lock:
                        sender_info = self.connected_clients.get(sender)
                        recipient_info = self.connected_clients.get(recipient)

                        if not sender_info or not sender_info['aes_key']:
                            print(f"[Server] No AES key for sender {sender}. Cannot decrypt.")
                            continue

                        if not recipient_info or not recipient_info['aes_key']:
                            print(f"[Server] Recipient {recipient} not found or no AES key. Cannot forward.")
                            continue

                        # Decrypt message from sender using their AES key
                        try:
                            plaintext_padded = aes_decryption(ciphertext, sender_info['aes_key'])
                            plaintext_str = plaintext_padded.decode('utf-8', errors='replace').rstrip('\x00')
                            print(f"[Server] Decrypted message from {sender} for {recipient}: '{plaintext_str}'")
                        except Exception as e:
                            print(f"[Server] Error decrypting message from {sender}: {e}")
                            continue

                        # Re-encrypt message for recipient using recipient's AES key
                        try:
                            msg_bytes = plaintext_str.encode("utf-8")
                            block_size = 16
                            msg_bytes_padded = msg_bytes.ljust(block_size, b'\0')
                            re_encrypted_ciphertext = aes_encryption(msg_bytes_padded, recipient_info['aes_key'])
                        except Exception as e:
                            print(f"[Server] Error re-encrypting message for {recipient}: {e}")
                            continue

                        # Forward the re-encrypted message
                        try:
                            self.send_data_direct(recipient_info['conn'], {
                                "type": "message",
                                "from": sender,
                                "recipient": recipient, # Keep recipient for client's display
                                "data": list(re_encrypted_ciphertext)
                            })
                            print(f"[Server] Forwarded message from {sender} to {recipient}.")
                        except Exception as e:
                            print(f"[Server] Failed to forward message to {recipient}: {e}")
                            if recipient in self.connected_clients:
                                recipient_info['conn'].close()
                                del self.connected_clients[recipient]


                else:
                    print(f"[Server] Unknown message type from {client_name}: {msg.get('type')}")

        except json.JSONDecodeError:
            print(f"[Server] Initial message from {client_name or addr} was not valid JSON.")
        except ConnectionResetError:
            print(f"[Server] Client {client_name or addr} unexpectedly disconnected.")
            with self.client_lock:
                if client_name in self.connected_clients:
                    self.connected_clients[client_name]['conn'].close()
                    del self.connected_clients[client_name]
        except Exception as e:
            print(f"[Server] Error handling client {client_name or addr}: {e}")
        finally:
            if conn and client_name not in self.connected_clients:
                conn.close()

if __name__ == "__main__":
    server = SecureServer(SERVER_HOST, SERVER_PORT)
    server.start()