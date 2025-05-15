import socket
import threading
import sys
import time

# Configuration
CLIENTS = {
    'client1': ('127.0.0.1', 9001),
    'client2': ('127.0.0.1', 9002),
    'client3': ('127.0.0.1', 9003),
}

BUFFER_SIZE = 1024
RETRY_ATTEMPTS = 5
RETRY_DELAY = 1  # seconds


def start_server(host, port, name):
    """Server thread to receive messages."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen()
        print(f"[{name}] Listening on {host}:{port}...")

        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr, name), daemon=True).start()


def handle_client(conn, addr, name):
    """Handles incoming messages."""
    with conn:
        data = conn.recv(BUFFER_SIZE)
        if data:
            print(f"\n[{name}] Received from {addr}: {data.decode()}\n> ", end='')


def send_message(target_name, message, self_name):
    """Send message to another client, with retry logic."""
    if target_name not in CLIENTS:
        print(f"[{self_name}] Error: Unknown client {target_name}")
        return

    target_host, target_port = CLIENTS[target_name]
    for attempt in range(RETRY_ATTEMPTS):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((target_host, target_port))
                sock.sendall(message.encode())
                print(f"[{self_name}] Message sent to {target_name}")
                return
        except ConnectionRefusedError:
            print(f"[{self_name}] {target_name} not ready. Retrying ({attempt + 1}/{RETRY_ATTEMPTS})...")
            time.sleep(RETRY_DELAY)
    print(f"[{self_name}] Failed to send message to {target_name} after {RETRY_ATTEMPTS} attempts.")


def run_client(self_name):
    if self_name not in CLIENTS:
        print("Invalid client name. Choose from:", ', '.join(CLIENTS.keys()))
        return

    host, port = CLIENTS[self_name]

    # Start server thread first
    threading.Thread(target=start_server, args=(host, port, self_name), daemon=True).start()

    # Small delay to ensure all servers are up before allowing sends
    time.sleep(1)

    print(f"[{self_name}] Ready. Known peers: {[k for k in CLIENTS if k != self_name]}")

    while True:
        try:
            command = input("> ").strip()
            if command.lower() in ['quit', 'exit']:
                print("Exiting...")
                break
            parts = command.split(' ', 1)
            if len(parts) != 2:
                print("Usage: <target_client> <message>")
                continue
            target_client, message = parts
            if target_client == self_name:
                print("You can't message yourself.")
                continue
            send_message(target_client, message, self_name)
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client.py <client1|client2|client3>")
    else:
        run_client(sys.argv[1])
