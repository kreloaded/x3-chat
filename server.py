import socket
import threading
import base64
import dotenv

dotenv.load_dotenv()


class Server:
    def __init__(self, host="127.0.0.1", port=5001):
        self.host = host
        self.port = port
        self.public_keys = {}  # {user: {'id': key, 'prekey': key}}
        self.messages = {}  # {user: [messages]}

    def handle_client(self, conn, addr):
        try:
            while True:
                data = conn.recv(1024).decode()
                if not data:
                    break
                parts = data.strip().split()
                if parts[0] == "REGISTER":
                    user, key_type, key = parts[1], parts[2], " ".join(parts[3:])
                    if user not in self.public_keys:
                        self.public_keys[user] = {}
                    self.public_keys[user][key_type] = key
                    conn.send(b"OK")
                elif parts[0] == "GET_KEYS":
                    user = parts[1]
                    if user in self.public_keys:
                        keys = self.public_keys[user]
                        response = f"KEYS {keys['id']} {keys['prekey']}"
                        conn.send(response.encode())
                    else:
                        conn.send(b"ERROR")
                elif parts[0] == "SEND":
                    _, from_user, to_user, *message_parts = parts
                    message = " ".join(message_parts)
                    if to_user not in self.messages:
                        self.messages[to_user] = []
                    self.messages[to_user].append(message)
                    conn.send(b"OK")
                elif parts[0] == "RECEIVE":
                    user = parts[1]
                    if user in self.messages and self.messages[user]:
                        msg = self.messages[user].pop(0)
                        conn.send(msg.encode())
                    else:
                        conn.send(b"NO_MESSAGES")
                else:
                    conn.send(b"ERROR")
        finally:
            conn.close()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"Server listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    Server().start()
