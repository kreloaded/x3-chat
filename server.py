import socket
import threading
import base64
import dotenv
import os

dotenv.load_dotenv()

HOST = os.getenv("HOST")
PORT = int(os.getenv("PORT"))


class Server:
    """
    A simple TCP-based messaging server that supports user registration with public keys,
    message exchange, and key retrieval.

    Attributes:
        host (str): IP address or hostname on which the server listens.
        port (int): Port number on which the server listens.
        public_keys (dict): Stores user public keys in the format {user: {'id': key, 'prekey': key}}.
        messages (dict): Stores pending messages for users in the format {user: [messages]}.
    """

    def __init__(self, host=HOST, port=PORT):
        """
        Initializes the Server with specified host and port.

        Args:
            host (str, optional): Host IP address or name. Defaults to HOST from environment.
            port (int, optional): Port number. Defaults to PORT from environment.
        """
        self.host = host
        self.port = port
        self.public_keys = {}  # {user: {'id': key, 'prekey': key}}
        self.messages = {}  # {user: [messages]}

    def handle_client(self, conn, addr):
        """
        Handles communication with a connected client.

        Supports the following commands from clients:
            - REGISTER <user> <key_type> <key>: Registers a public key for the user.
            - GET_KEYS <user>: Retrieves the registered keys for a user.
            - SEND <from_user> <to_user> <message>: Sends a message to another user.
            - RECEIVE <user>: Retrieves the oldest pending message for the user.

        Args:
            conn (socket.socket): Socket connection object for the client.
            addr (tuple): Client's (IP, port) address tuple.
        """
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
        """
        Starts the server and begins listening for incoming client connections.

        For each new client, a new thread is created to handle communication independently.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"Server listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    Server().start()
