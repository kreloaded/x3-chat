import socket
import base64
import time
import dotenv
import os
import threading
import cryptography
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

dotenv.load_dotenv()

HOST = os.getenv("HOST")
PORT = int(os.getenv("PORT"))


class Bob:
    def __init__(self):
        self.id_priv = X25519PrivateKey.generate()
        self.id_pub = self.id_priv.public_key()
        self.prekey_priv = X25519PrivateKey.generate()
        self.prekey_pub = self.prekey_priv.public_key()
        self.root_key = None
        self.send_chain = None
        self.recv_chain = None

    def register(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(
                f"REGISTER Bob id {base64.b64encode(self.id_pub.public_bytes_raw()).decode()}".encode()
            )
            s.recv(1024)
            s.send(
                f"REGISTER Bob prekey {base64.b64encode(self.prekey_pub.public_bytes_raw()).decode()}".encode()
            )
            s.recv(1024)

    def x3dh(self, alice_id_pub, alice_eph_pub):
        dh1 = self.id_priv.exchange(alice_id_pub)
        dh2 = self.prekey_priv.exchange(alice_id_pub)
        dh3 = self.id_priv.exchange(alice_eph_pub)
        shared_secret = dh1 + dh2 + dh3
        hkdf = HKDF(hashes.SHA256(), 32, None, b"x3dh root key")
        self.root_key = hkdf.derive(shared_secret)
        root_hkdf = HKDF(hashes.SHA256(), 64, None, b"root chain")
        root_material = root_hkdf.derive(self.root_key)
        self.recv_chain, self.send_chain = root_material[:32], root_material[32:]

    def step_chain(self, chain, info):
        hkdf = HKDF(hashes.SHA256(), 64, None, info)
        material = hkdf.derive(chain)
        return material[:32], material[32:]

    def decrypt(self, nonce, ciphertext):
        msg_key, self.recv_chain = self.step_chain(self.recv_chain, b"send_chain")
        try:
            decrypted_message = AESGCM(msg_key).decrypt(nonce, ciphertext, None)
            return decrypted_message
        except cryptography.exceptions.InvalidTag:
            print("Decryption failed due to invalid tag.")
            raise
        except Exception as e:
            print(f"Error during decryption: {e}")
            raise

    def encrypt(self, plaintext):
        msg_key, self.send_chain = self.step_chain(self.send_chain, b"send_chain")
        nonce = os.urandom(12)
        ciphertext = AESGCM(msg_key).encrypt(nonce, plaintext.encode(), None)
        return nonce, ciphertext

    def send_message(self, msg):
        nonce, ciphertext = self.encrypt(msg)
        encoded_nonce = base64.b64encode(nonce).decode()
        encoded_ciphertext = base64.b64encode(ciphertext).decode()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(f"SEND Bob Alice MSG {encoded_nonce} {encoded_ciphertext}".encode())
            s.recv(1024)

    def listen(self):
        self.register()
        print("Bob is ready.")

        # Start sending thread
        def send_input():
            while True:
                message = input("You (Bob): ")
                self.send_message(message)

        threading.Thread(target=send_input, daemon=True).start()

        # Listen for messages
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.send(b"RECEIVE Bob")
                data = s.recv(2048).decode()
                if data == "NO_MESSAGES":
                    time.sleep(0.5)
                    continue
                if data.startswith("ALICE_KEYS"):
                    _, id_pub, eph_pub = data.split()
                    alice_id = X25519PublicKey.from_public_bytes(
                        base64.b64decode(id_pub)
                    )
                    alice_eph = X25519PublicKey.from_public_bytes(
                        base64.b64decode(eph_pub)
                    )
                    self.x3dh(alice_id, alice_eph)
                    print("Root key established.")
                elif data.startswith("MSG"):
                    _, nonce, ciphertext = data.split()
                    try:
                        decrypted = self.decrypt(
                            base64.b64decode(nonce), base64.b64decode(ciphertext)
                        )
                        print(f"\nAlice: {decrypted.decode()}")
                    except Exception as e:
                        print(f"\nFailed to decrypt message: {e}")


if __name__ == "__main__":
    Bob().listen()
