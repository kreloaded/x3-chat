import socket
import base64
import time
import os
import dotenv
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


class Alice:
    def __init__(self):
        self.id_priv = X25519PrivateKey.generate()
        self.id_pub = self.id_priv.public_key()
        self.eph_priv = X25519PrivateKey.generate()
        self.eph_pub = self.eph_priv.public_key()
        self.root_key = None
        self.send_chain = None
        self.recv_chain = None

    def get_bob_keys(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(b"GET_KEYS Bob")
            data = s.recv(1024).decode()
            if data.startswith("KEYS"):
                try:
                    _, id_key, prekey = data.split()
                    id_pub = X25519PublicKey.from_public_bytes(base64.b64decode(id_key))
                    prekey_pub = X25519PublicKey.from_public_bytes(
                        base64.b64decode(prekey)
                    )
                    return id_pub, prekey_pub
                except Exception as e:
                    print("Error decoding keys:", e)
                    return None, None
            else:
                print("Bob's keys not found. Is Bob running?")
                return None, None

    def x3dh(self, bob_id_pub, bob_prekey_pub):
        dh1 = self.id_priv.exchange(bob_id_pub)
        dh2 = self.id_priv.exchange(bob_prekey_pub)
        dh3 = self.eph_priv.exchange(bob_id_pub)
        shared_secret = dh1 + dh2 + dh3
        hkdf = HKDF(hashes.SHA256(), 32, None, b"x3dh root key")
        self.root_key = hkdf.derive(shared_secret)
        root_hkdf = HKDF(hashes.SHA256(), 64, None, b"root chain")
        root_material = root_hkdf.derive(self.root_key)
        self.send_chain, self.recv_chain = root_material[:32], root_material[32:]

    def step_chain(self, chain, info):
        hkdf = HKDF(hashes.SHA256(), 64, None, info)
        material = hkdf.derive(chain)
        return material[:32], material[32:]

    def encrypt(self, plaintext):
        msg_key, self.send_chain = self.step_chain(self.send_chain, b"send_chain")
        nonce = os.urandom(12)
        ciphertext = AESGCM(msg_key).encrypt(nonce, plaintext.encode(), None)
        return nonce, ciphertext

    def send(self, msg):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(f"SEND Alice Bob {msg}".encode())
            s.recv(1024)

    def start(self):
        time.sleep(1)
        bob_id_pub, bob_prekey_pub = self.get_bob_keys()
        if not bob_id_pub or not bob_prekey_pub:
            print("Could not retrieve Bob's keys. Exiting.")
            return
        self.x3dh(bob_id_pub, bob_prekey_pub)
        print("Root key established.")

        # Send Alice's public keys to Bob for root key derivation
        id_pub_b64 = base64.b64encode(self.id_pub.public_bytes_raw()).decode()
        eph_pub_b64 = base64.b64encode(self.eph_pub.public_bytes_raw()).decode()
        self.send(f"ALICE_KEYS {id_pub_b64} {eph_pub_b64}")
        print("Sent key info to Bob.")

        # Wait for Bob to process keys
        time.sleep(1)

        # Send encrypted message
        nonce, ciphertext = self.encrypt("Hello Bobby! 🕊️")
        self.send(
            f"MSG {base64.b64encode(nonce).decode()} {base64.b64encode(ciphertext).decode()}"
        )
        print("Message sent.")


if __name__ == "__main__":
    Alice().start()
