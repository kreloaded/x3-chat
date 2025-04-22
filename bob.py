import socket
import base64
import time

import cryptography
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
            s.connect(('127.0.0.1', 5001))
            s.send(f'REGISTER Bob id {base64.b64encode(self.id_pub.public_bytes_raw()).decode()}'.encode())
            s.recv(1024)
            s.send(f'REGISTER Bob prekey {base64.b64encode(self.prekey_pub.public_bytes_raw()).decode()}'.encode())
            s.recv(1024)

    def x3dh(self, alice_id_pub, alice_eph_pub):
        dh1 = self.id_priv.exchange(alice_id_pub)
        dh2 = self.prekey_priv.exchange(alice_id_pub)
        dh3 = self.id_priv.exchange(alice_eph_pub)
        shared_secret = dh1 + dh2 + dh3
        hkdf = HKDF(hashes.SHA256(), 32, None, b'x3dh root key')
        self.root_key = hkdf.derive(shared_secret)
        root_hkdf = HKDF(hashes.SHA256(), 64, None, b'root chain')
        root_material = root_hkdf.derive(self.root_key)
        self.recv_chain, self.send_chain = root_material[:32], root_material[32:]

    def step_chain(self, chain, info):
        hkdf = HKDF(hashes.SHA256(), 64, None, info)
        material = hkdf.derive(chain)
        return material[:32], material[32:]

    def decrypt(self, nonce, ciphertext):
        msg_key, self.recv_chain = self.step_chain(self.recv_chain, b'send_chain')
        print(f"Bob msg_key: {msg_key}")  # Log the msg_key here
        try:
            decrypted_message = AESGCM(msg_key).decrypt(nonce, ciphertext, None)
            print("Decrypted message:", decrypted_message.decode())
            return decrypted_message
        except cryptography.exceptions.InvalidTag:
            print("Decryption failed due to invalid tag.")
            raise
        except Exception as e:
            print(f"Error during decryption: {e}")
            raise

    def listen(self):
        self.register()
        print("Bob is ready.")
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('127.0.0.1', 5001))
                s.send(b'RECEIVE Bob')

                try:
                    msg = s.recv(2048).decode()
                except ValueError:
                    print("Message decryption failed on bob's side")

                if msg == 'NO_MESSAGES':
                    time.sleep(0.5)
                    continue
                if msg.startswith('ALICE_KEYS'):
                    _, id_pub, eph_pub = msg.split()
                    alice_id = X25519PublicKey.from_public_bytes(base64.b64decode(id_pub))
                    alice_eph = X25519PublicKey.from_public_bytes(base64.b64decode(eph_pub))
                    self.x3dh(alice_id, alice_eph)
                    print("Root key established.")
                else:
                    parts = msg.split()
                    print("Raw Message:", msg)  # Print the full message for inspection
                    print("Parts:", parts)  # Print the parts after splitting

                    # Ensure there are exactly three parts (msg, nonce, ciphertext)
                    if len(parts) != 3:
                        print("Error: Invalid message format.")
                        continue

                    # Decode base64 encoded nonce and ciphertext
                    nonce = base64.b64decode(parts[1])
                    ciphertext = base64.b64decode(parts[2])

                    print("Decoded Nonce:", nonce)
                    print("Decoded Ciphertext:", ciphertext)

                    # Now attempt to decrypt
                    try:
                        decrypted_msg = self.decrypt(nonce, ciphertext)
                        print("Decrypted:", decrypted_msg.decode())
                    except Exception as e:
                        print(f"Error during decryption: {e}")

if __name__ == "__main__":
    Bob().listen()
