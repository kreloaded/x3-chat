import socket
import base64
import time
import os
import dotenv
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


class Alice:
    """
    Implements the Alice client for secure communication using X3DH and Double Ratchet-like symmetric ratcheting.
    """

    def __init__(self):
        """
        Initializes identity and ephemeral keys, and prepares placeholders for root and chain keys.
        """
        self.id_priv = X25519PrivateKey.generate()
        self.id_pub = self.id_priv.public_key()
        self.eph_priv = X25519PrivateKey.generate()
        self.eph_pub = self.eph_priv.public_key()
        self.root_key = None
        self.send_chain = None
        self.recv_chain = None
        # DH Ratchet state
        self.ratchet_priv = None
        self.ratchet_pub = None
        self.remote_ratchet_pub = None
        self.role = "initiator"

    def get_bob_keys(self):
        """
        Requests Bob's identity and prekey public keys from the server.

        Returns:
            Tuple[X25519PublicKey, X25519PublicKey]: (Bob's identity key, Bob's prekey) or (None, None) on failure.
        """
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
                print("Bob's keys not found. Exiting.")
                return None, None

    def x3dh(self, bob_id_pub, bob_prekey_pub):
        """
        Establishes a root key using the X3DH protocol with Bob's keys.

        Args:
            bob_id_pub (X25519PublicKey): Bob's identity public key.
            bob_prekey_pub (X25519PublicKey): Bob's prekey public key.
        """
        dh1 = self.id_priv.exchange(bob_id_pub)
        dh2 = self.id_priv.exchange(bob_prekey_pub)
        dh3 = self.eph_priv.exchange(bob_id_pub)
        shared_secret = dh1 + dh2 + dh3
        hkdf = HKDF(hashes.SHA256(), 32, None, b"x3dh root key")
        self.root_key = hkdf.derive(shared_secret)
        root_hkdf = HKDF(hashes.SHA256(), 64, None, b"root chain")
        root_material = root_hkdf.derive(self.root_key)
        self.send_chain, self.recv_chain = root_material[:32], root_material[32:]
        # Initialize DH Ratchet after X3DH
        self.ratchet_priv = X25519PrivateKey.generate()
        self.ratchet_pub = self.ratchet_priv.public_key()

    def step_chain(self, chain, info):
        """
        Advances a symmetric key chain and returns a message key and new chain key.

        Args:
            chain (bytes): Current chain key.
            info (bytes): Context string for HKDF.

        Returns:
            Tuple[bytes, bytes]: (message_key, next_chain_key)
        """
        hkdf = HKDF(hashes.SHA256(), 64, None, info)
        material = hkdf.derive(chain)
        return material[:32], material[32:]

    def encrypt(self, plaintext):
        """
        Encrypts a message using AES-GCM and the send chain key.

        Args:
            plaintext (str): The message to encrypt.

        Returns:
            Tuple[bytes, bytes]: (nonce, ciphertext)
        """
        msg_key, self.send_chain = self.step_chain(self.send_chain, b"send_chain")
        nonce = os.urandom(12)
        ciphertext = AESGCM(msg_key).encrypt(nonce, plaintext.encode(), None)
        return nonce, ciphertext

    def decrypt(self, nonce, ciphertext):
        """
        Decrypts a message using AES-GCM and the receive chain key.

        Args:
            nonce (bytes): Nonce used during encryption.
            ciphertext (bytes): Encrypted message.

        Returns:
            bytes: Decrypted message content.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails.
            Exception: For all other decryption issues.
        """
        msg_key, self.recv_chain = self.step_chain(
            self.recv_chain, b"send_chain"
        )  # Use "send_chain"
        try:
            return AESGCM(msg_key).decrypt(nonce, ciphertext, None)
        except cryptography.exceptions.InvalidTag:
            print("Decryption failed: Invalid tag")
            raise

    def perform_dh_ratchet(self, new_ratchet_pub):
        # Generate new ratchet key pair
        new_self_ratchet_priv = X25519PrivateKey.generate()
        new_self_ratchet_pub = new_self_ratchet_priv.public_key()

        # Compute DH
        dh_shared = new_self_ratchet_priv.exchange(new_ratchet_pub)

        # Update root key with combined existing root + new DH
        hkdf = HKDF(hashes.SHA256(), 32, None, b"dh_ratchet")
        new_root = hkdf.derive(self.root_key + dh_shared)

        # Derive new chains
        root_hkdf = HKDF(hashes.SHA256(), 64, None, b"root_chain_update")
        root_material = root_hkdf.derive(new_root)
        self.send_chain, self.recv_chain = root_material[:32], root_material[32:]

        # Update state
        self.root_key = new_root
        self.remote_ratchet_pub = new_ratchet_pub
        self.ratchet_priv = new_self_ratchet_priv
        self.ratchet_pub = new_self_ratchet_pub

    def send_message(self, msg):
        ratchet_pub_b64 = base64.b64encode(self.ratchet_pub.public_bytes_raw()).decode()
        nonce, ciphertext = self.encrypt(msg)
        encoded_nonce = base64.b64encode(nonce).decode()
        encoded_ciphertext = base64.b64encode(ciphertext).decode()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(
                f"SEND Alice Bob MSG {ratchet_pub_b64} {encoded_nonce} {encoded_ciphertext}".encode()
            )
            s.recv(1024)

    def listen_for_messages(self):
        """
        Continuously polls the server for new messages for Alice and attempts to decrypt them.
        """
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.send(b"RECEIVE Alice")
                data = s.recv(4096).decode()
                if data == "NO_MESSAGES":
                    time.sleep(0.5)
                    continue
                if data.startswith("MSG"):
                    _, ratchet_pub_b64, nonce_b64, ciphertext_b64 = data.split()
                    ratchet_pub = X25519PublicKey.from_public_bytes(
                        base64.b64decode(ratchet_pub_b64)
                    )
                    nonce = base64.b64decode(nonce_b64)
                    ciphertext = base64.b64decode(ciphertext_b64)

                    # Check if ratchet key changed
                    ratchet_changed = ratchet_pub != self.remote_ratchet_pub

                    try:
                        # Decrypt with current chains
                        decrypted = self.decrypt(nonce, ciphertext)
                        print(f"\nBob: {decrypted.decode()}")

                        # Update DH Ratchet after successful decryption
                        if ratchet_changed:
                            self.perform_dh_ratchet(ratchet_pub)
                    except Exception as e:
                        print(f"\nFailed to decrypt: {e}")

    def start(self):
        """
        Starts the Alice client:
        - Retrieves Bob's keys.
        - Performs X3DH to derive shared root key.
        - Sends Alice's identity and ephemeral keys to Bob.
        - Begins listening for incoming messages.
        - Sends an initial greeting and enters interactive messaging loop.
        """
        time.sleep(1)
        bob_id_pub, bob_prekey_pub = self.get_bob_keys()
        if not bob_id_pub or not bob_prekey_pub:
            return
        self.x3dh(bob_id_pub, bob_prekey_pub)
        print("Root key established")

        id_pub_b64 = base64.b64encode(self.id_pub.public_bytes_raw()).decode()
        eph_pub_b64 = base64.b64encode(self.eph_pub.public_bytes_raw()).decode()
        ratchet_pub_b64 = base64.b64encode(
            self.ratchet_pub.public_bytes_raw()
        ).decode()  # Added
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(
                f"SEND Alice Bob ALICE_KEYS {id_pub_b64} {eph_pub_b64} {ratchet_pub_b64}".encode()
            )  # Include ratchet key
            s.recv(1024)

        time.sleep(1)
        threading.Thread(target=self.listen_for_messages, daemon=True).start()

        self.send_message("Hello Bobby! 🕊️")
        print("Initial message sent")

        while True:
            message = input("You (Alice): ")
            self.send_message(message)


if __name__ == "__main__":
    Alice().start()
