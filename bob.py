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
    """
    Represents Bob in a secure messaging protocol using the X3DH and Double Ratchet algorithms.
    """

    def __init__(self):
        """
        Initializes Bob's identity and prekey pairs and sets up placeholders for cryptographic state.
        """
        self.id_priv = X25519PrivateKey.generate()
        self.id_pub = self.id_priv.public_key()
        self.prekey_priv = X25519PrivateKey.generate()
        self.prekey_pub = self.prekey_priv.public_key()
        self.root_key = None
        self.send_chain = None
        self.recv_chain = None
        # DH Ratchet state
        self.ratchet_priv = None
        self.ratchet_pub = None
        self.remote_ratchet_pub = None
        self.role = "responder"  # Add role attribute

    def register(self):
        """
        Registers Bob's identity and prekey public keys with the server.
        """
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
        """
        Performs the X3DH key agreement protocol with Alice's identity and ephemeral keys.

        Args:
            alice_id_pub (X25519PublicKey): Alice's identity public key.
            alice_eph_pub (X25519PublicKey): Alice's ephemeral public key.
        """
        dh1 = self.id_priv.exchange(alice_id_pub)
        dh2 = self.prekey_priv.exchange(alice_id_pub)
        dh3 = self.id_priv.exchange(alice_eph_pub)
        shared_secret = dh1 + dh2 + dh3
        hkdf = HKDF(hashes.SHA256(), 32, None, b"x3dh root key")
        self.root_key = hkdf.derive(shared_secret)
        root_hkdf = HKDF(hashes.SHA256(), 64, None, b"root chain")
        root_material = root_hkdf.derive(self.root_key)
        self.recv_chain, self.send_chain = root_material[:32], root_material[32:]
        # Initialize DH Ratchet after X3DH
        self.ratchet_priv = X25519PrivateKey.generate()
        self.ratchet_pub = self.ratchet_priv.public_key()

    def step_chain(self, chain, info):
        """
        Advances the key chain using HKDF.

        Args:
            chain (bytes): The current chain key.
            info (bytes): Context-specific info used in HKDF.

        Returns:
            tuple: A tuple containing (message_key, next_chain_key).
        """
        hkdf = HKDF(hashes.SHA256(), 64, None, info)
        material = hkdf.derive(chain)
        return material[:32], material[32:]

    def encrypt(self, plaintext):
        """
        Encrypts a plaintext message using the current send chain.

        Args:
            plaintext (str): The message to encrypt.

        Returns:
            tuple: A tuple containing (nonce, ciphertext).
        """
        msg_key, self.send_chain = self.step_chain(self.send_chain, b"send_chain")
        nonce = os.urandom(12)
        ciphertext = AESGCM(msg_key).encrypt(nonce, plaintext.encode(), None)
        return nonce, ciphertext

    def decrypt(self, nonce, ciphertext):
        """
        Decrypts a message using the current receive chain.

        Args:
            nonce (bytes): A 12-byte nonce used during encryption.
            ciphertext (bytes): The encrypted message.

        Returns:
            bytes: The decrypted message.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails.
            Exception: For any other error during decryption.
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
        self.recv_chain, self.send_chain = root_material[:32], root_material[32:]

        # Update state
        self.root_key = new_root
        self.remote_ratchet_pub = new_ratchet_pub
        self.ratchet_priv = new_self_ratchet_priv
        self.ratchet_pub = new_self_ratchet_pub

    def send_message(self, msg):
        """
        Encrypts and sends a message to Alice via the server.

        Args:
            msg (str): The plaintext message to send.
        """
        ratchet_pub_b64 = base64.b64encode(self.ratchet_pub.public_bytes_raw()).decode()
        nonce, ciphertext = self.encrypt(msg)
        encoded_nonce = base64.b64encode(nonce).decode()
        encoded_ciphertext = base64.b64encode(ciphertext).decode()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(
                f"SEND Bob Alice MSG {ratchet_pub_b64} {encoded_nonce} {encoded_ciphertext}".encode()
            )
            s.recv(1024)

    def listen(self):
        """
        Starts Bob's listening loop: registers with the server, listens for messages,
        performs X3DH handshake if needed, and allows user to send messages interactively.
        """
        self.register()
        print("Bob is ready")

        def send_input():
            while True:
                message = input("You (Bob): ")
                self.send_message(message)

        threading.Thread(target=send_input, daemon=True).start()

        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.send(b"RECEIVE Bob")
                data = s.recv(4096).decode()
                if data == "NO_MESSAGES":
                    time.sleep(0.5)
                    continue
                elif data.startswith("ALICE_KEYS"):
                    _, id_pub, eph_pub, ratchet_pub_b64 = (
                        data.split()
                    )  # Added ratchet_pub
                    alice_id = X25519PublicKey.from_public_bytes(
                        base64.b64decode(id_pub)
                    )
                    alice_eph = X25519PublicKey.from_public_bytes(
                        base64.b64decode(eph_pub)
                    )
                    self.x3dh(alice_id, alice_eph)
                    # Set initial remote ratchet key from ALICE_KEYS
                    self.remote_ratchet_pub = X25519PublicKey.from_public_bytes(
                        base64.b64decode(ratchet_pub_b64)
                    )  # Added
                    print("Root key established")
                elif data.startswith("MSG"):
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
                        print(f"\nAlice: {decrypted.decode()}")

                        # Update DH Ratchet after successful decryption
                        if ratchet_changed:
                            self.perform_dh_ratchet(ratchet_pub)
                    except Exception as e:
                        print(f"\nFailed to decrypt: {e}")


if __name__ == "__main__":
    Bob().listen()
