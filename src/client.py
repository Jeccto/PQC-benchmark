import socket
import struct
import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

KEM_NAME = "ML-KEM-768"
SERVER_HOST = "127.0.0.1"
PORT = 5000

def raw_public_bytes(pubkey):
    return pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)

def derive_key(ss_classical, ss_pq, transcript):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"hybrid-demo-v1" + transcript,
    ).derive(ss_classical + ss_pq)

def send_blob(conn, data):
    conn.sendall(struct.pack(">I", len(data)) + data)

def recv_blob(conn):
    length_bytes = conn.recv(4)
    length = struct.unpack(">I", length_bytes)[0]
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        data += chunk
    return data

def run_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, PORT))
    print(f"Connected to server at {SERVER_HOST}:{PORT}")

    server_x_pub_bytes = recv_blob(sock)
    server_kem_pub_bytes = recv_blob(sock)

    server_x_pub = X25519PublicKey.from_public_bytes(server_x_pub_bytes)

    x_priv = X25519PrivateKey.generate()
    x_pub_bytes = raw_public_bytes(x_priv.public_key())
    ss_x = x_priv.exchange(server_x_pub)

    kem = oqs.KeyEncapsulation(KEM_NAME)
    kem_ciphertext, ss_pq = kem.encap_secret(server_kem_pub_bytes)

    send_blob(sock, x_pub_bytes)
    send_blob(sock, kem_ciphertext)

    transcript = x_pub_bytes + server_x_pub_bytes + server_kem_pub_bytes + kem_ciphertext
    session_key = derive_key(ss_x, ss_pq, transcript)
    print(f"Session key: {session_key.hex()}")

    nonce = os.urandom(12)
    plaintext = b"hello from the post-quantum era"
    ciphertext_msg = AESGCM(session_key).encrypt(nonce, plaintext, None)
    send_blob(sock, nonce + ciphertext_msg)

    print("Encrypted message sent.")
    sock.close()
    kem.free()

if __name__ == "__main__":
    run_client()