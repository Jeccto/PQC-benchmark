import socket
import struct
import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEM_NAME = "ML-KEM-768"
HOST = "0.0.0.0"
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

def run_server():
    x_priv = X25519PrivateKey.generate()
    x_pub = x_priv.public_key()
    x_pub_bytes = raw_public_bytes(x_pub)

    kem = oqs.KeyEncapsulation(KEM_NAME)
    kem_pub_bytes = kem.generate_keypair()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(1)
    print(f"Server listening on {HOST}:{PORT}")

    conn, addr = sock.accept()
    print(f"Connection from {addr}")

    send_blob(conn, x_pub_bytes)
    send_blob(conn, kem_pub_bytes)

    client_x_pub_bytes = recv_blob(conn)
    client_kem_ciphertext = recv_blob(conn)

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    client_x_pub = X25519PublicKey.from_public_bytes(client_x_pub_bytes)

    ss_x = x_priv.exchange(client_x_pub)
    ss_pq = kem.decap_secret(client_kem_ciphertext)

    transcript = client_x_pub_bytes + x_pub_bytes + kem_pub_bytes + client_kem_ciphertext
    session_key = derive_key(ss_x, ss_pq, transcript)
    print(f"Session key: {session_key.hex()}")

    encrypted_msg = recv_blob(conn)
    nonce = encrypted_msg[:12]
    ciphertext_msg = encrypted_msg[12:]
    plaintext = AESGCM(session_key).decrypt(nonce, ciphertext_msg, None)
    print(f"Decrypted message from client: {plaintext.decode()}")

    conn.close()
    sock.close()
    kem.free()

if __name__ == "__main__":
    run_server()