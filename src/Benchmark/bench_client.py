import socket
import struct
import time
import sys
import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import os

KEM_NAME = "ML-KEM-768"
PORT = 5000

with open("server_identity_public.pem", "rb") as f:
    SERVER_IDENTITY_PUB = load_pem_public_key(f.read())

def raw_public_bytes(pubkey):
    return pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)

def derive_key(ss_x, ss_pq, transcript):
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"hybrid-demo-v1" + transcript,
    ).derive(ss_x + ss_pq)

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

def one_handshake(host):
    t_start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, PORT))
    t_connected = time.perf_counter()

    server_x_pub_bytes = recv_blob(sock)
    server_kem_pub_bytes = recv_blob(sock)
    signature = recv_blob(sock)
    SERVER_IDENTITY_PUB.verify(signature, server_x_pub_bytes + server_kem_pub_bytes)
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

    nonce = os.urandom(12)
    ciphertext_msg = AESGCM(session_key).encrypt(nonce, b"benchmark message", None)
    send_blob(sock, nonce + ciphertext_msg)
    t_done = time.perf_counter()

    sock.close()
    kem.free()
    return {
        "connect_ms": (t_connected - t_start) * 1000,
        "handshake_ms": (t_done - t_connected) * 1000,
        "total_ms": (t_done - t_start) * 1000,
    }

def run_bench(host, n):
    results = []
    for i in range(n):
        try:
            r = one_handshake(host)
            results.append(r)
            print(f"Run {i+1}/{n}: total={r['total_ms']:.2f} ms")
        except Exception as e:
            print(f"Run {i+1}/{n} failed: {e}")

    totals = [r["total_ms"] for r in results]
    if totals:
        print("\n--- Client summary ---")
        print(f"Successful runs: {len(totals)}/{n}")
        print(f"Min:  {min(totals):.2f} ms")
        print(f"Max:  {max(totals):.2f} ms")
        print(f"Avg:  {sum(totals)/len(totals):.2f} ms")

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    run_bench(host, n)