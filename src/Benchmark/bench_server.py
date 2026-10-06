import socket
import struct
import time
import json
import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KEM_NAME = "ML-KEM-768"
HOST = "0.0.0.0"
PORT = 5000

with open("server_identity_private.pem", "rb") as f:
    IDENTITY_PRIV = load_pem_private_key(f.read(), password=None)

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

def handle_client(conn, addr):
    t0 = time.perf_counter()
    bytes_sent = 0
    bytes_received = 0

    x_priv = X25519PrivateKey.generate()
    x_pub_bytes = raw_public_bytes(x_priv.public_key())
    kem = oqs.KeyEncapsulation(KEM_NAME)
    kem_pub_bytes = kem.generate_keypair()
    signature = IDENTITY_PRIV.sign(x_pub_bytes + kem_pub_bytes)
    t1 = time.perf_counter()  # key generation + signing done

    for blob in (x_pub_bytes, kem_pub_bytes, signature):
        send_blob(conn, blob)
        bytes_sent += 4 + len(blob)
    t2 = time.perf_counter()  # server's blobs sent

    client_x_pub_bytes = recv_blob(conn)
    client_kem_ciphertext = recv_blob(conn)
    bytes_received += 8 + len(client_x_pub_bytes) + len(client_kem_ciphertext)
    t3 = time.perf_counter()  # client's blobs received

    client_x_pub = X25519PublicKey.from_public_bytes(client_x_pub_bytes)
    ss_x = x_priv.exchange(client_x_pub)
    ss_pq = kem.decap_secret(client_kem_ciphertext)
    transcript = client_x_pub_bytes + x_pub_bytes + kem_pub_bytes + client_kem_ciphertext
    session_key = derive_key(ss_x, ss_pq, transcript)
    t4 = time.perf_counter()  # session key derived

    encrypted_msg = recv_blob(conn)
    bytes_received += 4 + len(encrypted_msg)
    nonce, ciphertext_msg = encrypted_msg[:12], encrypted_msg[12:]
    try:
        plaintext = AESGCM(session_key).decrypt(nonce, ciphertext_msg, None)
        ok = True
    except InvalidTag:
        ok = False
    t5 = time.perf_counter()  # message decrypted

    conn.close()
    kem.free()

    record = {
        "addr": str(addr),
        "keygen_sign_ms": (t1 - t0) * 1000,
        "send_server_blobs_ms": (t2 - t1) * 1000,
        "recv_client_blobs_ms": (t3 - t2) * 1000,
        "key_derivation_ms": (t4 - t3) * 1000,
        "recv_decrypt_ms": (t5 - t4) * 1000,
        "total_ms": (t5 - t0) * 1000,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "message_ok": ok,
    }
    print(json.dumps(record))
    return record

def run_server(n_connections):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"Benchmark server listening on {HOST}:{PORT}, expecting {n_connections} connections")

    records = []
    for _ in range(n_connections):
        conn, addr = sock.accept()
        try:
            records.append(handle_client(conn, addr))
        except Exception as e:
            print(f"Error: {e}")
            conn.close()
    sock.close()

    totals = [r["total_ms"] for r in records]
    print("\n--- Summary ---")
    print(f"Runs: {len(totals)}")
    print(f"Min:  {min(totals):.2f} ms")
    print(f"Max:  {max(totals):.2f} ms")
    print(f"Avg:  {sum(totals)/len(totals):.2f} ms")
    if records:
        print(f"Bytes sent/received per handshake: {records[0]['bytes_sent']} / {records[0]['bytes_received']}")

    with open("bench_results.json", "w") as f:
        json.dump(records, f, indent=2)
    print("Full results written to bench_results.json")

if __name__ == "__main__":
    import sys
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    run_server(n)