import socket
import struct
import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KEM_NAME = "ML-KEM-768"
HOST = "0.0.0.0" #listen on all available interfaces
PORT = 5000 #arbitrary

### NEW: load the server's long-term identity key at startup
with open("server_identity_private.pem", "rb") as f:
    IDENTITY_PRIV = load_pem_private_key(f.read(), password=None)

def raw_public_bytes(pubkey): #X25519 keys need to be transformed into bytes explicitly to transfer over the socket
    return pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw) #what is this

#===========================================================================================================

#we use hkdf to covert the single shared secret produced by bob alongside the cipher into multiple secure keys
#why: because traditional key exchange methods (like Diffie-Hellman) rely on mathematical problems that quantum computers can easily solve.

def derive_key(ss_x, ss_pq, transcript):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32, #bytes
        salt=None, #HKDF's salt adds extra randomness per-use; None means it defaults to a string of zero bytes
        # acceptable for this demo since our inputs (the two shared secrets) are already high-entropy random values
        info=b"hybrid-demo-v1" + transcript, #b"hybrid-demo-v1" is a fixed domain-separation label (so this key can never collide with a key derived for some other protocol using the same HKDF call)
        #and appending transcript binds the key to this exact handshake's public data.
    ).derive(ss_x + ss_pq)
#============================================================================================================

def send_blob(conn, data):
    conn.sendall(struct.pack(">I", len(data)) + data) #send all

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

    ### NEW: sign the ephemeral handshake keys with the server's long-term identity key.
    ### This is what lets the client verify "these keys really came from the real server,"
    ### not just "these keys are internally consistent" (which a fake server could fake too).
    signed_payload = x_pub_bytes + kem_pub_bytes
    signature = IDENTITY_PRIV.sign(signed_payload)

    sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM) #AD_INET: ipv4 , SOCK_STREAM: TCP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(1)
    print(f"Server listening on {HOST}:{PORT}")

    conn, addr = sock.accept()
    print(f"Connection from {addr}")

    send_blob(conn, x_pub_bytes)
    send_blob(conn, kem_pub_bytes)
    send_blob(conn, signature)  ### NEW: send the signature as a third blob

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

    try:
        plaintext = AESGCM(session_key).decrypt(nonce, ciphertext_msg, None)
        print(f"Decrypted message from client: {plaintext.decode()}")
    except InvalidTag:
        print(f"TAMPER DETECTED from {addr}: ciphertext/nonce failed authentication — message rejected.")

    conn.close()
    sock.close()
    kem.free()

if __name__ == "__main__":
    run_server()