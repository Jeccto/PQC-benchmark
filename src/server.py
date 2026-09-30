import socket
import struct
import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEM_NAME = "ML-KEM-768"
HOST = "0.0.0.0" #listen on all available interfaces
PORT = 5000 #arbitrary

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
    ).derive(ss_x + ss_pq) #.derive(ss_classical + ss_pq) — the actual input keying material: the two raw shared secrets concatenated together (X25519's first, ML-KEM's second — order just needs to be consistent on both sides).
    #! derive_key() is the step that turns "two independent secrets plus a record of what was exchanged" into "one trustworthy AES key that's cryptographically proof against tampering"
    #! it's the glue that makes the hybrid design, and the whole handshake's integrity, actually mean something.
    #! If this function didn't exist and you just used, say, ss_classical alone as the key: you'd lose all the post-quantum protection (an attacker who broke only the classical math would get the real key). If you used ss_classical + ss_pq directly as the key without HKDF: you'd lose the tamper-binding property, and risk using non-uniform bytes as a key. The function's purpose is closing both of those gaps in one step.
#============================================================================================================

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

# Picture you're sending letters through a mail slot that has no envelopes — just one long continuous stream of paper coming out the other side, all glued together. The person on the other end has no way to tell where one letter ends and the next begins, unless you tell them somehow.
#
# So here's the trick: before you shove a letter through the slot, you first write a little sticky note that says "the next letter is exactly 47 words long" and push that through first. The person on the other end reads the sticky note, sees "47," and then just keeps grabbing words one at a time until they've collected exactly 47 — then they know: okay, that's the whole letter, stop here.
#
# That's it. That's the whole trick.
#
# send_blob = write the sticky note (how many bytes are coming), push it through, then push the actual letter through right after.
# recv_blob = read the sticky note first to find out the number, then keep grabbing bytes — even if they dribble in a few at a time — until you've collected exactly that many. Then stop, you're done, that's one complete "blob."
#
# Why bother with the sticky note at all? Because the mail slot (TCP) doesn't respect your letter boundaries — it might squish two letters together, or chop one letter in half and make you wait for the rest. Without the sticky note telling you the length upfront, you'd have no idea when to stop reading.

#============================================================================================================

def run_server():
    x_priv = X25519PrivateKey.generate()
    x_pub = x_priv.public_key()
    x_pub_bytes = raw_public_bytes(x_pub)

    kem = oqs.KeyEncapsulation(KEM_NAME)
    kem_pub_bytes = kem.generate_keypair()

    sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM) #AD_INET: ipv4 , SOCK_STREAM: TCP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #Without this, restarting the server script quickly after stopping it often fails with "address already in use"
    # the OS holds the port briefly after a socket closes. This flag lets you rebind immediately, purely a development convenience.
    sock.bind((HOST, PORT))
    sock.listen(1) # 1: number of pending connections (1 is largely enough for the test)
    print(f"Server listening on {HOST}:{PORT}")

    conn, addr = sock.accept() # conn: new connection object , addr: client address (the socket is still listening)
    print(f"Connection from {addr}")

    send_blob(conn, x_pub_bytes)
    send_blob(conn, kem_pub_bytes)

    client_x_pub_bytes = recv_blob(conn)
    client_kem_ciphertext = recv_blob(conn)

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey #import done here to save resources incase of no connections
    client_x_pub = X25519PublicKey.from_public_bytes(client_x_pub_bytes) #reverse of raw_public_bytes(bytes)

    # ss:shared secret

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