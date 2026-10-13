import socket
import struct
import hashlib
import hmac
import threading
import tkinter as tk
from collections import namedtuple
from tkinter import scrolledtext, messagebox
import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KEM_NAME = "ML-KEM-768"
HOST = "0.0.0.0" #listen on all available interfaces
PORT = 5000 #arbitrary

PROTOCOL_LABEL = b"pq-hybrid-v2"   # domain-separation label mixed into every hash / HKDF use
MAX_BLOB = 64 * 1024               # reject any length-prefixed value bigger than 64 KB (DoS guard)
SOCKET_TIMEOUT = 10.0              # seconds; a peer that goes silent is dropped instead of hanging us

### NEW: load the server's long-term identity key at startup
with open("server_identity_private.pem", "rb") as f:
    IDENTITY_PRIV = load_pem_private_key(f.read(), password=None)

# the full direction-separated key schedule (see derive_keys)
SessionKeys = namedtuple("SessionKeys", "c2s_key s2c_key c2s_iv s2c_iv client_finished server_finished")

class ConnectionClosed(Exception):
    """Peer closed the connection cleanly (recv returned 0 bytes)."""

class ProtocolError(Exception):
    """Malformed framing, or a value that exceeds the size cap."""

def raw_public_bytes(pubkey): #X25519 keys need to be transformed into bytes explicitly to transfer over the socket
    return pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)

#============================================================================================================
# HARDENED FRAMING
#============================================================================================================
# The old recv_blob had three bugs: it assumed recv(4) returned four bytes, it looped
# forever if the peer disconnected mid-message (recv() returns b"" and len never grows),
# and it trusted an attacker-supplied length with no upper bound. recv_exact fixes the
# first two; the MAX_BLOB check fixes the third (a peer can no longer announce a 4 GB
# message and make us allocate it). Timeouts are set on the socket itself.

def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk: # peer closed mid-message -> stop, do NOT spin forever
            raise ConnectionClosed()
        data += chunk
    return data

def recv_blob(conn):
    length = struct.unpack(">I", recv_exact(conn, 4))[0]
    if length > MAX_BLOB:
        raise ProtocolError(f"declared blob of {length} bytes exceeds the {MAX_BLOB}-byte cap")
    return recv_exact(conn, length)

def send_blob(conn, data):
    if len(data) > MAX_BLOB:
        raise ProtocolError(f"refusing to send a {len(data)}-byte blob (cap {MAX_BLOB})")
    conn.sendall(struct.pack(">I", len(data)) + data)

#============================================================================================================
# TRANSCRIPT + KEY SCHEDULE
#============================================================================================================

def transcript_hash(*parts):
    # Hash the running transcript, always prefixed with the protocol label so a digest
    # from this protocol can never be confused with one from any other context.
    h = hashlib.sha256()
    h.update(PROTOCOL_LABEL)
    for part in parts:
        h.update(part)
    return h.digest()

def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

def derive_keys(ss_x, ss_pq, th):
    # Derive an INDEPENDENT key for every purpose from the same two shared secrets.
    # HKDF guarantees the outputs are unrelated, so leaking one key says nothing about
    # the others (a single AES key can't be safely reused as an HMAC key, etc.).
    # salt=th binds every derived key to this exact handshake; the label selects which key.
    def derive(label, length):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length, #bytes
            salt=th,                              # transcript hash binds the keys to this handshake
            info=PROTOCOL_LABEL + b" " + label,   # a distinct label => an independent key
        ).derive(ss_x + ss_pq)
    return SessionKeys(
        c2s_key=derive(b"c2s key", 32),          # client -> server record key
        s2c_key=derive(b"s2c key", 32),          # server -> client record key
        c2s_iv=derive(b"c2s iv", 12),            # per-direction nonce base
        s2c_iv=derive(b"s2c iv", 12),
        client_finished=derive(b"client finished", 32),  # key for the client's Finished MAC
        server_finished=derive(b"server finished", 32),  # key for the server's Finished MAC
    )

def nonce_for(iv, seq):
    # TLS-1.3-style record nonce: XOR the 64-bit record counter into the IV. The nonce is
    # never transmitted; both sides count independently. Because the receiver expects a
    # strictly increasing counter, a replayed or reordered record decrypts under the wrong
    # nonce and fails authentication.
    return bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))

def record_encrypt(key, iv, seq, plaintext):
    return AESGCM(key).encrypt(nonce_for(iv, seq), plaintext, None)

def record_decrypt(key, iv, seq, ciphertext):
    return AESGCM(key).decrypt(nonce_for(iv, seq), ciphertext, None)

#============================================================================================================

def run_server(port, log):
    try:
        x_priv = X25519PrivateKey.generate()
        x_pub = x_priv.public_key()
        x_pub_bytes = raw_public_bytes(x_pub)

        kem = oqs.KeyEncapsulation(KEM_NAME)
        kem_pub_bytes = kem.generate_keypair()

        ### NEW: sign a hash of the server's flight (the entire transcript at this point) with
        ### the long-term identity key. Signing a hash of the transcript — rather than the raw
        ### bytes — with a context string is exactly the TLS 1.3 CertificateVerify construction:
        ### it proves the keys are the server's AND binds the signature to this handshake.
        server_flight = x_pub_bytes + kem_pub_bytes
        signature = IDENTITY_PRIV.sign(PROTOCOL_LABEL + b" server-handshake" + transcript_hash(server_flight))

        sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM) #AD_INET: ipv4 , SOCK_STREAM: TCP
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, port))
        sock.listen(1)
        log(f"Server listening on {HOST}:{port}")

        conn, addr = sock.accept()
        conn.settimeout(SOCKET_TIMEOUT) # a silent peer can no longer hang the server
        log(f"Connection from {addr}")

        send_blob(conn, x_pub_bytes)
        send_blob(conn, kem_pub_bytes)
        send_blob(conn, signature)  ### send the signature as a third blob

        client_x_pub_bytes = recv_blob(conn)
        client_kem_ciphertext = recv_blob(conn)
        client_finished = recv_blob(conn)   ### NEW: the client's Finished (key confirmation)

        client_x_pub = X25519PublicKey.from_public_bytes(client_x_pub_bytes)

        ss_x = x_priv.exchange(client_x_pub)
        ss_pq = kem.decap_secret(client_kem_ciphertext)

        # The transcript is EVERYTHING both sides exchanged, in a fixed order, including the
        # signature. Both sides build the identical bytes, so both derive identical keys.
        transcript = server_flight + signature + client_x_pub_bytes + client_kem_ciphertext
        th = transcript_hash(transcript)
        keys = derive_keys(ss_x, ss_pq, th)

        #================================================================================================
        # KEY CONFIRMATION (the "Finished" message)
        # The client sends HMAC(client_finished_key, "client finished" || transcript_hash). We can
        # only recompute it if we derived the same session secret from the same transcript, so a
        # valid MAC proves the client really holds the key — no more waiting for the app message
        # to "happen to decrypt". It also binds the client's half of the exchange, which the
        # signature (sent before the client spoke) could not.
        #================================================================================================
        expected_client_finished = hmac_sha256(keys.client_finished, b"client finished" + th)
        if not hmac.compare_digest(expected_client_finished, client_finished):
            log("KEY CONFIRMATION FAILED: client Finished did not verify — aborting (MITM or key mismatch).")
            conn.close(); sock.close(); kem.free()
            return
        log("Client key confirmation verified.")

        # The server's own Finished covers the transcript PLUS the client's Finished, so its
        # MAC is tied to everything that came before it.
        th2 = transcript_hash(transcript + client_finished)
        server_finished = hmac_sha256(keys.server_finished, b"server finished" + th2)
        send_blob(conn, server_finished)
        log("Server key confirmation sent.")

        #================================================================================================
        # RECORD LAYER
        # Application data flows as independent records, each encrypted under a direction-specific
        # key with an implicit counter nonce. We loop, so many messages are supported; the counter
        # advances per record, which is what gives replay/reordering detection within the session.
        #================================================================================================
        c2s_seq = 0
        s2c_seq = 0
        while True:
            try:
                ciphertext_msg = recv_blob(conn)
            except ConnectionClosed:
                log("Client closed the connection.")
                break
            except socket.timeout:
                log("Timed out waiting for the client.")
                break

            try:
                plaintext = record_decrypt(keys.c2s_key, keys.c2s_iv, c2s_seq, ciphertext_msg)
            except InvalidTag:
                log(f"REJECTED record from {addr}: failed authentication (tampering, replay, or reordering).")
                break   # in TLS this is a fatal alert; we end the session
            c2s_seq += 1
            log(f"Message {c2s_seq} from client: {plaintext.decode(errors='replace')}")

            # Acknowledge on the other direction, proving the reverse key works too.
            ack = f"server received {len(plaintext)} bytes".encode()
            send_blob(conn, record_encrypt(keys.s2c_key, keys.s2c_iv, s2c_seq, ack))
            s2c_seq += 1

        conn.close()
        sock.close()
        kem.free()
    except Exception as e:
        log(f"Error: {e}")
        show_error("Server failed", str(e))

def show_error(title, message):
    # messagebox needs a display; in headless mode (e.g. Docker) just skip the dialog.
    try:
        messagebox.showerror(title, message)
    except tk.TclError:
        pass

class ServerApp:
    def __init__(self, root):
        root.title("PQ Hybrid Server")
        root.geometry("500x460")

        tk.Label(root, text="Listen port:").pack(anchor="w", padx=10, pady=(10, 0))
        self.port_entry = tk.Entry(root)
        self.port_entry.insert(0, str(PORT))
        self.port_entry.pack(fill="x", padx=10)

        self.start_btn = tk.Button(root, text="Start Server (accept one client)", command=self.on_start)
        self.start_btn.pack(pady=10)

        tk.Label(root, text="Log:").pack(anchor="w", padx=10)
        self.log_box = scrolledtext.ScrolledText(root, height=15, state="disabled")
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def log(self, text):
        self.log_box.config(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def on_start(self):
        port = self.port_entry.get().strip()
        if not port:
            messagebox.showwarning("Missing input", "Enter a port.")
            return
        try:
            port = int(port)
        except ValueError:
            messagebox.showwarning("Invalid port", "Port must be a number.")
            return
        self.start_btn.config(state="disabled")
        threading.Thread(target=self._server_thread, args=(port,), daemon=True).start()

    def _server_thread(self, port):
        run_server(port, self.log)
        self.start_btn.config(state="normal")

if __name__ == "__main__":
    try:
        root = tk.Tk()
    except tk.TclError:
        # no display available (e.g. inside the Docker container) — fall back to headless CLI mode
        print(f"No display found — starting headless server on {HOST}:{PORT}")
        run_server(PORT, print)
    else:
        app = ServerApp(root)
        root.mainloop()
