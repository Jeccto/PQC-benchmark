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
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

KEM_NAME = "ML-KEM-768"
PORT = 5000

PROTOCOL_LABEL = b"pq-hybrid-v2"   # must match the server exactly
MAX_BLOB = 64 * 1024               # reject oversized length prefixes (DoS guard)
SOCKET_TIMEOUT = 10.0              # seconds without progress => give up

### NEW: the server's public identity key, obtained out-of-band (copied from the server
### after running gen_identity.py there). This file must sit next to client.py.
with open("server_identity_public.pem", "rb") as f:
    SERVER_IDENTITY_PUB = load_pem_public_key(f.read())

# mirrors the server's key schedule exactly
SessionKeys = namedtuple("SessionKeys", "c2s_key s2c_key c2s_iv s2c_iv client_finished server_finished")

class ConnectionClosed(Exception):
    """Peer closed the connection cleanly (recv returned 0 bytes)."""

class ProtocolError(Exception):
    """Malformed framing, or a value that exceeds the size cap."""

def raw_public_bytes(pubkey):
    return pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)

#============================================================================================================
# HARDENED FRAMING (must stay byte-for-byte compatible with the server)
#============================================================================================================

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
# TRANSCRIPT + KEY SCHEDULE (must stay identical to the server)
#============================================================================================================

def transcript_hash(*parts):
    h = hashlib.sha256()
    h.update(PROTOCOL_LABEL)
    for part in parts:
        h.update(part)
    return h.digest()

def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

def derive_keys(ss_x, ss_pq, th):
    def derive(label, length):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=th,                              # transcript hash binds the keys to this handshake
            info=PROTOCOL_LABEL + b" " + label,   # a distinct label => an independent key
        ).derive(ss_x + ss_pq)
    return SessionKeys(
        c2s_key=derive(b"c2s key", 32),
        s2c_key=derive(b"s2c key", 32),
        c2s_iv=derive(b"c2s iv", 12),
        s2c_iv=derive(b"s2c iv", 12),
        client_finished=derive(b"client finished", 32),
        server_finished=derive(b"server finished", 32),
    )

def nonce_for(iv, seq):
    return bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))

def record_encrypt(key, iv, seq, plaintext):
    return AESGCM(key).encrypt(nonce_for(iv, seq), plaintext, None)

def record_decrypt(key, iv, seq, ciphertext):
    return AESGCM(key).decrypt(nonce_for(iv, seq), ciphertext, None)

#============================================================================================================
# NEW: flips every bit in the first byte of a bytes object, for the tamper demo.
def corrupt_first_byte(data: bytes) -> bytes:
    corrupted = bytearray(data)
    corrupted[0] ^= 0xFF
    return bytes(corrupted)

def run_client(host, message, log, tamper_target="None"):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT) # a silent server can no longer hang the client
        sock.connect((host, PORT))
        log(f"Connected to {host}:{PORT}")

        server_x_pub_bytes = recv_blob(sock)
        server_kem_pub_bytes = recv_blob(sock)
        signature = recv_blob(sock)

        ### Verify the signature over a hash of the server's flight BEFORE trusting these keys.
        ### A forged signature (impersonating server / tampered keys) is rejected here.
        server_flight = server_x_pub_bytes + server_kem_pub_bytes
        try:
            SERVER_IDENTITY_PUB.verify(signature, PROTOCOL_LABEL + b" server-handshake" + transcript_hash(server_flight))
            log("Server identity verified.")
        except InvalidSignature:
            log("AUTHENTICATION FAILED: server signature invalid — aborting handshake.")
            sock.close()
            return

        server_x_pub = X25519PublicKey.from_public_bytes(server_x_pub_bytes)

        x_priv = X25519PrivateKey.generate()
        x_pub_bytes = raw_public_bytes(x_priv.public_key())
        ss_x = x_priv.exchange(server_x_pub)

        kem = oqs.KeyEncapsulation(KEM_NAME)
        kem_ciphertext, ss_pq = kem.encap_secret(server_kem_pub_bytes)

        send_blob(sock, x_pub_bytes)
        send_blob(sock, kem_ciphertext)

        transcript = server_flight + signature + x_pub_bytes + kem_ciphertext
        th = transcript_hash(transcript)
        keys = derive_keys(ss_x, ss_pq, th)
        log("Session keys established (direction-separated).")

        #================================================================================================
        # KEY CONFIRMATION
        # Send our Finished (HMAC over the transcript under our Finished key) so the server can prove
        # we derived the same secret; then verify the server's Finished in return.
        #================================================================================================
        client_finished = hmac_sha256(keys.client_finished, b"client finished" + th)
        send_blob(sock, client_finished)

        server_finished = recv_blob(sock)
        th2 = transcript_hash(transcript + client_finished)
        expected_server_finished = hmac_sha256(keys.server_finished, b"server finished" + th2)
        if not hmac.compare_digest(expected_server_finished, server_finished):
            log("KEY CONFIRMATION FAILED: server Finished did not verify — aborting.")
            sock.close()
            kem.free()
            return
        log("Server key confirmation verified.")

        #================================================================================================
        # RECORD LAYER: send the application message on the client->server key and read the ack.
        #================================================================================================
        ciphertext_msg = record_encrypt(keys.c2s_key, keys.c2s_iv, 0, message.encode())

        ### Tamper target "Ciphertext": corrupt the record so the server's tag check fails.
        if tamper_target == "Ciphertext":
            ciphertext_msg = corrupt_first_byte(ciphertext_msg)
            log("Tampering simulated: corrupted the record ciphertext.")
        send_blob(sock, ciphertext_msg)

        try:
            ack = record_decrypt(keys.s2c_key, keys.s2c_iv, 0, recv_blob(sock))
            log(f"Server replied: {ack.decode(errors='replace')}")
        except (InvalidTag, ConnectionClosed, socket.timeout, ProtocolError):
            log("No valid acknowledgement from the server (it rejected the record).")

        ### Tamper target "Replay": resend the previous record verbatim. The server's counter has
        ### already advanced, so it decrypts under the wrong nonce and rejects it — replay detected.
        if tamper_target == "Replay":
            log("Replay simulated: resending the previous record verbatim.")
            send_blob(sock, ciphertext_msg)

        sock.close()
        kem.free()
    except Exception as e:
        log(f"Error: {e}")
        messagebox.showerror("Connection failed", str(e))

class ClientApp:
    def __init__(self, root):
        root.title("PQ Hybrid Client")
        root.geometry("500x480")

        tk.Label(root, text="Server IP:").pack(anchor="w", padx=10, pady=(10, 0))
        self.ip_entry = tk.Entry(root)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.pack(fill="x", padx=10)

        tk.Label(root, text="Message:").pack(anchor="w", padx=10, pady=(10, 0))
        self.msg_entry = tk.Entry(root)
        self.msg_entry.insert(0, "hello from the post-quantum era")
        self.msg_entry.pack(fill="x", padx=10)

        tk.Label(root, text="Tamper target:").pack(anchor="w", padx=10, pady=(10, 0))
        self.tamper_var = tk.StringVar(value="None")
        self.tamper_menu = tk.OptionMenu(root, self.tamper_var, "None", "Ciphertext", "Replay")
        self.tamper_menu.pack(fill="x", padx=10)

        self.send_btn = tk.Button(root, text="Send Encrypted Message", command=self.on_send)
        self.send_btn.pack(pady=10)

        tk.Label(root, text="Log:").pack(anchor="w", padx=10)
        self.log_box = scrolledtext.ScrolledText(root, height=12, state="disabled")
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def log(self, text):
        self.log_box.config(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def on_send(self):
        host = self.ip_entry.get().strip()
        message = self.msg_entry.get()
        tamper_target = self.tamper_var.get()
        if not host or not message:
            messagebox.showwarning("Missing input", "Enter both an IP and a message.")
            return
        self.send_btn.config(state="disabled")
        threading.Thread(target=self._send_thread, args=(host, message, tamper_target), daemon=True).start()

    def _send_thread(self, host, message, tamper_target):
        run_client(host, message, self.log, tamper_target)
        self.send_btn.config(state="normal")

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
