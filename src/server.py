import socket
import struct
import oqs
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
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

def show_error(title, message):
    # messagebox needs a display; in headless mode (e.g. Docker) just skip the dialog.
    try:
        messagebox.showerror(title, message)
    except tk.TclError:
        pass

def run_server(port, log):
    try:
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
        sock.bind((HOST, port))
        sock.listen(1)
        log(f"Server listening on {HOST}:{port}")

        conn, addr = sock.accept()
        log(f"Connection from {addr}")

        send_blob(conn, x_pub_bytes)
        send_blob(conn, kem_pub_bytes)
        send_blob(conn, signature)  ### NEW: send the signature as a third blob

        client_x_pub_bytes = recv_blob(conn)
        client_kem_ciphertext = recv_blob(conn)

        client_x_pub = X25519PublicKey.from_public_bytes(client_x_pub_bytes)

        ss_x = x_priv.exchange(client_x_pub)
        ss_pq = kem.decap_secret(client_kem_ciphertext)

        transcript = client_x_pub_bytes + x_pub_bytes + kem_pub_bytes + client_kem_ciphertext
        session_key = derive_key(ss_x, ss_pq, transcript)
        log(f"Session key: {session_key.hex()}")

        encrypted_msg = recv_blob(conn)
        nonce = encrypted_msg[:12]
        ciphertext_msg = encrypted_msg[12:]

        try:
            plaintext = AESGCM(session_key).decrypt(nonce, ciphertext_msg, None)
            log(f"Decrypted message from client: {plaintext.decode()}")
        except InvalidTag:
            log(f"TAMPER DETECTED from {addr}: ciphertext/nonce failed authentication — message rejected.")

        conn.close()
        sock.close()
        kem.free()
    except Exception as e:
        log(f"Error: {e}")
        show_error("Server failed", str(e))

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