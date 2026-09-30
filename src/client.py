import socket
import struct
import oqs
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

KEM_NAME = "ML-KEM-768"
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

def run_client(host, message, log):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, PORT))
        log(f"Connected to {host}:{PORT}")

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
        log(f"Session key: {session_key.hex()}")

        nonce = os.urandom(12) # nonce: number used once, 12: bytes
        #!AES-GCM requires a nonce (number used once) — 12 bytes is the standard size for GCM. It doesn't need to be secret, just unique per encryption with the same key
        #!reusing a nonce with the same key catastrophically breaks GCM's security.
        ciphertext_msg = AESGCM(session_key).encrypt(nonce, message.encode(), None)
        send_blob(sock, nonce + ciphertext_msg)

        log("Message sent and encrypted successfully.")
        sock.close()
        kem.free()
    except Exception as e:
        log(f"Error: {e}")
        messagebox.showerror("Connection failed", str(e))

class ClientApp:
    def __init__(self, root):
        root.title("PQ Hybrid Client")
        root.geometry("500x400")

        tk.Label(root, text="Server IP:").pack(anchor="w", padx=10, pady=(10, 0))
        self.ip_entry = tk.Entry(root)
        self.ip_entry.insert(0, "192.168.56.10")
        self.ip_entry.pack(fill="x", padx=10)

        tk.Label(root, text="Message:").pack(anchor="w", padx=10, pady=(10, 0))
        self.msg_entry = tk.Entry(root)
        self.msg_entry.insert(0, "hello from the post-quantum era")
        self.msg_entry.pack(fill="x", padx=10)

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
        if not host or not message:
            messagebox.showwarning("Missing input", "Enter both an IP and a message.")
            return
        self.send_btn.config(state="disabled")
        threading.Thread(target=self._send_thread, args=(host, message), daemon=True).start()

    def _send_thread(self, host, message):
        run_client(host, message, self.log)
        self.send_btn.config(state="normal")

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()