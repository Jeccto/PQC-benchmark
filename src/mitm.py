#!/usr/bin/env python3
"""
MITM lab — a man-in-the-middle listener for the pq-hybrid-v2 handshake.

PURPOSE
-------
Sits between `client.py` and `server.py` on the TCP path and shows concretely what an
attacker in that position actually obtains — and, more importantly, which defence stops
each attack. It is a *demonstration* tool for this project's own protocol; it does not
break or weaken the cryptography.

Four modes
----------
  observe      Passive relay. Forwards every frame untouched (the handshake still
               completes) while classifying exactly what leaks: lengths, public keys,
               the signature, and pure ciphertext. Nothing decryptable.
  tamper T     Active relay that corrupts/duplicates one chosen frame mid-flight, so you
               can watch the matching defence fire in the client/server logs.
               T in: server-keys | server-sig | server-finished |
                     client-ct | client-finished | client-record | replay
  impersonate  Presents ITS OWN X25519/ML-KEM keys signed with ITS OWN Ed25519 identity
               (the classic impostor-server attack). The client must reject it — this is
               exactly what the pinned server_identity_public.pem protects against.
  splice       Forwards the REAL server's flight to the client (signature verifies!) but
               runs its own client half toward the real server. Shows the transcript
               binding + Finished key confirmation catching the splice — and that the
               server, which does not authenticate clients, happily completes a
               handshake with the attacker.

HOW TO RUN (single shot: one connection per run, like server.py; run from src/)
-------------------------------------------------------------------------------
  Terminal 1 — real server on port 5001 (type 5001 in the server GUI port field, or headless):
      python -c "import server; server.run_server(5001, print)"
  Terminal 2 — the MITM on port 5000 (that is where client.py connects):
      python mitm.py observe                      # passive demo
      python mitm.py tamper client-record         # active demo (pick a target)
      python mitm.py impersonate                  # impostor server (no target needed)
      python mitm.py splice                       # transcript/key-confirmation demo
  Terminal 3 — the unmodified client (GUI): enter 127.0.0.1, send a message.
      # or headless: python -c "import client; client.run_client('127.0.0.1','hi',print,'None')"

  Options (all modes): --listen HOST:PORT (default 127.0.0.1:5000)
                       --target  HOST:PORT (default 127.0.0.1:5001)   [observe/tamper/splice]
                       --server-pub PATH   verify the genuine server signature (observe)
                       --hex N             bytes of hex preview per frame (default 16)

  Note: the real server must listen on a port OTHER than the MITM's, because the client
  connects to a fixed port 5000. Move the server to 5001 and let the MITM own 5000.
"""

import argparse
import hashlib
import hmac
import socket
import struct
import sys
import threading
import time
from collections import namedtuple

import oqs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

KEM_NAME = "ML-KEM-768"
PROTOCOL_LABEL = b"pq-hybrid-v2"   # must match client.py / server.py exactly
MAX_BLOB = 64 * 1024
SOCKET_TIMEOUT = 10.0

T0 = time.monotonic()

# mirrors the key schedule in client.py / server.py (needed for impersonate/splice)
SessionKeys = namedtuple("SessionKeys", "c2s_key s2c_key c2s_iv s2c_iv client_finished server_finished")


class ConnectionClosed(Exception):
    """Peer closed the connection cleanly (recv returned 0 bytes)."""


class ProtocolError(Exception):
    """Malformed framing, or a value that exceeds the size cap."""


# =============================================================================================================
# LOGGING
# =============================================================================================================

def log(msg):
    print(f"[+{time.monotonic() - T0:7.3f}s] {msg}", flush=True)


def hexpreview(data, n):
    shown = data[:n].hex()
    ellipsis = " …" if len(data) > n else ""
    return f"{shown}{ellipsis}"


# =============================================================================================================
# FRAMING (byte-for-byte identical to client.py / server.py — the MITM only needs to parse,
# never to understand, the payloads)
# =============================================================================================================

def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionClosed()
        data += chunk
    return data


def recv_blob(conn):
    length = struct.unpack(">I", recv_exact(conn, 4))[0]
    if length > MAX_BLOB:
        raise ProtocolError(f"declared blob of {length} bytes exceeds the {MAX_BLOB}-byte cap")
    return recv_exact(conn, length)


def send_blob(conn, data):
    conn.sendall(struct.pack(">I", len(data)) + data)


# =============================================================================================================
# PROTOCOL MATH — only used by impersonate/splice, which act as a real protocol endpoint
# =============================================================================================================

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
            salt=th,
            info=PROTOCOL_LABEL + b" " + label,
        ).derive(ss_x + ss_pq)
    return SessionKeys(
        c2s_key=derive(b"c2s key", 32),
        s2c_key=derive(b"s2c key", 32),
        c2s_iv=derive(b"c2s iv", 12),
        s2c_iv=derive(b"s2c iv", 12),
        client_finished=derive(b"client finished", 32),
        server_finished=derive(b"server finished", 32),
    )


def raw_public_bytes(pubkey):
    return pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)


# =============================================================================================================
# WHAT THE ATTACKER SEES — classify every frame by position (the framing is unencrypted, so a
# passive listener always knows *which* message it is looking at; it just can't read the secrets)
# =============================================================================================================

def describe(direction, idx, data):
    if direction == "s2c":
        return {
            0: "X25519 server public key — PUBLIC (safe to expose)",
            1: "ML-KEM-768 server public key — PUBLIC (safe to expose)",
            2: "Ed25519 signature over the server flight — PUBLIC (verifiable, NOT forgeable)",
            3: "Finished (HMAC-SHA256) — OPAQUE without the session keys",
        }.get(idx, "AES-256-GCM record — CIPHERTEXT (opaque; length leaks plaintext length only)")
    return {
        0: "X25519 client public key — PUBLIC (safe to expose)",
        1: "ML-KEM-768 ciphertext — PUBLIC (hides the encapsulated secret)",
        2: "Finished (HMAC-SHA256) — OPAQUE without the session keys",
    }.get(idx, "AES-256-GCM record — CIPHERTEXT (opaque; GCM tag detects any change)")


def flip_first_byte(data):
    corrupted = bytearray(data)
    corrupted[0] ^= 0xFF
    return bytes(corrupted)


# =============================================================================================================
# TAMPER PRESETS: (direction, frame index, action)
#   server-keys     -> corrupt the server's X25519 pubkey  -> client: signature check fails
#   server-sig      -> corrupt the Ed25519 signature       -> client: signature check fails
#   server-finished -> corrupt the server's Finished       -> client: KEY CONFIRMATION FAILED
#   client-ct       -> corrupt the ML-KEM ciphertext       -> server: KEY CONFIRMATION FAILED
#   client-finished -> corrupt the client's Finished       -> server: KEY CONFIRMATION FAILED
#   client-record   -> corrupt the AES-GCM record          -> server: REJECTED record (InvalidTag)
#   replay          -> re-send the record verbatim         -> server: REJECTED record (counter nonce)
# =============================================================================================================

TAMPER_PRESETS = {
    "server-keys":     ("s2c", 0, "flip"),
    "server-sig":      ("s2c", 2, "flip"),
    "server-finished": ("s2c", 3, "flip"),
    "client-ct":       ("c2s", 1, "flip"),
    "client-finished": ("c2s", 2, "flip"),
    "client-record":   ("c2s", 3, "flip"),
    "replay":          ("c2s", 3, "duplicate"),
}

TAMPER_EXPECTED = {
    "server-keys":     "CLIENT aborts -> \"AUTHENTICATION FAILED: server signature invalid\"",
    "server-sig":      "CLIENT aborts -> \"AUTHENTICATION FAILED: server signature invalid\"",
    "server-finished": "CLIENT aborts -> \"KEY CONFIRMATION FAILED: server Finished did not verify\"",
    "client-ct":       "SERVER aborts -> \"KEY CONFIRMATION FAILED: client Finished did not verify\"",
    "client-finished": "SERVER aborts -> \"KEY CONFIRMATION FAILED: client Finished did not verify\"",
    "client-record":   "SERVER aborts -> \"REJECTED record ... failed authentication\" (GCM tag)",
    "replay":          "SERVER aborts -> \"REJECTED record ... failed authentication\" (wrong counter nonce)",
}


# =============================================================================================================
# PASSIVE / ACTIVE RELAY (modes: observe, tamper)
# =============================================================================================================

def parse_addr(text):
    host, _, port = text.rpartition(":")
    return host or "127.0.0.1", int(port)


def open_listener(addr):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(addr)
    srv.listen(1)
    return srv


def pump(src, dst, direction, tamper, hex_len, stats, server_pub, flight):
    """Read frames from `src`, log/classify them, optionally corrupt one, forward to `dst`."""
    arrow = "S->C" if direction == "s2c" else "C->S"
    idx = 0
    try:
        while True:
            data = recv_blob(src)
            n = idx
            idx += 1
            stats[direction][0] += 1
            stats[direction][1] += len(data)

            # observe mode: verify the genuine server signature ourselves (we can verify,
            # but — this is the point — we can never forge it)
            sig_note = None
            if direction == "s2c" and n < 2:
                flight.append(data)
            if direction == "s2c" and n == 2 and server_pub is not None and len(flight) == 2:
                try:
                    msg = PROTOCOL_LABEL + b" server-handshake" + transcript_hash(flight[0] + flight[1])
                    server_pub.verify(data, msg)
                    sig_note = ("    ^ genuine server signature VERIFIED by the MITM "
                                "(anyone can verify; only the server can produce it)")
                except InvalidSignature:
                    sig_note = "    ^ server signature INVALID (unexpected for a genuine server)"

            action = None
            if tamper and tamper[0] == direction and tamper[1] == n:
                action = tamper[2]

            out = data
            note = ""
            if action == "flip":
                out = flip_first_byte(data)
                note = f"   <<< TAMPERED: byte0 {data[0]:02x}->{out[0]:02x} (xor 0xFF)"
            elif action == "duplicate":
                note = "   <<< FIRST COPY"

            log(f"{arrow} #{n:<3} {len(data):>5} B  {describe(direction, n, data)}")
            log(f"           hex: {hexpreview(out, hex_len)}{note}")
            if sig_note:
                log(sig_note)
            send_blob(dst, out)

            if action == "duplicate":
                log(f"{arrow} #{n:<3} {len(data):>5} B  REPLAYED VERBATIM   <<< TAMPERED: duplicate frame")
                send_blob(dst, out)
    except (ConnectionClosed, ProtocolError, socket.timeout, ConnectionResetError, BrokenPipeError, OSError) as e:
        log(f"{arrow} stream ended ({type(e).__name__})")
    finally:
        # shutdown() wakes a peer pump that is blocked in recv(); closing both sockets
        # ends the other direction too and lets the process exit immediately
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def run_relay(listen_addr, target_addr, tamper, hex_len, server_pub_path):
    server_pub = None
    if server_pub_path:
        with open(server_pub_path, "rb") as f:
            server_pub = load_pem_public_key(f.read())

    srv = open_listener(listen_addr)
    log(f"MITM listening on {listen_addr[0]}:{listen_addr[1]} (mode: "
        f"{'observe' if tamper is None else 'tamper'})")
    log(f"Forwarding everything to the real server at {target_addr[0]}:{target_addr[1]}")
    if tamper is None:
        log("PASSIVE mode: frames are forwarded byte-for-byte — the handshake should succeed.")
    else:
        log(f"ACTIVE mode: frame #{tamper[1]} of {tamper[0]} will be attacked: {tamper[2]}")
        log(f"Expected defence: {TAMPER_EXPECTED[_preset_name(tamper)]}")

    conn, addr = srv.accept()
    conn.settimeout(SOCKET_TIMEOUT)
    log(f"Client connected from {addr}")
    try:
        upstream = socket.create_connection(target_addr, timeout=SOCKET_TIMEOUT)
    except OSError as e:
        log(f"Cannot reach the real server at {target_addr}: {e}")
        conn.close()
        srv.close()
        return 1
    upstream.settimeout(SOCKET_TIMEOUT)
    log("Connected to the real server — relaying both directions.")

    stats = {"s2c": [0, 0], "c2s": [0, 0]}
    flight = []
    # NOTE the (src, dst) order: the pump that READS the client's socket relays C->S data,
    # the pump that reads the upstream socket relays S->C data.
    threads = [
        threading.Thread(target=pump, args=(upstream, conn, "s2c", tamper, hex_len, stats, server_pub, flight),
                         daemon=True),
        threading.Thread(target=pump, args=(conn, upstream, "c2s", tamper, hex_len, stats, None, flight),
                         daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    srv.close()

    print()
    log("--- MITM session summary ---")
    log(f"S->C : {stats['s2c'][0]:>3} frames, {stats['s2c'][1]:>6} bytes forwarded")
    log(f"C->S : {stats['c2s'][0]:>3} frames, {stats['c2s'][1]:>6} bytes forwarded")
    log("ATTACKER OBTAINED : IP addresses, timing, exact frame sizes, the two X25519 public")
    log("                    keys, the ML-KEM public key/ciphertext, one Ed25519 signature,")
    log("                    and AES-GCM ciphertext that is indistinguishable from random.")
    log("ATTACKER LACKS    : ss_x (X25519, 256-bit security) and ss_pq (ML-KEM-768, NIST")
    log("                    Level 3) — HKDF keys, Finished MACs and every plaintext depend")
    log("                    on BOTH, so no single break is enough.")
    if tamper is None:
        log("RESULT             : passive attack changed nothing — the session completed.")
    else:
        log(f"RESULT             : active attack detected — {TAMPER_EXPECTED[_preset_name(tamper)]}")
    return 0


def _preset_name(tamper):
    for name, preset in TAMPER_PRESETS.items():
        if preset == tamper:
            return name
    return "client-record"


# =============================================================================================================
# MODE: impersonate — the impostor-server attack (own keys, own Ed25519 identity)
# =============================================================================================================

def run_impersonate(listen_addr):
    log("IMPERSONATE mode: we present OUR OWN flight signed with OUR OWN Ed25519 key.")
    log("The client pinned server_identity_public.pem — it must reject us.")

    srv = open_listener(listen_addr)
    log(f"MITM listening on {listen_addr[0]}:{listen_addr[1]} (waiting for the client)")
    conn, addr = srv.accept()
    conn.settimeout(SOCKET_TIMEOUT)
    log(f"Client connected from {addr}")

    x_priv = X25519PrivateKey.generate()
    x_pub_bytes = raw_public_bytes(x_priv.public_key())
    kem = oqs.KeyEncapsulation(KEM_NAME)
    kem_pub_bytes = kem.generate_keypair()
    attacker_identity = Ed25519PrivateKey.generate()      # NOT the server's key
    flight = x_pub_bytes + kem_pub_bytes
    signature = attacker_identity.sign(
        PROTOCOL_LABEL + b" server-handshake" + transcript_hash(flight)
    )

    send_blob(conn, x_pub_bytes)
    send_blob(conn, kem_pub_bytes)
    send_blob(conn, signature)
    log("Sent 3-frame flight signed by an attacker-controlled identity -> waiting for the client...")

    try:
        client_x_bytes = recv_blob(conn)
        client_ct = recv_blob(conn)
        client_finished = recv_blob(conn)
    except (ConnectionClosed, socket.timeout, ProtocolError, OSError):
        log("")
        log(">>> CLIENT ABORTED — \"AUTHENTICATION FAILED: server signature invalid\".")
        log(">>> The Ed25519 identity pin stopped us BEFORE any key material was used.")
        log("    This is the attack the hybrid handshake is designed to lose. We never even")
        log("    reached key agreement: the client sent no public keys and no Finished.")
        conn.close()
        srv.close()
        kem.free()
        return 0

    # Counterfactual branch: this only runs if the client skips signature verification.
    client_x = X25519PublicKey.from_public_bytes(client_x_bytes)
    ss_x = x_priv.exchange(client_x)
    ss_pq = kem.decap_secret(client_ct)
    transcript = flight + signature + client_x_bytes + client_ct
    th = transcript_hash(transcript)
    keys = derive_keys(ss_x, ss_pq, th)
    expected = hmac_sha256(keys.client_finished, b"client finished" + th)
    ok = hmac.compare_digest(expected, client_finished)
    th2 = transcript_hash(transcript + client_finished)
    server_finished = hmac_sha256(keys.server_finished, b"server finished" + th2)
    send_blob(conn, server_finished)
    log("")
    log("!!! COUNTERFACTUAL: the client proceeded (verification disabled) — we would own the")
    log(f"!!! session key: {keys.c2s_key.hex()}  (client Finished valid: {ok})")
    log("!!! ...which is precisely why client.py verifies the signature FIRST.")
    conn.close()
    srv.close()
    kem.free()
    return 0


# =============================================================================================================
# MODE: splice — genuine server flight to the client, attacker's own flight to the server
# =============================================================================================================

def run_splice(listen_addr, target_addr):
    log("SPLICE mode: relay the REAL server's flight to the client (signature verifies), but")
    log("complete a DIFFERENT handshake with the real server using our own keys.")

    srv = open_listener(listen_addr)
    log(f"MITM listening on {listen_addr[0]}:{listen_addr[1]} (waiting for the client)")
    conn, addr = srv.accept()
    conn.settimeout(SOCKET_TIMEOUT)
    log(f"Client connected from {addr}")

    try:
        upstream = socket.create_connection(target_addr, timeout=SOCKET_TIMEOUT)
    except OSError as e:
        log(f"Cannot reach the real server at {target_addr}: {e}")
        conn.close()
        srv.close()
        return 1
    upstream.settimeout(SOCKET_TIMEOUT)

    # --- real server's flight, forwarded verbatim: the client's signature check PASSES ---
    s_x, s_kem, s_sig = recv_blob(upstream), recv_blob(upstream), recv_blob(upstream)
    send_blob(conn, s_x)
    send_blob(conn, s_kem)
    send_blob(conn, s_sig)
    log("Relayed the genuine server flight -> client logs \"Server identity verified.\"")

    # --- the client's half: observed, but WITHHELD from the real server ---
    c_x, c_ct, c_fin = recv_blob(conn), recv_blob(conn), recv_blob(conn)
    log(f"Client half observed and WITHHELD: x25519 {len(c_x)} B, ml-kem ct {len(c_ct)} B, "
        f"finished {len(c_fin)} B")
    log("If we had simply forwarded it, the real session would be client<->server and we would")
    log("see only ciphertext (the 'observe' mode). So instead we splice OUR OWN half in.")

    # --- our own client half toward the real server (the server has NO client auth) ---
    x_priv = X25519PrivateKey.generate()
    x_pub_bytes = raw_public_bytes(x_priv.public_key())
    kem = oqs.KeyEncapsulation(KEM_NAME)
    ct, ss_pq = kem.encap_secret(s_kem)
    send_blob(upstream, x_pub_bytes)
    send_blob(upstream, ct)

    server_flight = s_x + s_kem
    transcript = server_flight + s_sig + x_pub_bytes + ct
    th = transcript_hash(transcript)
    keys = derive_keys(x_priv.exchange(X25519PublicKey.from_public_bytes(s_x)), ss_pq, th)
    my_finished = hmac_sha256(keys.client_finished, b"client finished" + th)
    send_blob(upstream, my_finished)

    s_finished = recv_blob(upstream)
    expected = hmac_sha256(keys.server_finished,
                           b"server finished" + transcript_hash(transcript + my_finished))
    log("Server accepted OUR half: " + ("Finished VERIFIED" if hmac.compare_digest(expected, s_finished)
                                        else "Finished NOT verified"))
    log(">>> The server does not authenticate clients — an attacker can complete a full,")
    log(">>> key-confirmed handshake with it while the real client never notices.")

    # --- forward the server's Finished to the real client: it was computed over OUR transcript ---
    send_blob(conn, s_finished)
    log("Forwarded the server's Finished to the client — but it was MAC'd over the attacker's")
    log("transcript, not the client's.")
    log("")
    log(">>> CLIENT RESULT: \"KEY CONFIRMATION FAILED: server Finished did not verify — aborting.\"")
    log(">>> The signature alone could not have caught this (it covers only the server's half);")
    log(">>> the transcript-bound Finished messages did.")

    conn.close()
    upstream.close()
    srv.close()
    kem.free()
    log("")
    log("--- SPLICE summary ---")
    log("Attacker DID: pass the client's identity check with the genuine flight, complete an")
    log("              authenticated-by-key-confirmation session with the server.")
    log("Attacker COULD NOT: produce a valid server Finished for the real client's transcript,")
    log("                     i.e. silently sit inside the client's session.")
    return 0


# =============================================================================================================
# CLI
# =============================================================================================================

def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--listen", default="127.0.0.1:5000",
                        help="address the MITM listens on (default 127.0.0.1:5000)")
    common.add_argument("--target", default="127.0.0.1:5001",
                        help="real server address (default 127.0.0.1:5001)")
    common.add_argument("--hex", dest="hex_len", type=int, default=16,
                        help="bytes of hex preview per frame (default 16)")

    p = argparse.ArgumentParser(description="Man-in-the-middle lab for the pq-hybrid-v2 handshake.")
    sub = p.add_subparsers(dest="mode", required=True)

    o = sub.add_parser("observe", parents=[common], help="passive relay: log what leaks, change nothing")
    o.add_argument("--server-pub", default=None, metavar="PATH",
                   help="optional server_identity_public.pem to verify the relayed signature")

    t = sub.add_parser("tamper", parents=[common], help="actively corrupt one frame in flight")
    # NB: the positional must not be called "target" — the shared --target option would clash
    t.add_argument("attack", choices=sorted(TAMPER_PRESETS), help="which frame to attack")

    sub.add_parser("impersonate", parents=[common],
                   help="present our own identity (no target connection is made)")
    sub.add_parser("splice", parents=[common],
                   help="genuine flight to the client + our own flight to the server")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    listen = parse_addr(args.listen)
    target = parse_addr(args.target)

    if args.mode == "observe":
        return run_relay(listen, target, None, args.hex_len, args.server_pub)
    if args.mode == "tamper":
        return run_relay(listen, target, TAMPER_PRESETS[args.attack], args.hex_len, None)
    if args.mode == "impersonate":
        return run_impersonate(listen)
    if args.mode == "splice":
        return run_splice(listen, target)
    return 2


if __name__ == "__main__":
    sys.exit(main())
