# Post-Quantum Hybrid Key Exchange

A client/server system demonstrating a **hybrid post-quantum key exchange**: combining a classical elliptic-curve key agreement (X25519) with a post-quantum key encapsulation mechanism (ML-KEM-768), authenticated with Ed25519, to derive a shared AES-GCM session key over an untrusted network.

This is the same migration strategy currently being deployed by Chrome, Signal, and other major software (often under names like `X25519Kyber768` or `X25519MLKEM768`), implemented here as a learning project and course deliverable.

---

## 1. Why this project

### The problem: quantum computers threaten today's key exchange

Almost all key exchange and digital signature methods in use today (RSA, Diffie-Hellman, elliptic curve cryptography) rely on mathematical problems — factoring large numbers, or solving discrete logarithms — that are hard for classical computers but would be efficiently solvable by a sufficiently powerful quantum computer running **Shor's algorithm**.

This matters today, not just in some future where quantum computers exist, because of **"harvest now, decrypt later"**: an attacker can record encrypted traffic right now and simply wait until quantum computers become powerful enough to break it retroactively. Any data that needs to stay confidential for years (medical records, state secrets, long-term financial data) is already at risk today, even though the quantum computer that would break it may not exist yet.

### The response: post-quantum cryptography

NIST has standardized new algorithms built on different mathematical foundations — specifically **lattice problems** — that are believed to resist both classical *and* quantum attacks. This project uses **ML-KEM** (Module-Lattice Key Encapsulation Mechanism, FIPS 203), the standardized version of the algorithm formerly known as Kyber.

### Why "hybrid" and not pure post-quantum

ML-KEM is a relatively new standard and has had far less real-world scrutiny than classical methods like X25519, which has been studied and deployed for over a decade. Rather than betting entirely on the new algorithm, this project runs **both simultaneously** and combines their outputs into a single session key. An attacker now has to break **both** the classical and the post-quantum math to compromise the connection — a failure in either algorithm alone is not enough. This is the standard "hybrid" approach recommended during the industry's transition period.

---

## 2. What the system actually does

Two parties — a server and a client — perform a handshake over TCP that establishes a shared secret key, authenticates the server's identity, **confirms that both sides derived the same key**, and then exchanges authenticated messages in both directions over a simple record layer.

### High-level flow

```
 CLIENT                                           SERVER
   |                                                 |
   |  <----------- TCP connection established ------ |
   |                                                 |
   |  <-- X25519 pubkey, ML-KEM pubkey, signature --  |
   |                                                 |
   |  (verify signature over a hash of the server    |
   |   flight against the known identity public key) |
   |                                                 |
   |  -- X25519 pubkey, ML-KEM ciphertext --------->  |
   |                                                 |
   | (both sides derive direction-separated keys     |
   |  from X25519 + ML-KEM + HKDF over the           |
   |  full transcript)                               |
   |                                                 |
   |  -- Finished (HMAC key confirmation) -------->   |
   |  <-- Finished (HMAC key confirmation) ---------  |
   |                                                 |
   |  -- encrypted record (counter nonce) -------->   |
   |  <-- encrypted record (counter nonce) ---------  |
   |                                                 |
   |   (both directions, any number of records;      |
   |    counter nonces detect replay / reordering)   |
```

### Security properties demonstrated

| Property | Mechanism | What it protects against |
|---|---|---|
| **Confidentiality** | X25519 + ML-KEM → HKDF → AES-GCM | Eavesdropping on the message content |
| **Quantum resistance** | ML-KEM (lattice-based) | A future quantum computer breaking the key exchange |
| **Integrity** | AES-GCM authentication tag | Tampering with an encrypted record in transit |
| **Server authenticity** | Ed25519 signature over a hash of the server's flight | An attacker impersonating the server (MITM) |
| **Key confirmation** | Finished messages (HMAC over the transcript) | Either side proceeding without the other proving it holds the same key |
| **Replay / reordering resistance** | Per-direction counter nonces in the record layer | An attacker re-sending or reordering captured records |
| **DoS resistance** | 64 KB blob cap + socket timeouts | A peer announcing a huge message, or stalling the connection forever |

---

## 3. Cryptographic building blocks

### X25519 (classical key exchange)

An elliptic-curve Diffie-Hellman function. Each side generates a fresh keypair for this session, exchanges public keys, and independently computes the same shared secret using their own private key and the other party's public key — without that secret ever being transmitted. Chosen over plain RSA/DH because it offers equivalent security with much smaller keys, and over other curves (like P-256) because it was specifically designed to be hard to implement incorrectly and uses transparently generated parameters.

### ML-KEM-768 (post-quantum key exchange)

A Key Encapsulation Mechanism based on the Module Learning-With-Errors (Module-LWE) problem — solving noisy systems of linear equations over polynomial rings, a problem with no known efficient quantum algorithm. Unlike Diffie-Hellman, a KEM is asymmetric in its roles: the sender generates a random secret and "locks" it using the receiver's public key (encapsulation); the receiver uses its private key to recover that secret (decapsulation). The "-768" denotes the security parameter set (there are also -512 and -1024 variants, trading size/speed for security margin).

### HKDF (key derivation)

Combines the two independent shared secrets (from X25519 and ML-KEM) into a set of uniformly random keys. Rather than a single key, HKDF is called once per purpose with a distinct `info` label — producing a client→server key, a server→client key, their nonce bases, and two Finished-MAC keys — all salted with a hash of the **transcript** (every public key, ciphertext, and signature exchanged during the handshake). The transcript salt binds every key to this exact handshake, and the labels keep the keys independent: a leak of one reveals nothing about the others. If any part of the exchange were altered, the two sides would derive different keys.

### AES-GCM (symmetric authenticated encryption)

Once keys are established, application data is sent as AES-256-GCM **records**, one per message, in both directions. GCM provides both encryption *and* authentication: it produces a tag that lets the receiver detect any tampering with the ciphertext or the nonce. Each record uses an implicit **counter nonce** (`IV XOR sequence number`) rather than random bytes, so the receiver can also detect a replayed or reordered record — it decrypts under the wrong nonce and the tag check fails. If the tag doesn't match on decryption, the operation fails loudly rather than returning corrupted plaintext.

### Ed25519 (server authentication)

A digital signature scheme using an Edwards-curve variant of elliptic-curve cryptography. The server holds a long-term identity keypair (generated once, independent of any single session) and signs a hash of its ephemeral X25519/ML-KEM public keys (with a protocol label) before sending them. The client, holding a trusted copy of the server's public identity key, verifies this signature before proceeding — this is what prevents an attacker from presenting their own keys and impersonating the server. Chosen over ECDSA because its deterministic signing process avoids a known class of implementation bugs (nonce reuse, which has previously led to real-world private key leaks).

### Finished (key confirmation)

After deriving the keys, each side sends a **Finished** message: `HMAC(finished_key, label ‖ transcript_hash)`. Because the MAC key is derived from the session secret and the transcript, a valid MAC proves the peer derived the same key from the same exchange — the TLS 1.3 "Finished" step. It replaces the old behaviour of "send a message and hope it happens to decrypt," and it binds the client's half of the exchange (which the server's signature, sent before the client spoke, could not).

---

## 4. Architecture and components

```
pq-hybrid-kem/
├── Dockerfile                    # Builds a container with liboqs + Python deps
├── requirements.txt
├── server_identity_private.pem   # Server's long-term identity key (server only)
├── server_identity_public.pem    # Copied to the client out-of-band
├── src/
│   ├── gen_identity.py           # One-time: generates the Ed25519 identity keypair
│   ├── kem_demo.py               # Minimal ML-KEM encapsulate/decapsulate demo
│   ├── benchmark.py              # Timing comparison: ML-KEM vs X25519 vs ECDSA
│   ├── server.py                 # GUI (Tkinter): listens, handshake + Finished, record layer
│   └── client.py                 # GUI (Tkinter): connects, handshake + Finished, sends records
```

### Why a GUI client

Both applications are small Tkinter apps. The client lets a user enter a target IP, type a message, and optionally select a tampering mode for demonstration purposes (see Section 6). The server lets a user choose the listen port, start accepting a connection, and watch the handshake and record layer scroll past in a log pane. The server falls back to a plain command-line loop automatically when no display is available — for example inside the Docker container.

### Why Docker for the server

`liboqs` (the C library implementing ML-KEM) requires a compiled toolchain to build, which differs significantly across operating systems (CMake generators, MSVC on Windows vs. GCC on Linux, etc.). Packaging the server in a Docker image means the entire build happens once, reproducibly, inside a controlled Linux environment — anyone can run the server with `docker build` and `docker run`, without needing to install a C compiler or manually build the library.

---

## 5. Protocol walkthrough (byte-level)

1. **Server startup**: generates an ephemeral X25519 keypair and an ephemeral ML-KEM-768 keypair. It hashes its flight (both public keys) and signs `label ‖ hash` with its long-term Ed25519 identity key — the same construction TLS 1.3 uses for `CertificateVerify`.
2. **Server → Client**: sends (in order) its X25519 public key, its ML-KEM public key, and the Ed25519 signature.
3. **Client verification**: recomputes the flight hash and checks the signature against its known copy of the server's Ed25519 public key. If invalid, the handshake is aborted immediately, before any key material is used.
4. **Client**: generates its own ephemeral X25519 keypair and computes the X25519 shared secret using the server's public key. Encapsulates a random secret against the server's ML-KEM public key, producing a ciphertext and its own copy of the ML-KEM shared secret.
5. **Client → Server**: sends its X25519 public key and the ML-KEM ciphertext.
6. **Both sides**: build the identical **transcript** (the server flight, the signature, and the client flight, in matching order) and run HKDF over it to derive *separate* keys for each purpose — a client→server key, a server→client key, their nonce bases, and two Finished-MAC keys. Using the transcript hash as the HKDF salt binds every key to this exact handshake, and using a distinct `info` label per key guarantees the keys are independent.
7. **Client → Server**: sends its **Finished** — `HMAC(client_finished_key, "client finished" ‖ transcript_hash)`.
8. **Server**: recomputes the expected Finished and compares it in constant time. A valid MAC proves the client derived the same session secret (key confirmation) and binds the client's half of the exchange, which the earlier signature — sent before the client spoke — could not. The server then sends its own **Finished**, covering the transcript plus the client's Finished.
9. **Client**: verifies the server's Finished. Both sides have now confirmed they hold the same key.
10. **Record layer**: application data flows as AES-GCM records under the direction-specific keys, using an implicit counter nonce (`IV XOR seq`). The server loops on the client→server key and acknowledges each record on the server→client key, so the protocol supports many messages in both directions. Because every record consumes the next counter value, a replayed or reordered record decrypts under the wrong nonce and is rejected.

### Message framing

Since TCP is a byte stream with no inherent message boundaries, every value exchanged above is sent using a simple **length-prefixed framing** scheme: a 4-byte big-endian integer announcing the length, followed by that many bytes of actual data. This lets each side know exactly where one value ends and the next begins.

The receive side is deliberately defensive (see *input validation and DoS resistance* in Section 8):

- a `recv_exact` helper loops until it has read the requested number of bytes, and raises `ConnectionClosed` on a clean end-of-stream instead of spinning forever when the peer disconnects mid-message;
- a **64 KB cap** (`MAX_BLOB`) is enforced on the announced length *before* allocating, so a peer cannot declare a 4 GB message and exhaust memory;
- every socket has a **10-second timeout**, so a peer that goes silent is dropped rather than hanging the process.

---

## 6. Demonstrated failure modes

Beyond the "happy path," the client includes a dropdown to deliberately misbehave, to demonstrate that each case is detected rather than silently accepted:

| Tamper target | What happens | Why |
|---|---|---|
| None | Server decrypts the record, prints the message, and acknowledges it | — |
| Ciphertext | Server detects `InvalidTag`, rejects the record, and ends the session | A single flipped bit anywhere in the ciphertext invalidates AES-GCM's authentication tag |
| Replay | Client re-sends the previous record verbatim; the server rejects it | The server's counter has already advanced, so the record decrypts under the wrong nonce and fails authentication |

Separately, an invalid or substituted Ed25519 signature (simulating an impersonating server) causes the **client** to abort the handshake before any key material is even used — demonstrating the authentication layer independently of the encryption layer. Likewise, a client whose Finished MAC does not verify, or a server whose Finished MAC does not verify, causes the peer to abort before any application data is exchanged.

These failure modes are deliberately distinct: AES-GCM catches a corrupted *record*, the counter nonce catches a *replayed or reordered* record, the Finished MACs catch a *failed key agreement*, and Ed25519 catches a fraudulent *server*. The project demonstrates them together because they protect against different threats — a passive tamperer on the wire, an active impersonator, or a peer that never actually agreed on the key.

The framing layer is hardened the same way: an announced length above the 64 KB cap raises `ProtocolError` before anything is allocated, and a peer that disconnects mid-message raises `ConnectionClosed` instead of hanging (see Section 8).

---

## 7. Benchmark results

`benchmark.py` times key generation, encapsulation/exchange, and decapsulation/verification for ML-KEM-768 against classical X25519 and ECDSA P-256, averaged over repeated runs.

*(Insert your actual measured numbers and chart here before submitting.)*

**Expected finding**: ML-KEM's operations are typically comparable in speed to, or faster than, the classical algorithms — but its keys and ciphertexts are substantially larger (roughly 1-1.5 KB vs. 32-64 bytes for X25519/ECDSA). This size increase, not speed, is the primary practical challenge in migrating existing systems to post-quantum algorithms — it affects bandwidth usage, packet fragmentation, and the size of certificates and handshake messages across the internet.

---

## 8. Limitations and scope

This project is a **demonstration of the cryptographic concepts**, not a production-ready secure messaging system. Known limitations, stated explicitly:

- **Single-shot server**: the server currently handles one connection — though it now processes multiple records within that connection — and then exits, rather than accepting further connections. This keeps the demo deterministic and simple to reason about; a production version would handle concurrent clients, likely with threading or async I/O.
- **Trust-on-first-use identity distribution**: the client trusts the server's Ed25519 public key because it was copied onto the client's machine manually, out-of-band. A real deployment would need a proper public-key infrastructure (a certificate authority, or a verified distribution channel) to establish that trust at scale — this project does not implement that layer.
- **Replay protection is per-session**: within a session, counter nonces detect replayed or reordered records. Across sessions, replay is already defeated because every handshake uses fresh ephemeral keys, so an old record decrypts under an entirely different key. There is no additional timestamp or handshake-freshness check beyond those ephemeral keys.
- **Input validation and DoS resistance**: framing enforces `recv_exact`, a 64 KB cap, and a 10-second socket timeout (Section 5), which removes the memory-exhaustion and infinite-loop failure modes. The server still processes one connection at a time, however, so a determined attacker could deny service simply by occupying that single connection slot — a production server would need rate limiting and concurrency.
- **No forward secrecy beyond the session**: while each handshake uses fresh ephemeral keys (providing forward secrecy between sessions), there is no ongoing key ratcheting within a session, unlike protocols such as Signal's Double Ratchet.
- **Unencrypted private key storage**: the server's Ed25519 private key is stored unencrypted on disk for simplicity. A production system would encrypt it at rest.

---

## 9. How to run

### Prerequisites

- Docker (for the server), or a native build of `liboqs` + Python 3.10+ with `liboqs-python` and `cryptography` installed.

### One-time setup

```bash
python src/gen_identity.py
```
Generates `server_identity_private.pem` (keep on the server) and `server_identity_public.pem` (copy to wherever the client runs).

### Running the server (Docker)

```bash
docker build -t pq-hybrid-kem .
docker network create --subnet=192.168.56.0/24 pq-net
docker run -it --rm --network pq-net --ip 192.168.56.10 --name server pq-hybrid-kem
```

The container has no display, so the server automatically runs headless (its Tkinter GUI is skipped). If you did not mount a key, the container generates its own identity keypair on first start — copy the matching public key out so the client trusts it:

```bash
docker cp server:/app/src/server_identity_public.pem ./server_identity_public.pem
```

For a stable identity across containers, generate the keypair once on the host (`python src/gen_identity.py`) and mount the private key into the container instead:

```bash
docker run -it --rm --network pq-net --ip 192.168.56.10 --name server \
  -v "/absolute/path/to/server_identity_private.pem:/app/src/server_identity_private.pem" \
  pq-hybrid-kem
```

### Running the client (native)

```bash
python src/client.py
```
Enter the server's IP, a message, and optionally a tampering mode, then click **Send Encrypted Message**.

---

## 10. References

- NIST FIPS 203 — *Module-Lattice-Based Key-Encapsulation Mechanism Standard*
- NIST FIPS 186-5 — *Digital Signature Standard* (EdDSA)
- RFC 5869 — *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*
- RFC 8032 — *Edwards-Curve Digital Signature Algorithm (EdDSA)*
- RFC 7748 — *Elliptic Curves for Security* (X25519)
- Open Quantum Safe project (`liboqs`) — reference implementation of ML-KEM used in this project