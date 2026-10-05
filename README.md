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

Two parties — a server and a client — perform a handshake over TCP that establishes a shared secret key, authenticates the server's identity, and uses that key to send one encrypted message.

### High-level flow

```
 CLIENT                                           SERVER
   |                                                 |
   |  <----------- TCP connection established ------ |
   |                                                 |
   |  <-- X25519 pubkey, ML-KEM pubkey, signature --  |
   |                                                 |
   |  (verify signature against known server         |
   |   identity public key)                          |
   |                                                 |
   |  -- X25519 pubkey, ML-KEM ciphertext --------->  |
   |                                                 |
   | (both sides independently derive the same       |
   |  session key via X25519 exchange + ML-KEM       |
   |  decapsulation + HKDF)                           |
   |                                                 |
   |  -- AES-GCM encrypted message --------------->   |
   |                                                 |
   |                      (server decrypts and verifies integrity)
```

### Security properties demonstrated

| Property | Mechanism | What it protects against |
|---|---|---|
| **Confidentiality** | X25519 + ML-KEM → HKDF → AES-GCM | Eavesdropping on the message content |
| **Quantum resistance** | ML-KEM (lattice-based) | A future quantum computer breaking the key exchange |
| **Integrity** | AES-GCM authentication tag | Tampering with the encrypted message in transit |
| **Server authenticity** | Ed25519 signature over handshake keys | An attacker impersonating the server (MITM) |

---

## 3. Cryptographic building blocks

### X25519 (classical key exchange)

An elliptic-curve Diffie-Hellman function. Each side generates a fresh keypair for this session, exchanges public keys, and independently computes the same shared secret using their own private key and the other party's public key — without that secret ever being transmitted. Chosen over plain RSA/DH because it offers equivalent security with much smaller keys, and over other curves (like P-256) because it was specifically designed to be hard to implement incorrectly and uses transparently generated parameters.

### ML-KEM-768 (post-quantum key exchange)

A Key Encapsulation Mechanism based on the Module Learning-With-Errors (Module-LWE) problem — solving noisy systems of linear equations over polynomial rings, a problem with no known efficient quantum algorithm. Unlike Diffie-Hellman, a KEM is asymmetric in its roles: the sender generates a random secret and "locks" it using the receiver's public key (encapsulation); the receiver uses its private key to recover that secret (decapsulation). The "-768" denotes the security parameter set (there are also -512 and -1024 variants, trading size/speed for security margin).

### HKDF (key derivation)

Combines the two independent shared secrets (from X25519 and ML-KEM) into a single, uniformly random 32-byte session key, suitable for use with AES-256. The derivation also mixes in a **transcript** — a record of every public key and ciphertext exchanged during the handshake — which cryptographically binds the resulting key to this exact handshake. If any part of the exchange were altered, the two sides would derive different keys.

### AES-GCM (symmetric authenticated encryption)

Once a shared key is established, the actual message is encrypted using AES-256 in Galois/Counter Mode. GCM provides both encryption *and* authentication: it produces a tag that lets the receiver detect any tampering with the ciphertext or the nonce. If the tag doesn't match on decryption, the operation fails loudly rather than returning corrupted plaintext.

### Ed25519 (server authentication)

A digital signature scheme using an Edwards-curve variant of elliptic-curve cryptography. The server holds a long-term identity keypair (generated once, independent of any single session) and signs its ephemeral X25519/ML-KEM public keys with it before sending them. The client, holding a trusted copy of the server's public identity key, verifies this signature before proceeding — this is what prevents an attacker from presenting their own keys and impersonating the server. Chosen over ECDSA because its deterministic signing process avoids a known class of implementation bugs (nonce reuse, which has previously led to real-world private key leaks).

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
│   ├── server.py                 # Listens, performs handshake, decrypts message
│   └── client.py                 # GUI (Tkinter): connects, performs handshake, sends message
```

### Why a GUI client

The client is a small Tkinter application allowing a user to enter a target IP, type a message, and optionally select a tampering mode for demonstration purposes (see Section 6). The server remains a command-line process, since it has no interactive input of its own — it only listens and reports results.

### Why Docker for the server

`liboqs` (the C library implementing ML-KEM) requires a compiled toolchain to build, which differs significantly across operating systems (CMake generators, MSVC on Windows vs. GCC on Linux, etc.). Packaging the server in a Docker image means the entire build happens once, reproducibly, inside a controlled Linux environment — anyone can run the server with `docker build` and `docker run`, without needing to install a C compiler or manually build the library.

---

## 5. Protocol walkthrough (byte-level)

1. **Server startup**: generates an ephemeral X25519 keypair and an ephemeral ML-KEM-768 keypair. Signs the concatenation of both public keys with its long-term Ed25519 identity key.
2. **Server → Client**: sends (in order) its X25519 public key, its ML-KEM public key, and the Ed25519 signature over both.
3. **Client verification**: checks the signature against its known copy of the server's Ed25519 public key. If invalid, the handshake is aborted immediately.
4. **Client**: generates its own ephemeral X25519 keypair and computes the X25519 shared secret using the server's public key. Encapsulates a random secret against the server's ML-KEM public key, producing a ciphertext and its own copy of the ML-KEM shared secret.
5. **Client → Server**: sends its X25519 public key and the ML-KEM ciphertext.
6. **Both sides**: compute an identical **transcript** (the concatenation of all four exchanged values, in matching order) and feed it, along with both shared secrets, into HKDF to derive a 32-byte AES-256 session key. Both sides arrive at the same key independently, without it ever being transmitted.
7. **Client**: encrypts a message with AES-GCM using the session key and a random 12-byte nonce, sends it.
8. **Server**: decrypts and authenticates the message using its independently-derived session key.

### Message framing

Since TCP is a byte stream with no inherent message boundaries, every value exchanged above is sent using a simple **length-prefixed framing** scheme: a 4-byte big-endian integer announcing the length, followed by that many bytes of actual data. This lets each side know exactly where one value ends and the next begins.

---

## 6. Demonstrated failure modes

Beyond the "happy path," the client includes a dropdown to deliberately corrupt part of the final message before sending, to demonstrate that tampering is detected rather than silently accepted:

| Tamper target | What happens | Why |
|---|---|---|
| None | Server decrypts and prints the message normally | — |
| Ciphertext | Server detects `InvalidTag` and rejects the message | A single flipped bit anywhere in the ciphertext invalidates AES-GCM's authentication tag |
| Nonce | Server detects `InvalidTag` and rejects the message | GCM authenticates the nonce together with the ciphertext; altering either breaks the tag |

Separately, an invalid or substituted Ed25519 signature (simulating an impersonating server) causes the **client** to abort the handshake before any key material is even used — demonstrating the authentication layer independently of the encryption layer.

These two failure modes are deliberately distinct: one (AES-GCM) catches a corrupted *message*, the other (Ed25519) catches a fraudulent *server*. The project demonstrates both because they protect against different threats — a passive tamperer on the wire versus an active impersonator.

---

## 7. Benchmark results

`benchmark.py` times key generation, encapsulation/exchange, and decapsulation/verification for ML-KEM-768 against classical X25519 and ECDSA P-256, averaged over repeated runs.

*(Insert your actual measured numbers and chart here before submitting.)*

**Expected finding**: ML-KEM's operations are typically comparable in speed to, or faster than, the classical algorithms — but its keys and ciphertexts are substantially larger (roughly 1-1.5 KB vs. 32-64 bytes for X25519/ECDSA). This size increase, not speed, is the primary practical challenge in migrating existing systems to post-quantum algorithms — it affects bandwidth usage, packet fragmentation, and the size of certificates and handshake messages across the internet.

---

## 8. Limitations and scope

This project is a **demonstration of the cryptographic concepts**, not a production-ready secure messaging system. Known limitations, stated explicitly:

- **Single-shot server**: the server currently handles one connection and exits, rather than looping to accept further connections. This keeps the demo deterministic and simple to reason about; a production version would handle concurrent clients, likely with threading or async I/O.
- **Trust-on-first-use identity distribution**: the client trusts the server's Ed25519 public key because it was copied onto the client's machine manually, out-of-band. A real deployment would need a proper public-key infrastructure (a certificate authority, or a verified distribution channel) to establish that trust at scale — this project does not implement that layer.
- **No replay protection**: a captured, valid encrypted message could in principle be resent and would still decrypt successfully, since there's no sequence number or timestamp binding each message to a single use.
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
docker run -it --rm --network pq-net --ip 192.168.56.10 --name server pq-hybrid-kem python src/server.py
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