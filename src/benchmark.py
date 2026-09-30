import time
import oqs
from cryptography.hazmat.primitives.asymmetric import ec #ECDSA (Elliptic Curve Digital Signature Algorithm: a public-key cryptographic method used to generate and verify digital signatures)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey #(X25519 key exchange: Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol that uses Curve25519 to let two parties safely agree on a shared secret over an unsecured network)
from cryptography.hazmat.primitives import hashes

def bench(fn, n=100000):
    start = time.perf_counter()
    for _ in range(n):
        fn()
    elapsed = time.perf_counter() - start
    return (elapsed / n) * 1000

def bench_mlkem(kem_name="ML-KEM-768"):
    with oqs.KeyEncapsulation(kem_name) as kem: #Alice
        pk = kem.generate_keypair() #pk: public key

    keygen_time = bench(lambda: oqs.KeyEncapsulation(kem_name).generate_keypair()) #how long it takes for key generation on average

    def encaps_op():
        with oqs.KeyEncapsulation(kem_name) as sender: #Bob, we get ciphers here
            sender.encap_secret(pk)
    encaps_time = bench(encaps_op)

    with oqs.KeyEncapsulation(kem_name) as receiver: #Alice
        pk2 = receiver.generate_keypair()  #we can't use the pk we used before since when the "with" block ends, the private key stored in kem is deleted, and we can't do much without it
        with oqs.KeyEncapsulation(kem_name) as sender: #Bob
            ct, _ = sender.encap_secret(pk2)
        decaps_time = bench(lambda: receiver.decap_secret(ct))

    return keygen_time, encaps_time, decaps_time

#  ============================================================================
#  X25519 KEY EXCHANGE (Classical Pre-Quantum Baseline)
#  ============================================================================
#  What it is: A highly efficient Elliptic-Curve Diffie-Hellman (ECDH) protocol.
#
#  How it works:
#  1. Both parties generate a random private key.
#  2. They derive a 32-byte public key using a secure mathematical curve (Curve25519).
#  3. They swap public keys and multiply them by their own private keys.
#  4. Because of elliptic curve math, both sides arrive at the exact same secret.
#
#  Why it's here: In this hybrid PQC project, X25519 provides a fast, time-tested
#  classical safety net. It protects traffic against current threats while new
#  post-quantum algorithms (like ML-KEM) protect against future quantum computers.
#  ============================================================================


def bench_x25519():
    keygen_time = bench(lambda: X25519PrivateKey.generate())

    alice = X25519PrivateKey.generate()
    bob = X25519PrivateKey.generate()
    bob_pub = bob.public_key()
    exchange_time = bench(lambda: alice.exchange(bob_pub))

    return keygen_time, exchange_time

def bench_ecdsa():
    keygen_time = bench(lambda: ec.generate_private_key(ec.SECP256R1()))

    priv = ec.generate_private_key(ec.SECP256R1())
    msg = b"benchmark message"
    sign_time = bench(lambda: priv.sign(msg, ec.ECDSA(hashes.SHA256())))

    sig = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
    pub = priv.public_key()
    verify_time = bench(lambda: pub.verify(sig, msg, ec.ECDSA(hashes.SHA256())))

    return keygen_time, sign_time, verify_time

if __name__ == "__main__":
    print("=== ML-KEM-768 ===")
    kg, en, de = bench_mlkem()
    print(f"Keygen:  {kg:.4f} ms")
    print(f"Encaps:  {en:.4f} ms")
    print(f"Decaps:  {de:.4f} ms")

    print("\n=== X25519 ===")
    kg, ex = bench_x25519()
    print(f"Keygen:   {kg:.4f} ms")
    print(f"Exchange: {ex:.4f} ms")

    print("\n=== ECDSA P-256 ===")
    kg, sg, vf = bench_ecdsa()
    print(f"Keygen:  {kg:.4f} ms")
    print(f"Sign:    {sg:.4f} ms")
    print(f"Verify:  {vf:.4f} ms")