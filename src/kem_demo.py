import oqs

KEM_NAME = "ML-KEM-768"

def run_demo():
    with oqs.KeyEncapsulation(KEM_NAME) as receiver:
        public_key = receiver.generate_keypair()#Receiver object hold the private key s, it is hidden since It's private!! Receiver only!!
        print(f"Public key (t=A.s+e) : {public_key}")

        with oqs.KeyEncapsulation(KEM_NAME) as sender:
            ciphertext, shared_secret_sender = sender.encap_secret(public_key)
            print(f"Ciphertext ( u=transpose(A).r+e1 , V=transpose(A).r+e2+encode(m) ): {ciphertext}") #sender chooses r and small errors e1 and e2

            #m is the message to transfer, we encode it:

            # ==============================================================================
            # ML-KEM-768 MATHEMATICAL ENCODING MECHANISM: Encode(m)
            # ==============================================================================
            #
            # 1. THE OBJECTIVE:
            #    Before the sender executes `sender.encap_secret(public_key)`, a random
            #    32-byte message seed (m) is generated. This 32-byte seed must be translated
            #    into the language of lattice cryptography (polynomials) so that it can be
            #    safely encrypted, injected with math noise, and cleanly decrypted.
            #
            # 2. THE BIT-TO-COEFFICIENT MAPPING:
            #    32 bytes * 8 bits = 256 individual bits: m = (b_0, b_1, ..., b_255).
            #    ML-KEM uses 256-degree polynomials: P(x) = c_0 + c_1*x + ... + c_255*x^255.
            #    The `Encode(m)` function maps each raw bit to its corresponding coefficient:
            #
            #    - If bit b_i == 0  ==>  Coefficient c_i = 0
            #    - If bit b_i == 1  ==>  Coefficient c_i = 1665
            #
            #    WHY 1665?
            #    ML-KEM operates under a prime modulus (q = 3329). The value 1665 is exactly
            #    ceiling(q/2) — the precise mathematical midpoint of the number space.
            #    This pushes the "0" and "1" states as far apart from each other as possible.
            #
            # 3. ERROR CORRECTION DURING DECAPSULATION:
            #    When the receiver computes `v - s^T * u`, the result is:
            #    Result = Encode(m) + Combined_Mathematical_Noise
            #
            #    Because of the noise, the receiver will never get a perfect 0 or 1665.
            #    Instead, they get a noisy integer which they decode using rounding zones:
            #
            #    - [Bit 0 Zone]: If c_i is closer to 0 (Value is inside [0 +/- 832])
            #    - [Bit 1 Zone]: If c_i is closer to 1665 (Value is inside [1665 +/- 832])
            #
            #    This massive structural buffer guarantees that quantum-safe noise can shift
            #    the numbers during transmission without ever corrupting the underlying data.
            # ==============================================================================

            print(f"Shared secret sender: {shared_secret_sender}")
            print()

        shared_secret_receiver = receiver.decap_secret(ciphertext)

        # ==============================================================================
        # ALGEBRAIC PROOF: WHY THE DECAPSULATION MATH CANCELS OUT PERFECTLY
        # ==============================================================================
        #
        # 1. THE DECRYPTION EQUATION:
        #    When Alice receives the ciphertext components (u, v), she uses her
        #    private key (s) to strip away the matrix math by computing:
        #
        #    Result = v - (s^T * u)
        #
        # 2. EXPANDING THE EXPRESSIONS:
        #    Substituting Bob's original encapsulation formulas for u and v into
        #    Alice's equation expands the math to this:
        #
        #    Result = ( (t^T * r) + e2 + Encode(m) ) - s^T * ( (A^T * r) + e1 )
        #
        # 3. ALGEBRAIC ALIGNMENT AND CANCELLATION:
        #    Recall from Key Generation that Alice's public key vector is: t = (A * s) + e.
        #    When transposed, this becomes: t^T = (s^T * A^T) + e^T.
        #
        #    Substituting t^T back into the expanded equation yields:
        #    Result = (s^T * A^T * r) + (e^T * r) + e2 + Encode(m) - (s^T * A^T * r) - (s^T * e1)
        #
        #    Notice that the primary algebraic terms match perfectly and cancel out:
        #    ==> (s^T * A^T * r) - (s^T * A^T * r) = 0
        #
        # 4. THE REMAINING NOISE LAYER:
        #    Once the massive matrix structures cancel out, Alice is left with:
        #    Result = Encode(m) + (e^T * r + e2 - s^T * e1)
        #           = Encode(m) + [Minor Background Noise]
        #
        # 5. ERROR CORRECTION AND ROUNDING:
        #    Because the noise vectors (e, e1, e2) and secret parameters (s, r) are
        #    intentionally chosen to be very small numbers, their combined sum is small.
        #    Alice rounds the resulting values to the nearest target (0 or 1665) to
        #    completely eliminate this minor background noise and perfectly recover
        #    the original 32-byte message seed (m).
        #
        # 6. THE SHARED SECRET (K):
        #    With 'm' successfully recovered, Alice hashes 'm' using the exact same
        #    Key Derivation Function (KDF) that Bob used, generating the identical
        #    final 32-byte Shared Secret (K).
        # ==============================================================================

    assert shared_secret_sender == shared_secret_receiver, "Shared secrets don't match!"

    #• Bob has a public key and a long-term private/secret key.
    #• Alice takes Bob's public key and runs an Encapsulate function. This function outputs two things: a random Shared Secret and a Ciphertext.
    #• Alice sends the Ciphertext to Bob. Bob uses his long-term private key to Decapsulate it and recover the exact same Shared Secret.


    print(f"Algorithm: {KEM_NAME}")
    print(f"Public key size:     {len(public_key)} bytes")
    print(f"Ciphertext size:     {len(ciphertext)} bytes")
    print(f"Shared secret size:  {len(shared_secret_sender)} bytes")
    print(f"Shared secret (hex): {shared_secret_sender.hex()}")
    print("Success — both sides derived the same secret.")

if __name__ == "__main__":
    run_demo()