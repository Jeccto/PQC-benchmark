from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)

priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

with open("server_identity_private.pem", "wb") as f:
    f.write(priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

with open("server_identity_public.pem", "wb") as f:
    f.write(pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

print("Identity keypair generated.")
print("Give server_identity_public.pem to the client. Keep the private one on the server only.")