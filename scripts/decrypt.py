import json
import base64
import hashlib
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ed25519, rsa
from cryptography.hazmat.backends import default_backend



# KEY FILE
KEY_DIR = "keys"
RSA_PRIV_FILE = f"{KEY_DIR}/recipient_private.pem"
#JSON FILE AS ARGS
json_file = sys.argv[1] if len(sys.argv) > 1 else "secure_message.json"
# LOAD JSON FILE
with open(json_file, "r") as f:
    data = json.load(f)

# DECODE BASE64
ciphertext = base64.b64decode(data["ciphertext"])
enc_key = base64.b64decode(data["enc_key"])
enc_iv = base64.b64decode(data["enc_iv"])
pubkey_hash = base64.b64decode(data["pubkey_hash"])
signature = base64.b64decode(data["signature"])
pubkey_signature_pem = base64.b64decode(data["pubkey_signature"])

# LOAD DEST KEY
with open(RSA_PRIV_FILE, "rb") as f:
    recipient_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
recipient_public_key = recipient_private_key.public_key()
recipient_pub_pem = recipient_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# CHECK HASH OF PUB KEY
computed_hash = hashlib.sha256(recipient_pub_pem).digest()
if computed_hash != pubkey_hash:
    raise ValueError("❌ Clé publique invalide : le hash ne correspond pas.")

# UNCIPHER AES AND IV KEYS
aes_key = recipient_private_key.decrypt(
    enc_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
iv = recipient_private_key.decrypt(
    enc_iv,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# CHECK SIGNATURE
signing_public_key = serialization.load_pem_public_key(pubkey_signature_pem, backend=default_backend())

ciphertext_hash = hashlib.sha256(ciphertext).digest()

try:
    signing_public_key.verify(signature, ciphertext_hash)
except Exception as e:
    raise ValueError("❌ Signature invalide.") from e

# UNCIPHER MESSAGE
aesgcm = AESGCM(aes_key)
try:
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    print("✅ Message déchiffré avec succès :\n")
    print(plaintext.decode())
except Exception as e:
    raise ValueError("❌ Erreur lors du déchiffrement AES-GCM.") from e
