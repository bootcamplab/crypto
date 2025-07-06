import os
import base64
import json
import hashlib
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
from cryptography.hazmat.backends import default_backend

# KEY FILES
KEY_DIR = "keys"
RSA_PRIV_FILE = os.path.join(KEY_DIR, "recipient_private.pem")
RSA_PUB_FILE = os.path.join(KEY_DIR, "recipient_public.pem")
SIGNER_PRIV_FILE = os.path.join(KEY_DIR, "signer_private.pem")
SIGNER_PUB_FILE = os.path.join(KEY_DIR, "signer_public.pem")

#ARGUMENT FILES
input_file = sys.argv[1] if len(sys.argv) > 1 else "message.txt"
output_file = sys.argv[2] if len(sys.argv) > 2 else "secure_message.json"

# SAVE AND LOAD KEYS

def save_key_pem(key, path, is_private=True, password=None):
    with open(path, "wb") as f:
        if is_private:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        else:
            f.write(key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def load_or_generate_rsa_keys():
    if os.path.exists(RSA_PRIV_FILE) and os.path.exists(RSA_PUB_FILE):
        with open(RSA_PRIV_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(RSA_PUB_FILE, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        save_key_pem(private_key, RSA_PRIV_FILE)
        save_key_pem(public_key, RSA_PUB_FILE, is_private=False)
    return private_key, public_key

def load_or_generate_signing_keys():
    if os.path.exists(SIGNER_PRIV_FILE) and os.path.exists(SIGNER_PUB_FILE):
        with open(SIGNER_PRIV_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(SIGNER_PUB_FILE, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    else:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        save_key_pem(private_key, SIGNER_PRIV_FILE)
        save_key_pem(public_key, SIGNER_PUB_FILE, is_private=False)
    return private_key, public_key

# READ MESSAGE
with open(input_file, "rb") as f:
    plaintext = f.read()

# GENERATE AES/IV
aes_key = AESGCM.generate_key(bit_length=256)
iv = os.urandom(12)

# LOAD OR GENERATE KEYS
recipient_private_key, recipient_public_key = load_or_generate_rsa_keys()
signing_private_key, signing_public_key = load_or_generate_signing_keys()

# CIPHER MESSAGE
aesgcm = AESGCM(aes_key)
ciphertext = aesgcm.encrypt(iv, plaintext, None)

# CIPHER AES/IV WITH RSA PUB
enc_key = recipient_public_key.encrypt(
    aes_key,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
enc_iv = recipient_public_key.encrypt(
    iv,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# HASH KEY PUB RSA 
recipient_pub_pem = recipient_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
pubkey_hash = hashlib.sha256(recipient_pub_pem).digest()

# SIGNING OF HASH OF CIPHERTEXT
ciphertext_hash = hashlib.sha256(ciphertext).digest()
signature = signing_private_key.sign(ciphertext_hash)

# EXPORT KEY PUB SIGNATURE 
signing_pub_pem = signing_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# FINAL JSON FILE
data = {
    "ciphertext": base64.b64encode(ciphertext).decode(),
    "enc_key": base64.b64encode(enc_key).decode(),
    "enc_iv": base64.b64encode(enc_iv).decode(),
    "pubkey_hash": base64.b64encode(pubkey_hash).decode(),
    "signature": base64.b64encode(signature).decode(),
    "pubkey_signature": base64.b64encode(signing_pub_pem).decode(),
    "algos": {
        "symmetric": "AES-256-GCM",
        "asymmetric": "RSA-2048",
        "hash": "SHA-256"
    }
}

with open(output_file, "w") as f:
    json.dump(data, f, indent=4)

print("✅ Message chiffré et sauvegardé dans secure_message.json")
