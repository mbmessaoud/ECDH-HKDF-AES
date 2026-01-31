import requests
import base64
import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_URL = "http://127.0.0.1:18080"   # matches app.cpp (port 18080)

# -------------------------------------------------------
# 1. Generate client ECDH key pair
# -------------------------------------------------------

client_private_key = ec.generate_private_key(ec.SECP256R1())
client_public_key = client_private_key.public_key()

# Use X9.62 uncompressed point bytes (what the C++ server expects)
client_pub_raw = client_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)
client_pub_b64 = base64.b64encode(client_pub_raw).decode()

# -------------------------------------------------------
# 2. Send public key to server and receive server public key
# -------------------------------------------------------

# Get server parameters (PEM public key)
resp = requests.get(f"{SERVER_URL}/login-params")
resp.raise_for_status()
server_pub_pem = resp.json()["server_pub"]
server_public_key = serialization.load_pem_public_key(server_pub_pem.encode())

# -------------------------------------------------------
# 3. Compute shared secret
# -------------------------------------------------------

shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)

# -------------------------------------------------------
# 4. Derive AES key using HKDF
# -------------------------------------------------------

username = "testuser"

# Derive AES key using same HKDF params as server: info = "login:" + username
aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=(b"login:" + username.encode()),
).derive(shared_secret)

print("AES key derived successfully")

# -------------------------------------------------------
# 5. Encrypt password using AES-GCM
# -------------------------------------------------------

# Encrypt password with AES-GCM and split tag
password = b"MySecretPassword123"
nonce = os.urandom(12)
aesgcm = AESGCM(aes_key)
ciphertext_and_tag = aesgcm.encrypt(nonce, password, None)
tag = ciphertext_and_tag[-16:]
cipher = ciphertext_and_tag[:-16]

cipher_b64 = base64.b64encode(cipher).decode()
nonce_b64 = base64.b64encode(nonce).decode()
tag_b64 = base64.b64encode(tag).decode()

# -------------------------------------------------------
# 6. Send encrypted password to server
# -------------------------------------------------------

payload = {
    "username": username,
    "client_pub": client_pub_b64,
    "iv": nonce_b64,
    "cipher": cipher_b64,
    "tag": tag_b64
}

r = requests.post(f"{SERVER_URL}/login", json=payload)
r.raise_for_status()
print("Server response JSON:", r.json())

# Decrypt returned encrypted_hello to verify
res = r.json()
enc_hello = res["encrypted_hello"]
iv_ret = base64.b64decode(enc_hello["iv"])
cipher_ret = base64.b64decode(enc_hello["cipher"])
tag_ret = base64.b64decode(enc_hello["tag"])

plaintext = aesgcm.decrypt(iv_ret, cipher_ret + tag_ret, None)
print("Decrypted 'hello' from server:", plaintext.decode())

# Decrypt encrypted_password from server and verify it matches original
enc_pass = res["encrypted_password"]
iv_p = base64.b64decode(enc_pass["iv"])
cipher_p = base64.b64decode(enc_pass["cipher"])
tag_p = base64.b64decode(enc_pass["tag"])

password_plain = aesgcm.decrypt(iv_p, cipher_p + tag_p, None)
print("Decrypted password from server:", password_plain.decode())
print("Original password matches:", password_plain == password)
