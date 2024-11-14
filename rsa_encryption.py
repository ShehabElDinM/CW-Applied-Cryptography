# rsa_encryption.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

# File paths for RSA keys
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"

# Generate and save keys if they don't already exist
def generate_keys():
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        with open(PRIVATE_KEY_FILE, "wb") as priv_file:
            priv_file.write(private_key)
        with open(PUBLIC_KEY_FILE, "wb") as pub_file:
            pub_file.write(public_key)

# Load the public key
def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as pub_file:
        return pub_file.read()

# Load the private key
def load_private_key():
    with open(PRIVATE_KEY_FILE, "rb") as priv_file:
        return priv_file.read()

# Encrypt data with the public key
def encrypt_data(data):
    public_key = RSA.import_key(load_public_key())
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(data.encode())
    return base64.b64encode(encrypted_data).decode()

# Decrypt data with the private key
def decrypt_data(encrypted_data):
    private_key = RSA.import_key(load_private_key())
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
    return decrypted_data.decode()

# Ensure keys are generated
generate_keys()
