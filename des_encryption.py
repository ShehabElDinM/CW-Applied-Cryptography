# des_encryption.py
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# DES key must be exactly 8 bytes
DES_KEY = b'9keyabcd'

def encrypt_message(message):
    """Encrypt the message using DES encryption with a random IV."""
    iv = get_random_bytes(8)  # Generate a random 8-byte IV for DES
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    padded_message = pad(message.encode(), DES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    
    # Prepend the IV to the encrypted message and encode it in base64
    return base64.b64encode(iv + encrypted_message).decode()

def decrypt_message(encrypted_message):
    """Decrypt the message using DES decryption."""
    # Decode from base64 and separate the IV and encrypted message
    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:8]  # Extract the first 8 bytes as the IV
    encrypted_message_body = encrypted_data[8:]  # The rest is the encrypted message
    
    # Decrypt using the extracted IV
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message_body), DES.block_size)
    return decrypted_message.decode()
