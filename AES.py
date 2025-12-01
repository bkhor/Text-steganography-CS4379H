import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def generate_secure_key():
    """Return a 32-byte AES key derived from SHA-256 of random bytes."""
    random_bytes = os.urandom(32)
    return hashlib.sha256(random_bytes).digest()  # 32 bytes

def encrypt_message(message, key_hex):
    """Encrypt message with AES CBC mode."""
    key = bytes.fromhex(key_hex)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return (cipher.iv + ct_bytes).hex()

def decrypt_message(ciphertext_hex, key_hex):
    """Decrypt message with AES CBC mode."""
    key = bytes.fromhex(key_hex)
    data = bytes.fromhex(ciphertext_hex)
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()
