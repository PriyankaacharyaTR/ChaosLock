"""
aes_util.py — AES-256 encryption/decryption (CBC mode) helpers
"""

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# AES block size (bytes)
BLOCK = AES.block_size  # 16


def generate_aes_key() -> bytes:
    """Return a cryptographically random 32-byte (256-bit) AES key."""
    return os.urandom(32)


def aes_encrypt(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt *data* with AES-256-CBC.

    Parameters:
        data : plaintext bytes (any length)
        key  : 32-byte AES key

    Returns:
        (iv, ciphertext)  — iv is 16 bytes, ciphertext is padded
    """
    iv = os.urandom(BLOCK)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, BLOCK))
    return iv, ciphertext


def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-256-CBC ciphertext.

    Parameters:
        iv         : 16-byte initialisation vector
        ciphertext : encrypted bytes
        key        : 32-byte AES key

    Returns:
        plaintext bytes
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), BLOCK)
    return plaintext
