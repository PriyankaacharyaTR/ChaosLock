"""
rsa_util.py — RSA-2048 key generation and OAEP encryption helpers
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_rsa_keypair(bits: int = 2048):
    """
    Generate an RSA key-pair.

    Parameters:
        bits : key size in bits (default 2048)

    Returns:
        (private_key, public_key)  — PyCryptodome RsaKey objects
    """
    private_key = RSA.generate(bits)
    public_key = private_key.publickey()
    return private_key, public_key


def rsa_encrypt(data: bytes, public_key) -> bytes:
    """
    Encrypt *data* with RSA-OAEP.

    Parameters:
        data       : plaintext bytes (≤ key_size/8 - 42 bytes for OAEP)
        public_key : RsaKey public key

    Returns:
        ciphertext bytes
    """
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)


def rsa_decrypt(ciphertext: bytes, private_key) -> bytes:
    """
    Decrypt RSA-OAEP ciphertext.

    Parameters:
        ciphertext  : encrypted bytes
        private_key : RsaKey private key

    Returns:
        plaintext bytes
    """
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


def export_keys(private_key, public_key) -> tuple[bytes, bytes]:
    """Export keys as PEM bytes for display / storage."""
    return private_key.export_key(), public_key.export_key()
