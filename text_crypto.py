"""
text_crypto.py — 3-layer text encryption/decryption:
    Chaos Masking → AES-256-CBC → RSA-OAEP (AES key)
"""

import base64
import json
import os
import hmac
import hashlib
from datetime import datetime, timezone

from chaos import apply_chaos_mask, remove_chaos_mask
from aes_util import generate_aes_key, aes_encrypt, aes_decrypt
from rsa_util import rsa_encrypt, rsa_decrypt


# Default chaos parameters — callers may override
DEFAULT_R = 3.99
DEFAULT_X0 = 0.5


PAYLOAD_VERSION = 1
PAYLOAD_SUITE = "CHAOS_XOR + AES-256-CBC + RSA-OAEP + HMAC-SHA256"


def _format_float(f: float) -> bytes:
    return ("%.10f" % float(f)).encode("utf-8")


def _text_mac_message(iv: bytes, ciphertext: bytes, enc_aes_key: bytes, nonce: bytes, r: float, x0: float) -> bytes:
    return b"|".join([iv, ciphertext, enc_aes_key, nonce, _format_float(r), _format_float(x0)])


def encrypt_text(
    message: str,
    public_key,
    r: float = DEFAULT_R,
    x0: float = DEFAULT_X0,
) -> dict:
    """
    Encrypt a plaintext message.

    Returns a dict with:
        chaos_masked_b64   : base64 of chaos-masked bytes (before AES)
        iv_b64             : base64 AES initialisation vector
        ciphertext_b64     : base64 AES ciphertext
        enc_aes_key_b64    : base64 RSA-encrypted AES key
        chaos_r            : chaos parameter r
        chaos_x0           : chaos parameter x0
    """
    # Layer 1: chaos masking
    raw = message.encode("utf-8")
    chaos_masked = apply_chaos_mask(raw, r, x0)

    # Layer 2: AES encryption
    aes_key = generate_aes_key()
    iv, ciphertext = aes_encrypt(chaos_masked, aes_key)

    # Layer 3: RSA-encrypt the AES key
    enc_aes_key = rsa_encrypt(aes_key, public_key)

    # Metadata (useful for network/replay demos & interoperability)
    nonce = os.urandom(16)
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Integrity (HMAC over critical fields)
    mac_msg = _text_mac_message(iv, ciphertext, enc_aes_key, nonce, r, x0)
    tag = hmac.new(aes_key, mac_msg, hashlib.sha256).digest()

    return {
        "version": PAYLOAD_VERSION,
        "suite": PAYLOAD_SUITE,
        "created_at": created_at,
        "nonce_b64": base64.b64encode(nonce).decode(),
        "chaos_masked_b64": base64.b64encode(chaos_masked).decode(),
        "iv_b64": base64.b64encode(iv).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "enc_aes_key_b64": base64.b64encode(enc_aes_key).decode(),
        "chaos_r": r,
        "chaos_x0": x0,
        "hmac_b64": base64.b64encode(tag).decode(),
    }


def decrypt_text(payload: dict, private_key) -> str:
    """
    Decrypt a payload produced by encrypt_text().

    Parameters:
        payload     : dict returned by encrypt_text
        private_key : RSA private key (RsaKey)

    Returns:
        recovered plaintext string
    """
    iv = base64.b64decode(payload["iv_b64"])
    ciphertext = base64.b64decode(payload["ciphertext_b64"])
    enc_aes_key = base64.b64decode(payload["enc_aes_key_b64"])
    r = payload["chaos_r"]
    x0 = payload["chaos_x0"]

    nonce = base64.b64decode(payload.get("nonce_b64", "")) if payload.get("nonce_b64") else b""

    # Layer 3 reverse: RSA decrypt AES key
    aes_key = rsa_decrypt(enc_aes_key, private_key)

    # Integrity check (if present)
    if "hmac_b64" in payload:
        tag = base64.b64decode(payload["hmac_b64"])
        mac_msg = _text_mac_message(iv, ciphertext, enc_aes_key, nonce, r, x0)
        expected = hmac.new(aes_key, mac_msg, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("Integrity check failed (HMAC mismatch). Payload may be corrupted or tampered.")

    # Layer 2 reverse: AES decrypt
    chaos_masked = aes_decrypt(iv, ciphertext, aes_key)

    # Layer 1 reverse: remove chaos mask (XOR is self-inverse)
    raw = remove_chaos_mask(chaos_masked, r, x0)

    return raw.decode("utf-8")


def payload_to_json(payload: dict) -> str:
    """Serialise payload to a JSON string for transmission / display."""
    return json.dumps(payload, indent=2)


def payload_from_json(json_str: str) -> dict:
    """Deserialise payload from a JSON string."""
    return json.loads(json_str)
