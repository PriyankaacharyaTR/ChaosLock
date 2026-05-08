"""
image_crypto.py — Chaos + AES + RSA image encryption/decryption
"""

import io
import base64
import os
import hmac
import hashlib
from datetime import datetime, timezone

import numpy as np
from PIL import Image

from chaos import chaos_matrix
from aes_util import generate_aes_key, aes_encrypt, aes_decrypt
from rsa_util import rsa_encrypt, rsa_decrypt


DEFAULT_R = 3.99
DEFAULT_X0 = 0.5


PAYLOAD_VERSION = 1
PAYLOAD_SUITE = "CHAOS_XOR(PIXELS) + AES-256-CBC + RSA-OAEP + HMAC-SHA256"


def _format_float(f: float) -> bytes:
    return ("%.10f" % float(f)).encode("utf-8")


def _image_mac_message(
    iv: bytes,
    ciphertext: bytes,
    enc_aes_key: bytes,
    nonce: bytes,
    r: float,
    x0: float,
    shape: tuple,
) -> bytes:
    shape_bytes = ("x".join(str(int(x)) for x in shape)).encode("utf-8")
    return b"|".join([iv, ciphertext, enc_aes_key, nonce, _format_float(r), _format_float(x0), shape_bytes])


# ── helpers ──────────────────────────────────────────────────────────────────

def pil_to_array(img: Image.Image) -> np.ndarray:
    """Convert PIL Image to uint8 numpy array (RGB or RGBA)."""
    return np.array(img.convert("RGB"), dtype=np.uint8)


def array_to_pil(arr: np.ndarray) -> Image.Image:
    """Convert uint8 numpy array to PIL Image."""
    return Image.fromarray(arr.astype(np.uint8))


def array_to_bytes(arr: np.ndarray) -> bytes:
    """Serialise numpy array to bytes (preserves shape/dtype)."""
    buf = io.BytesIO()
    np.save(buf, arr)
    return buf.getvalue()


def bytes_to_array(raw: bytes) -> np.ndarray:
    """Deserialise numpy array from bytes."""
    buf = io.BytesIO(raw)
    return np.load(buf)


# ── core ─────────────────────────────────────────────────────────────────────

def apply_chaos_to_image(arr: np.ndarray, r: float, x0: float) -> np.ndarray:
    """
    XOR every pixel channel value with a chaos sequence.
    Shape-agnostic: works for (H,W,C) or (H,W).
    Calling twice with same params recovers original.
    """
    mask = chaos_matrix(r, x0, arr.shape)
    return (arr.astype(np.uint16) ^ mask.astype(np.uint16)).astype(np.uint8)


def encrypt_image(
    img: Image.Image,
    public_key,
    r: float = DEFAULT_R,
    x0: float = DEFAULT_X0,
) -> dict:
    """
    Encrypt a PIL image.

    Returns a dict:
        chaos_img_b64   : base64 PNG of the chaos-scrambled image (for display)
        iv_b64          : base64 AES IV
        ciphertext_b64  : base64 AES ciphertext
        enc_aes_key_b64 : base64 RSA-encrypted AES key
        shape           : image shape tuple
        chaos_r / chaos_x0
    """
    arr = pil_to_array(img)
    shape = arr.shape

    # Layer 1: chaos pixel masking
    chaos_arr = apply_chaos_to_image(arr, r, x0)
    chaos_pil = array_to_pil(chaos_arr)

    # Serialise chaos image for display (base64 PNG)
    buf = io.BytesIO()
    chaos_pil.save(buf, format="PNG")
    chaos_img_b64 = base64.b64encode(buf.getvalue()).decode()

    # Layer 2: AES encrypt the chaos-scrambled pixel bytes
    raw_bytes = array_to_bytes(chaos_arr)
    aes_key = generate_aes_key()
    iv, ciphertext = aes_encrypt(raw_bytes, aes_key)

    # Layer 3: RSA encrypt AES key
    enc_aes_key = rsa_encrypt(aes_key, public_key)

    # Metadata
    nonce = os.urandom(16)
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Integrity (HMAC)
    mac_msg = _image_mac_message(iv, ciphertext, enc_aes_key, nonce, r, x0, shape)
    tag = hmac.new(aes_key, mac_msg, hashlib.sha256).digest()

    return {
        "version": PAYLOAD_VERSION,
        "suite": PAYLOAD_SUITE,
        "created_at": created_at,
        "nonce_b64": base64.b64encode(nonce).decode(),
        "chaos_img_b64": chaos_img_b64,
        "iv_b64": base64.b64encode(iv).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "enc_aes_key_b64": base64.b64encode(enc_aes_key).decode(),
        "shape": list(shape),
        "chaos_r": r,
        "chaos_x0": x0,
        "hmac_b64": base64.b64encode(tag).decode(),
    }


def decrypt_image(payload: dict, private_key) -> Image.Image:
    """
    Decrypt a payload produced by encrypt_image().

    Returns:
        recovered PIL Image
    """
    iv = base64.b64decode(payload["iv_b64"])
    ciphertext = base64.b64decode(payload["ciphertext_b64"])
    enc_aes_key = base64.b64decode(payload["enc_aes_key_b64"])
    r = payload["chaos_r"]
    x0 = payload["chaos_x0"]
    shape = tuple(payload.get("shape", []))

    nonce = base64.b64decode(payload.get("nonce_b64", "")) if payload.get("nonce_b64") else b""

    # Reverse layer 3: RSA decrypt AES key
    aes_key = rsa_decrypt(enc_aes_key, private_key)

    # Integrity check (if present)
    if "hmac_b64" in payload:
        tag = base64.b64decode(payload["hmac_b64"])
        mac_msg = _image_mac_message(iv, ciphertext, enc_aes_key, nonce, r, x0, shape)
        expected = hmac.new(aes_key, mac_msg, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("Integrity check failed (HMAC mismatch). Payload may be corrupted or tampered.")

    # Reverse layer 2: AES decrypt
    raw_bytes = aes_decrypt(iv, ciphertext, aes_key)
    chaos_arr = bytes_to_array(raw_bytes)

    # Reverse layer 1: remove chaos masking
    recovered_arr = apply_chaos_to_image(chaos_arr, r, x0)
    return array_to_pil(recovered_arr)


def chaos_image_from_payload(payload: dict) -> Image.Image:
    """Return the chaos-scrambled image stored in a payload (for display)."""
    raw = base64.b64decode(payload["chaos_img_b64"])
    return Image.open(io.BytesIO(raw))
