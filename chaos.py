"""
chaos.py — Chaos sequence generator using Logistic Map
"""

import numpy as np


def logistic_map(r: float, x0: float, n: int) -> np.ndarray:
    """
    Generate n values from the Logistic Map:
        x(n+1) = r * x(n) * (1 - x(n))

    Parameters:
        r  : control parameter (3.9 < r <= 4.0 gives chaotic behaviour)
        x0 : initial seed, must be in (0, 1)
        n  : number of values to generate

    Returns:
        numpy array of n float values in (0, 1)
    """
    if not (0 < x0 < 1):
        raise ValueError("x0 must be strictly between 0 and 1")
    if not (0 < r <= 4.0):
        raise ValueError("r must be in (0, 4]")

    seq = np.empty(n, dtype=np.float64)
    x = x0
    for i in range(n):
        x = r * x * (1.0 - x)
        seq[i] = x
    return seq


def chaos_bytes(r: float, x0: float, n: int) -> np.ndarray:
    """
    Convert a logistic-map sequence to uint8 values (0-255).

    Parameters:
        r, x0 : logistic map parameters
        n     : number of bytes needed

    Returns:
        numpy uint8 array of length n
    """
    seq = logistic_map(r, x0, n)
    return (seq * 255).astype(np.uint8)


def apply_chaos_mask(data: bytes, r: float, x0: float) -> bytes:
    """
    XOR every byte of *data* with the chaos sequence.
    Calling twice with the same (r, x0) recovers the original (XOR is self-inverse).

    Parameters:
        data  : plaintext or ciphertext bytes
        r, x0 : chaos parameters (must be the same for mask & unmask)

    Returns:
        bytes of the same length
    """
    key_stream = chaos_bytes(r, x0, len(data))
    masked = bytes(b ^ k for b, k in zip(data, key_stream))
    return masked


# Alias so callers can write remove_chaos_mask or apply_chaos_mask
remove_chaos_mask = apply_chaos_mask


def chaos_matrix(r: float, x0: float, shape: tuple) -> np.ndarray:
    """
    Build a 2-D uint8 chaos matrix for image masking.

    Parameters:
        r, x0 : logistic map parameters
        shape : (rows, cols) or (rows, cols, channels)

    Returns:
        uint8 numpy array of the requested shape
    """
    total = int(np.prod(shape))
    flat = chaos_bytes(r, x0, total)
    return flat.reshape(shape)
