"""
Hill Cipher – matrix-based polygraphic substitution.

Only supports uppercase A-Z (26-char alphabet).
Key matrix must be square and invertible mod 26.

Usage
-----
key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]  # 3×3 example
ct = hill_encrypt("ACT", key_matrix)
pt = hill_decrypt(ct, key_matrix)
"""

from __future__ import annotations
import numpy as np

_MOD = 26
_ORD_A = ord("A")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _text_to_vector(text: str) -> list[int]:
    """Map uppercase chars → 0-25."""
    return [ord(c) - _ORD_A for c in text.upper() if c.isalpha()]


def _vector_to_text(vec: list[int]) -> str:
    return "".join(chr(v % _MOD + _ORD_A) for v in vec)


def _cofactor(matrix: np.ndarray, row: int, col: int) -> int:
    """Return the (row, col) cofactor of *matrix* using exact integer arithmetic."""
    minor = np.delete(np.delete(matrix, row, axis=0), col, axis=1)
    # Compute determinant via numpy then round to nearest int (exact for integer matrices)
    sign = (-1) ** (row + col)
    return sign * int(round(np.linalg.det(minor)))


def _mod_matrix_inverse(matrix: np.ndarray, mod: int) -> np.ndarray:
    """Compute the modular inverse of a square integer matrix mod *mod*.

    Uses the classical adjugate (cofactor matrix transposed) built via exact
    integer cofactor expansion – no floating-point adjugate scaling that would
    accumulate rounding errors.
    """
    n = matrix.shape[0]
    det = int(round(np.linalg.det(matrix))) % mod
    det_inv = pow(det, -1, mod)  # raises ValueError if gcd(det, mod) != 1

    # Build adjugate = transpose of cofactor matrix, all integers
    adjugate = np.zeros((n, n), dtype=int)
    for r in range(n):
        for c in range(n):
            adjugate[c][r] = _cofactor(matrix, r, c)  # transposed: [c][r]

    return (det_inv * adjugate % mod).astype(int)


def _apply_key(text: str, key_matrix: list[list[int]], inverse: bool = False) -> str:
    n = len(key_matrix)
    key = np.array(key_matrix, dtype=int)
    mat = _mod_matrix_inverse(key, _MOD) if inverse else key

    nums = _text_to_vector(text)
    # Pad to multiple of n
    while len(nums) % n:
        nums.append(0)  # pad with 'A'

    result: list[int] = []
    for i in range(0, len(nums), n):
        block = np.array(nums[i : i + n])
        out = (mat @ block) % _MOD
        result.extend(out.tolist())
    return _vector_to_text(result)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def hill_encrypt(plaintext: str, key_matrix: list[list[int]]) -> str:
    """Encrypt *plaintext* (alpha chars only) using *key_matrix*."""
    return _apply_key(plaintext, key_matrix, inverse=False)


def hill_decrypt(ciphertext: str, key_matrix: list[list[int]]) -> str:
    """Decrypt *ciphertext* (alpha chars only) using *key_matrix*."""
    return _apply_key(ciphertext, key_matrix, inverse=True)
