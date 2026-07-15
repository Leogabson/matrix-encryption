"""
hill_keygen.py – Random valid Hill Cipher key-matrix generator.

A Hill key matrix must be square and invertible mod 26, i.e.
gcd(det(M), 26) == 1.  Since 26 = 2 × 13, this requires the determinant
to be odd AND not divisible by 13.

Usage
-----
from crypto.hill_keygen import generate_hill_key
matrix = generate_hill_key(n=3)   # returns a list[list[int]]
"""

from __future__ import annotations
import os
import math
import numpy as np


_MOD = 26


def _det_mod26(matrix: np.ndarray) -> int:
    """Return det(matrix) mod 26 as a non-negative integer."""
    det = int(round(np.linalg.det(matrix))) % _MOD
    return det % _MOD  # ensure positive


def generate_hill_key(n: int = 3) -> list[list[int]]:
    """Return a random n×n integer matrix (entries 0-25) invertible mod 26.

    Parameters
    ----------
    n : int
        Dimension of the square key matrix (default 3).

    Returns
    -------
    list[list[int]]
        Nested-list of Python ints, safe for JSON serialisation.

    Notes
    -----
    The function re-samples until a valid matrix is found.  For n=3 roughly
    1-in-5 random matrices are invertible mod 26, so convergence is fast
    (typically < 10 iterations).
    """
    if n < 2:
        raise ValueError("Hill matrix dimension must be >= 2")

    rng = np.random.default_rng(int.from_bytes(os.urandom(4), "little"))

    while True:
        mat = rng.integers(0, _MOD, size=(n, n))
        det = _det_mod26(mat)
        if det != 0 and math.gcd(int(det), _MOD) == 1:
            # Valid: det is coprime to 26 → matrix is invertible mod 26
            return mat.tolist()
