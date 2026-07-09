"""
AES-GCM encrypt / decrypt helpers using the `cryptography` library.

Usage
-----
key = aes_generate_key()          # 256-bit key (bytes)
ct, iv, tag = aes_encrypt(key, b"hello")
pt = aes_decrypt(key, ct, iv, tag)
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aes_generate_key() -> bytes:
    """Return a random 256-bit AES key."""
    return os.urandom(32)


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """Encrypt *plaintext* with AES-256-GCM.

    Returns
    -------
    (ciphertext, iv, tag)
        All three values are raw bytes.
        The 16-byte authentication tag is stripped from ciphertext automatically
        by the AESGCM wrapper – but we keep the interface explicit for clarity.
    """
    aesgcm = AESGCM(key)
    iv = os.urandom(12)  # 96-bit nonce recommended for GCM
    # AESGCM.encrypt returns ciphertext || tag (last 16 bytes)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, aad)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return ciphertext, iv, tag


def aes_decrypt(key: bytes, ciphertext: bytes, iv: bytes, tag: bytes, aad: bytes | None = None) -> bytes:
    """Decrypt and verify *ciphertext* encrypted with :func:`aes_encrypt`."""
    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + tag
    return aesgcm.decrypt(iv, ct_with_tag, aad)
