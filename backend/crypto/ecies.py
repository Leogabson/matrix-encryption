"""
ecies.py – Ephemeral ECDH (P-256) + AES-256-GCM key wrapping.

ECIES pattern
-------------
To wrap a secret key for a recipient whose P-256 public key we hold:

  1. Generate an ephemeral P-256 keypair (server-side, in-memory only).
  2. Perform ECDH: shared_point = eph_priv * recipient_pub
  3. Derive a 32-byte wrapping key via HKDF-SHA256 from the shared point.
  4. AES-256-GCM encrypt the secret with the derived key.
  5. Bundle the ephemeral public key (as JWK) + ciphertext + iv + tag into a JSON blob.
  6. The ephemeral private key is discarded immediately after step 3.

The recipient can reverse the process:
  1. Import the ephemeral public key from the blob.
  2. ECDH: shared_point = recipient_priv * eph_pub  (same shared point)
  3. HKDF-SHA256 → same wrapping key.
  4. AES-256-GCM decrypt → recover the session key.

This is all done in the browser with the Web Crypto API (see Prompt 3).

Public API
----------
wrap_key(recipient_pub_jwk_str: str, plaintext_key: bytes) -> dict
    Returns { eph_pub_jwk, ciphertext_b64, iv_b64, tag_b64 }.
"""

from __future__ import annotations
import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    EllipticCurvePublicNumbers,
    EllipticCurvePrivateKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------------
# JWK ↔ cryptography helpers
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    """Decode a Base64url string (no padding required)."""
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))


def _b64url_encode(b: bytes) -> str:
    """Encode bytes as Base64url without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _load_p256_pub_from_jwk(jwk_str: str):
    """Parse a P-256 public key from a JWK JSON string.

    Supports the JWK format produced by the Web Crypto API's exportKey('jwk').

    Parameters
    ----------
    jwk_str : str
        JSON string with at least { kty, crv, x, y } fields.

    Returns
    -------
    cryptography EllipticCurvePublicKey (SECP256R1)
    """
    jwk = json.loads(jwk_str)
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("JWK must be an EC P-256 public key (kty='EC', crv='P-256')")

    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")

    pub_numbers = EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256R1())
    return pub_numbers.public_key(default_backend())


def _export_pub_as_jwk(private_key: EllipticCurvePrivateKey) -> dict:
    """Export the *public* component of a P-256 private key as a JWK dict."""
    pub = private_key.public_key()
    nums = pub.public_numbers()
    coord_len = 32  # P-256 coordinates are 32 bytes each
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(nums.x.to_bytes(coord_len, "big")),
        "y": _b64url_encode(nums.y.to_bytes(coord_len, "big")),
        "key_ops": [],
        "ext": True,
    }


# ---------------------------------------------------------------------------
# HKDF helper
# ---------------------------------------------------------------------------

def _derive_wrapping_key(shared_secret: bytes) -> bytes:
    """Derive a 32-byte AES key from a raw ECDH shared secret via HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"matrix-encryption-session-key-wrap",
        backend=default_backend(),
    )
    return hkdf.derive(shared_secret)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def wrap_key(recipient_pub_jwk_str: str, plaintext_key: bytes) -> dict:
    """Wrap *plaintext_key* for the recipient identified by their P-256 public JWK.

    Parameters
    ----------
    recipient_pub_jwk_str : str
        The JWK JSON string stored in User.public_key.
    plaintext_key : bytes
        The raw session AES key to wrap (typically 32 bytes).

    Returns
    -------
    dict with keys: eph_pub_jwk (dict), ciphertext_b64 (str), iv_b64 (str), tag_b64 (str).

    Security notes
    --------------
    * A fresh ephemeral keypair is generated for every call → perfect forward
      secrecy: each wrapped blob is protected by a unique ephemeral secret.
    * The ephemeral private key is never stored or returned.
    """
    # 1. Load recipient's static public key
    recipient_pub = _load_p256_pub_from_jwk(recipient_pub_jwk_str)

    # 2. Generate ephemeral keypair (in-memory, never persisted)
    eph_priv = generate_private_key(SECP256R1(), default_backend())

    # 3. ECDH → raw shared secret bytes
    shared_secret: bytes = eph_priv.exchange(ECDH(), recipient_pub)

    # 4. HKDF → 32-byte wrapping key
    wrapping_key = _derive_wrapping_key(shared_secret)
    del shared_secret  # discard immediately

    # 5. AES-256-GCM encrypt the plaintext_key
    aesgcm = AESGCM(wrapping_key)
    iv = os.urandom(12)
    ct_with_tag = aesgcm.encrypt(iv, plaintext_key, None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    del wrapping_key  # discard immediately

    # 6. Export ephemeral public key as JWK (recipient needs it to re-derive the secret)
    eph_pub_jwk = _export_pub_as_jwk(eph_priv)
    del eph_priv  # ephemeral private key discarded

    return {
        "eph_pub_jwk":    eph_pub_jwk,
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "iv_b64":         base64.b64encode(iv).decode(),
        "tag_b64":        base64.b64encode(tag).decode(),
    }
