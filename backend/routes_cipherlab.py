"""
CipherLab blueprint – REST endpoints for AES-GCM and Hill cipher operations.
Imported and registered in app.py.
"""

import base64

from flask import Blueprint, jsonify, request

from crypto import aes_encrypt, aes_decrypt, hill_encrypt, hill_decrypt

cipherlab_bp = Blueprint("cipherlab", __name__, url_prefix="/api/cipherlab")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# AES-GCM
# ---------------------------------------------------------------------------

@cipherlab_bp.post("/aes/encrypt")
def aes_enc():
    """
    Body: { "plaintext": "...", "key_b64": "..." (optional 32-byte key) }
    Returns: { "ciphertext_b64", "iv_b64", "tag_b64", "key_b64" }
    """
    body = request.get_json(force=True, silent=True) or {}
    plaintext = body.get("plaintext", "").encode()

    if "key_b64" in body:
        key = _unb64(body["key_b64"])
    else:
        from crypto.aes import aes_generate_key
        key = aes_generate_key()

    ct, iv, tag = aes_encrypt(key, plaintext)
    return jsonify(
        {
            "ciphertext_b64": _b64(ct),
            "iv_b64": _b64(iv),
            "tag_b64": _b64(tag),
            "key_b64": _b64(key),
        }
    )


@cipherlab_bp.post("/aes/decrypt")
def aes_dec():
    """
    Body: { "ciphertext_b64", "iv_b64", "tag_b64", "key_b64" }
    Returns: { "plaintext": "..." }
    """
    body = request.get_json(force=True, silent=True) or {}
    try:
        pt = aes_decrypt(
            _unb64(body["key_b64"]),
            _unb64(body["ciphertext_b64"]),
            _unb64(body["iv_b64"]),
            _unb64(body["tag_b64"]),
        )
        return jsonify({"plaintext": pt.decode()})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


# ---------------------------------------------------------------------------
# Hill Cipher
# ---------------------------------------------------------------------------

@cipherlab_bp.post("/hill/encrypt")
def hill_enc():
    """
    Body: { "plaintext": "ACT", "key_matrix": [[...], [...], [...]] }
    Returns: { "ciphertext": "..." }
    """
    body = request.get_json(force=True, silent=True) or {}
    try:
        ct = hill_encrypt(body["plaintext"], body["key_matrix"])
        return jsonify({"ciphertext": ct})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@cipherlab_bp.post("/hill/decrypt")
def hill_dec():
    """
    Body: { "ciphertext": "...", "key_matrix": [[...], [...], [...]] }
    Returns: { "plaintext": "..." }
    """
    body = request.get_json(force=True, silent=True) or {}
    try:
        pt = hill_decrypt(body["ciphertext"], body["key_matrix"])
        return jsonify({"plaintext": pt})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
