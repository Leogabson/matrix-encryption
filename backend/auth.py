"""
Authentication helpers – password hashing and JWT-style session tokens.
Uses Werkzeug's scrypt-based pbkdf2 hashing (no extra deps needed).
"""

from __future__ import annotations
import os
import hmac
import hashlib
import base64
import json
from datetime import datetime, timedelta, timezone

from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Return a salted hash suitable for storage."""
    return generate_password_hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Return True if *password* matches *stored_hash*."""
    return check_password_hash(stored_hash, password)


# ---------------------------------------------------------------------------
# Simple HMAC token (replaces JWT to keep deps minimal)
# ---------------------------------------------------------------------------
#   Token format: base64url( JSON_payload ) + "." + base64url( HMAC-SHA256 )

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))


def generate_token(user_id: int, expiry_hours: int = 24) -> str:
    """Create a signed session token for *user_id*."""
    secret = current_app.config["SECRET_KEY"].encode()
    payload = json.dumps(
        {
            "sub": user_id,
            "exp": (datetime.now(timezone.utc) + timedelta(hours=expiry_hours)).isoformat(),
        }
    ).encode()
    sig = hmac.new(secret, _b64(payload).encode(), hashlib.sha256).digest()
    return f"{_b64(payload)}.{_b64(sig)}"


def verify_token(token: str) -> int | None:
    """Validate token; return user_id or None if invalid/expired."""
    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except ValueError:
        return None
    secret = current_app.config["SECRET_KEY"].encode()
    expected_sig = hmac.new(secret, payload_b64.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(_unb64(sig_b64), expected_sig):
        return None
    try:
        data = json.loads(_unb64(payload_b64))
        exp = datetime.fromisoformat(data["exp"])
        if datetime.now(timezone.utc) > exp:
            return None
        return int(data["sub"])
    except (KeyError, ValueError, json.JSONDecodeError):
        return None
