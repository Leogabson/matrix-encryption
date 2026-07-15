"""
routes_auth.py – /api/auth/register, /api/auth/login, and /api/auth/set_public_key endpoints.
"""
from __future__ import annotations

import hashlib
import base64
from flask import Blueprint, request, jsonify, current_app
from models import db, User
from auth import hash_password, verify_password, generate_token, verify_token

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _get_room_key() -> str:
    """Derive a static 32-byte AES key from the server's SECRET_KEY.
    All authenticated users on this server will share this key to talk in the Global Room.
    """
    secret = current_app.config["SECRET_KEY"].encode()
    derived = hashlib.sha256(secret).digest()
    return base64.b64encode(derived).decode()


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters."}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400

    existing = db.session.execute(
        db.select(User).where(User.username == username)
    ).scalar_one_or_none()
    if existing:
        return jsonify({"error": "Username already taken."}), 409

    user = User(username=username, password_hash=hash_password(password))
    db.session.add(user)
    db.session.commit()
    db.session.refresh(user)

    token = generate_token(user.id)
    return jsonify({
        "token": token,
        "user_id": user.id,
        "username": user.username,
        "aes_key": _get_room_key(),
        "has_public_key": bool(user.public_key),
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    user = db.session.execute(
        db.select(User).where(User.username == username)
    ).scalar_one_or_none()

    if not user or not verify_password(password, user.password_hash):
        return jsonify({"error": "Invalid username or password."}), 401

    token = generate_token(user.id)
    return jsonify({
        "token": token,
        "user_id": user.id,
        "username": user.username,
        "aes_key": _get_room_key(),
        "has_public_key": bool(user.public_key),
    }), 200


@auth_bp.route("/set_public_key", methods=["POST"])
def set_public_key():
    """Receive and store the client's ECDH P-256 public key (JWK JSON string).

    The client must send:
        Authorization: Bearer <token>
        Content-Type: application/json
        { "public_key": "{...JWK...}" }
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header."}), 401

    token = auth_header.removeprefix("Bearer ")
    user_id = verify_token(token)
    if user_id is None:
        return jsonify({"error": "Token invalid or expired."}), 401

    data = request.get_json(silent=True) or {}
    public_key = data.get("public_key", "").strip()
    if not public_key:
        return jsonify({"error": "public_key is required."}), 400

    user = db.session.get(User, user_id)
    if user is None:
        return jsonify({"error": "User not found."}), 404

    user.public_key = public_key
    db.session.commit()
    return jsonify({"ok": True}), 200


@auth_bp.get("/users")
def list_users():
    """Return all registered users except the caller.

    Used by the client-side user picker when starting a secure session.
    Includes has_public_key so the UI can disable users who can't
    participate in an ECIES-wrapped session.

    Auth: Authorization: Bearer <token>
    Response: [{ id, username, has_public_key }]
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header."}), 401

    token = auth_header.removeprefix("Bearer ")
    caller_id = verify_token(token)
    if caller_id is None:
        return jsonify({"error": "Token invalid or expired."}), 401

    users = db.session.execute(
        db.select(User).where(User.id != caller_id).order_by(User.username)
    ).scalars().all()

    return jsonify([
        {
            "id":             u.id,
            "username":       u.username,
            "has_public_key": bool(u.public_key),
        }
        for u in users
    ]), 200
