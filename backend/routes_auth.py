"""
routes_auth.py – /api/auth/register and /api/auth/login endpoints.
"""
from __future__ import annotations

from flask import Blueprint, request, jsonify
from models import db, User
from auth import hash_password, verify_password, generate_token

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


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
    return jsonify({"token": token, "user_id": user.id}), 201


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
    return jsonify({"token": token, "user_id": user.id}), 200
