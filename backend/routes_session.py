"""
routes_session.py – Session creation endpoint + Socket.IO push.

Blueprint: session_bp, prefix /api/session.

Endpoints
---------
POST /api/session/start
    Body: { "participant_username": "alice" }
    Auth: Authorization: Bearer <token>

GET /api/session/pending
    Auth: Authorization: Bearer <token>
    Returns all sessions where the caller is initiator or participant,
    with the correct wrapped-key blob for their role.
"""

from __future__ import annotations
import json
import os

from flask import Blueprint, request, jsonify

from auth import verify_token
from models import db, User, ConversationSession
from crypto import generate_hill_key, wrap_key

session_bp = Blueprint("session", __name__, url_prefix="/api/session")

# Will be injected by init_session_routes(socketio) called from app.py
_socketio = None


def init_session_routes(socketio) -> None:
    """Bind the SocketIO instance so this blueprint can emit events."""
    global _socketio
    _socketio = socketio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bearer_token() -> str | None:
    """Extract the Bearer token from the current request headers."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth.removeprefix("Bearer ")
    return None


# ---------------------------------------------------------------------------
# GET /api/session/pending
# ---------------------------------------------------------------------------

@session_bp.get("/pending")
def pending_sessions():
    """Return all sessions the caller is involved in, with the correct wrapped blob.

    Each item in the returned list includes the wrapped_key blob that belongs
    to this user (initiator gets wrapped_key_initiator, participant gets
    wrapped_key_participant).
    """
    token = _bearer_token()
    if not token:
        return jsonify({"error": "Missing or invalid Authorization header."}), 401

    user_id = verify_token(token)
    if user_id is None:
        return jsonify({"error": "Token invalid or expired."}), 401

    # Fetch all sessions where this user is involved
    stmt = db.select(ConversationSession).where(
        db.or_(
            ConversationSession.initiator_id == user_id,
            ConversationSession.participant_id == user_id,
        )
    ).order_by(ConversationSession.created_at.desc())

    sessions = db.session.execute(stmt).scalars().all()

    result = []
    for s in sessions:
        # Determine which wrapped blob belongs to this user
        is_initiator = (s.initiator_id == user_id)
        wrapped_key_json = s.wrapped_key_initiator if is_initiator else s.wrapped_key_participant

        # Resolve the other party's username for display
        other_id = s.participant_id if is_initiator else s.initiator_id
        other_user = db.session.get(User, other_id)
        initiator_user = db.session.get(User, s.initiator_id)

        result.append({
            "session_id":              s.id,
            "status":                  s.status,
            "hill_matrix_fingerprint": json.loads(s.hill_matrix_fingerprint),
            "initiator_username":      initiator_user.username if initiator_user else str(s.initiator_id),
            "other_username":          other_user.username if other_user else str(other_id),
            "is_initiator":            is_initiator,
            "wrapped_key":             json.loads(wrapped_key_json),
            "created_at":              s.created_at.isoformat(),
        })

    return jsonify(result), 200



# ---------------------------------------------------------------------------
# POST /api/session/start
# ---------------------------------------------------------------------------

@session_bp.post("/start")
def start_session():
    """Create a new encrypted session between the caller and another user.

    Returns
    -------
    201 JSON:
        {
            "session_id": int,
            "hill_matrix_fingerprint": list[list[int]],
            "wrapped_key": { eph_pub_jwk, ciphertext_b64, iv_b64, tag_b64 }
        }
    """
    # ── 1. Authenticate initiator ─────────────────────────────────────────
    token = _bearer_token()
    if not token:
        return jsonify({"error": "Missing or invalid Authorization header."}), 401

    initiator_id = verify_token(token)
    if initiator_id is None:
        return jsonify({"error": "Token invalid or expired."}), 401

    # ── 2. Resolve users ──────────────────────────────────────────────────
    data = request.get_json(silent=True) or {}
    participant_username = (data.get("participant_username") or "").strip()
    if not participant_username:
        return jsonify({"error": "participant_username is required."}), 400

    initiator = db.session.get(User, initiator_id)
    if initiator is None:
        return jsonify({"error": "Initiator user not found."}), 404

    participant = db.session.execute(
        db.select(User).where(User.username == participant_username)
    ).scalar_one_or_none()

    if participant is None:
        return jsonify({"error": f"User '{participant_username}' not found."}), 404

    if participant.id == initiator_id:
        return jsonify({"error": "Cannot start a session with yourself."}), 400

    if not initiator.public_key:
        return jsonify({"error": "Your ECDH public key has not been uploaded yet."}), 422

    if not participant.public_key:
        return jsonify(
            {"error": f"User '{participant_username}' has not uploaded their public key yet."}
        ), 422

    # ── 3. Generate Hill matrix fingerprint ───────────────────────────────
    hill_matrix: list[list[int]] = generate_hill_key(n=3)

    # ── 4. Generate session AES-256 key ───────────────────────────────────
    session_key: bytes = os.urandom(32)

    # ── 5. ECIES-wrap the session key for each participant ────────────────
    try:
        wrapped_initiator   = wrap_key(initiator.public_key,   session_key)
        wrapped_participant = wrap_key(participant.public_key, session_key)
    except Exception as exc:
        # Discard the raw key even on failure paths
        del session_key
        return jsonify({"error": f"Key wrapping failed: {exc}"}), 500

    # ── 6. Discard raw session key ────────────────────────────────────────
    del session_key  # raw key no longer needed

    # ── 7. Persist ConversationSession ────────────────────────────────────
    session_row = ConversationSession(
        initiator_id=initiator_id,
        participant_id=participant.id,
        wrapped_key_initiator=json.dumps(wrapped_initiator),
        wrapped_key_participant=json.dumps(wrapped_participant),
        hill_matrix_fingerprint=json.dumps(hill_matrix),
        status="pending",
    )
    db.session.add(session_row)
    db.session.commit()
    db.session.refresh(session_row)

    # ── 8. Emit Socket.IO "new_session" to participant's room ─────────────
    if _socketio is not None:
        _socketio.emit(
            "new_session",
            {
                "session_id":             session_row.id,
                "initiator_username":     initiator.username,
                "hill_matrix_fingerprint": hill_matrix,
                "wrapped_key":            wrapped_participant,
                "created_at":             session_row.created_at.isoformat(),
            },
            room=f"user_{participant.id}",
        )

    # ── 9. Return session_id + initiator's wrapped blob ───────────────────
    return jsonify(
        {
            "session_id":             session_row.id,
            "hill_matrix_fingerprint": hill_matrix,
            "wrapped_key":            wrapped_initiator,
            "created_at":             session_row.created_at.isoformat(),
        }
    ), 201
