"""
Chat blueprint – REST endpoints + Socket.IO events for encrypted messaging.
Imported and registered in app.py.
"""

import json

from flask import Blueprint, jsonify, request
from flask_socketio import emit, join_room

from models import db, Message, ConversationSession
from auth import verify_token

chat_bp = Blueprint("chat", __name__, url_prefix="/api/chat")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fingerprint_for_session(session_id: int | None) -> list | None:
    """Return the Hill matrix fingerprint list for *session_id*, or None."""
    if session_id is None:
        return None
    row = db.session.get(ConversationSession, session_id)
    if row is None:
        return None
    try:
        return json.loads(row.hill_matrix_fingerprint)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# REST: message history
# ---------------------------------------------------------------------------

@chat_bp.get("/history")
def history():
    """Return the last 50 messages (ciphertext blobs only – client decrypts).

    Each item now includes session_id (null for Global Room) and
    hill_matrix_fingerprint (null for Global Room or if not found).
    """
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    if not verify_token(token):
        return jsonify({"error": "Unauthorized"}), 401

    stmt = (
        db.select(Message)
        .order_by(Message.timestamp.desc())
        .limit(50)
    )
    msgs = db.session.execute(stmt).scalars().all()

    return jsonify(
        [
            {
                "id":                    m.id,
                "user_id":               m.user_id,
                "ciphertext":            m.ciphertext_b64,
                "iv":                    m.iv_b64,
                "tag":                   m.tag_b64,
                "session_id":            m.session_id,
                "hill_matrix_fingerprint": _fingerprint_for_session(m.session_id),
                "timestamp":             m.timestamp.isoformat(),
            }
            for m in reversed(msgs)
        ]
    )


# ---------------------------------------------------------------------------
# Socket.IO event handlers (registered in app.py via socketio.on_event)
# ---------------------------------------------------------------------------

def register_socketio_events(socketio):
    """Attach Socket.IO handlers to the *socketio* instance."""

    @socketio.on("connect")
    def on_connect(auth):
        token = (auth or {}).get("token", "")
        user_id = verify_token(token)
        if not user_id:
            return False  # reject connection
        join_room(f"user_{user_id}")
        emit("connected", {"status": "ok", "user_id": user_id})

    @socketio.on("disconnect")
    def on_disconnect():
        pass  # rooms are cleaned up automatically

    @socketio.on("send_message")
    def on_send_message(data):
        """
        Expected payload:
            { token, ciphertext_b64, iv_b64, tag_b64, session_id? }

        session_id is optional. When present and non-null, the message was
        encrypted with the named session's AES key rather than the Global Room key.
        """
        if not isinstance(data, dict):
            emit("error", {"msg": "Invalid payload"})
            return

        user_id = verify_token(data.get("token", ""))
        if not user_id:
            emit("error", {"msg": "Unauthorized"})
            return

        # Guard against missing cipher fields
        try:
            ciphertext_b64 = data["ciphertext_b64"]
            iv_b64         = data["iv_b64"]
            tag_b64        = data["tag_b64"]
        except KeyError as exc:
            emit("error", {"msg": f"Missing field: {exc}"})
            return

        # Optional session_id — validate type; ignore if bogus
        raw_session_id = data.get("session_id")
        session_id: int | None = None
        if isinstance(raw_session_id, int) and raw_session_id > 0:
            session_id = raw_session_id

        # Look up fingerprint now (single query before the commit)
        fingerprint = _fingerprint_for_session(session_id)

        msg = Message(
            user_id=user_id,
            ciphertext_b64=ciphertext_b64,
            iv_b64=iv_b64,
            tag_b64=tag_b64,
            session_id=session_id,
        )
        db.session.add(msg)
        db.session.commit()
        # Refresh to guarantee server-generated values (id, timestamp) are loaded
        db.session.refresh(msg)

        # Broadcast to all connected clients (intentionally public — the ciphertext
        # is what provides confidentiality for session-scoped messages)
        socketio.emit(
            "new_message",
            {
                "id":                    msg.id,
                "user_id":               msg.user_id,
                "ciphertext":            msg.ciphertext_b64,
                "iv":                    msg.iv_b64,
                "tag":                   msg.tag_b64,
                "session_id":            msg.session_id,
                "hill_matrix_fingerprint": fingerprint,
                "timestamp":             msg.timestamp.isoformat(),
            },
        )
