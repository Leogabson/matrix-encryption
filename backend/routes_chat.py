"""
Chat blueprint – REST endpoints + Socket.IO events for encrypted messaging.
Imported and registered in app.py.
"""

from flask import Blueprint, jsonify, request
from flask_socketio import emit, join_room

from models import db, Message
from auth import verify_token

chat_bp = Blueprint("chat", __name__, url_prefix="/api/chat")


# ---------------------------------------------------------------------------
# REST: message history
# ---------------------------------------------------------------------------

@chat_bp.get("/history")
def history():
    """Return the last 50 messages (ciphertext blobs only – client decrypts)."""
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
                "id": m.id,
                "user_id": m.user_id,
                "ciphertext": m.ciphertext_b64,
                "iv": m.iv_b64,
                "tag": m.tag_b64,
                "timestamp": m.timestamp.isoformat(),
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
            { token, ciphertext_b64, iv_b64, tag_b64 }
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

        msg = Message(
            user_id=user_id,
            ciphertext_b64=ciphertext_b64,
            iv_b64=iv_b64,
            tag_b64=tag_b64,
        )
        db.session.add(msg)
        db.session.commit()
        # Refresh to guarantee server-generated values (id, timestamp) are loaded
        db.session.refresh(msg)

        # Broadcast to all connected clients
        socketio.emit(
            "new_message",
            {
                "id": msg.id,
                "user_id": msg.user_id,
                "ciphertext": msg.ciphertext_b64,
                "iv": msg.iv_b64,
                "tag": msg.tag_b64,
                "timestamp": msg.timestamp.isoformat(),
            },
        )
