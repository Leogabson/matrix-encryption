"""
SQLAlchemy models – User and Message.
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    # ECDH P-256 public key stored as a JWK JSON string; set by the client after login/register.
    public_key = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    messages = db.relationship("Message", back_populates="author", lazy=True)

    def __repr__(self) -> str:
        return f"<User {self.username!r}>"


class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    ciphertext_b64 = db.Column(db.Text, nullable=False)   # base64-encoded AES-GCM output
    iv_b64 = db.Column(db.String(32), nullable=False)
    tag_b64 = db.Column(db.String(32), nullable=False)
    # Null → Global Room (shared AES key). Non-null → private session (ECIES session key).
    session_id = db.Column(db.Integer, db.ForeignKey("conversation_sessions.id"), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    author = db.relationship("User", back_populates="messages")

    def __repr__(self) -> str:
        return f"<Message id={self.id} user_id={self.user_id}>"


class ConversationSession(db.Model):
    """A private encrypted session between two users.

    The real session AES key is never stored here.  Each participant receives
    their own ECIES-wrapped blob from which they can locally derive the key.
    The Hill matrix is a *display fingerprint only* — not the session secret.
    """

    __tablename__ = "conversation_sessions"

    id = db.Column(db.Integer, primary_key=True)
    initiator_id   = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    participant_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # ECIES-wrapped session key blobs (JSON strings), one per participant.
    # Shape: { eph_pub_jwk: {...}, ciphertext_b64: "...", iv_b64: "...", tag_b64: "..." }
    wrapped_key_initiator   = db.Column(db.Text, nullable=False)
    wrapped_key_participant = db.Column(db.Text, nullable=False)

    # Plain NxN integer matrix stored as JSON — a display fingerprint, NOT the real secret.
    hill_matrix_fingerprint = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    status     = db.Column(db.String(20), nullable=False, default="pending")
    # status values: "pending" | "active" | "closed"

    initiator   = db.relationship("User", foreign_keys=[initiator_id])
    participant = db.relationship("User", foreign_keys=[participant_id])

    def __repr__(self) -> str:
        return (
            f"<ConversationSession id={self.id} "
            f"init={self.initiator_id} part={self.participant_id} "
            f"status={self.status!r}>"
        )
