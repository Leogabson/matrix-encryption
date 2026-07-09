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
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    author = db.relationship("User", back_populates="messages")

    def __repr__(self) -> str:
        return f"<Message id={self.id} user_id={self.user_id}>"
