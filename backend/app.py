"""
app.py – application factory and entry-point.

Run:
    cd backend
    python app.py
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, send_from_directory
from flask_socketio import SocketIO

# Load .env from project root (one level up from backend/)
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    frontend_dir = Path(__file__).resolve().parent.parent / "frontend"

    app = Flask(
        __name__,
        static_folder=str(frontend_dir / "assets"),
        static_url_path="/assets",
    )

    # ------- configuration ---------------------------------------------------
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{Path(__file__).resolve().parent / 'app.db'}",
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ------- extensions ------------------------------------------------------
    from models import db
    db.init_app(app)

    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode="threading",
        logger=False,
        engineio_logger=False,
    )

    # ------- blueprints ------------------------------------------------------
    from routes_auth import auth_bp
    from routes_chat import chat_bp, register_socketio_events
    from routes_cipherlab import cipherlab_bp
    from routes_session import session_bp, init_session_routes

    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(cipherlab_bp)
    app.register_blueprint(session_bp)
    register_socketio_events(socketio)
    init_session_routes(socketio)

    # ------- database init ---------------------------------------------------
    with app.app_context():
        db.create_all()

    # ------- frontend routes -------------------------------------------------
    @app.route("/")
    def index():
        return send_from_directory(str(frontend_dir), "login.html")

    @app.route("/<path:page>")
    def serve_page(page: str):
        """Serve any .html page from the frontend directory."""
        return send_from_directory(str(frontend_dir), page)

    # ------- hello-world health check ----------------------------------------
    @app.route("/api/hello")
    def hello():
        return {"message": "Hello from Matrix Encryption API 👋", "socketio": "wired"}

    return app, socketio


# Instantiate globally for WSGI/Serverless deployment engines (like Vercel)
app, socketio = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"[OK] Server running at  http://127.0.0.1:{port}")
    print(f"[OK] Hello-world check: http://127.0.0.1:{port}/api/hello")
    socketio.run(app, host="0.0.0.0", port=port, debug=True, allow_unsafe_werkzeug=True)

