# Matrix Encryption — Cryptographer's Desk 🕵️‍♂️📐

An interactive end-to-end encrypted chat room and cryptographic playground built with **Flask**, **Flask-SocketIO**, **SQLAlchemy**, and **SQLite** for the backend, and styled in a premium **"Cryptographer's Desk"** visual identity using plain HTML, CSS, and Vanilla JS.

---

## 🏛️ Visual Identity: "Cryptographer's Desk"

The application has been styled with a premium dark visual palette designed to feel like an antique workspace:
- **Carbon Ink (`#14181D`)**: Main background with a subtle graphite grid graph-paper pattern.
- **Aged Paper (`#EDE6D6`)**: Clean, crisp panels and cards representing notebooks.
- **Brass Key (`#B8863B`)**: Accent colors for buttons, primary controls, and active states.
- **Cipher Sage (`#6E8B6A`)** / **Grease Red (`#A33B32`)**: Confident green-sages and muted redaction-reds for warnings, alerts, and secured badges.
- **Typography**: Editorial headings in **Fraunces** serif, user interface copy in **Inter** sans-serif, and mathematical matrices or ciphertexts set in **IBM Plex Mono** to align columns.

---

## 🔒 Cryptosystems Supported

### 1. AES-256-GCM (Authenticated Encryption)
- **Chat Room (End-to-End)**: All chat room messages are encrypted *directly in the browser* using the Web Crypto API before hitting the wire. The Flask backend only sees and stores the Base64 ciphertext, initialization vector (IV), and authentication tag. It has zero capability to decrypt or read your conversations.
- **Cipher Lab (Sandbox)**: An interactive REST playground for encrypting and decrypting arbitrary texts with custom or auto-generated keys.

### 2. Hill Cipher (Polygraphic Substitution)
- An interactive implementation of the classical matrix-based substitution cipher over the alphabet A–Z (mod 26).
- Utilizes an integer-cofactor expansion method (classical adjugate) in Python (`numpy`) to guarantee mathematically perfect decryptions without float rounding errors.
- **Security Note**: Annotated as *cryptographically breakable* under known-plaintext attacks as a pedagogical reminder.

---

## 📂 Project Structure

```
matrix-encryption/
├── .env                  ← Local environment secrets (ignored by git)
├── .env.example          ← Template for configuring secrets
├── .gitignore            ← Excludes virtual environments, db files, and secrets
│
├── backend/
│   ├── app.py            ← Flask application factory & entry-point
│   ├── auth.py           ← User password hashing & HMAC-token generators
│   ├── models.py         ← SQLAlchemy models (User, Message)
│   ├── routes_auth.py    ← User registration & login endpoints
│   ├── routes_chat.py    ← Encrypted chat history & Socket.IO handlers
│   ├── routes_cipherlab.py ← REST playground endpoints for AES & Hill ciphers
│   ├── requirements.txt  ← Backend dependencies
│   └── crypto/           ← Cryptographic modules
│       ├── __init__.py
│       ├── aes.py
│       └── hill_cipher.py
│
└── frontend/
    ├── login.html        ← Login / Registration interface
    ├── chat.html         ← E2E Encrypted Chat workspace
    ├── cipher-lab.html   ← Interactive cryptographic sandbox
    └── assets/
        ├── style.css     ← Main stylesheet containing the visual identity design tokens
        ├── chat.js       ← Web Crypto API encryption + Socket.IO connection orchestration
        └── cipherlab.js  ← Interface binder for the AES & Hill ciphers
```

---

## 🔒 Security Properties

- **Confidentiality**: Active conversations use dedicated AES-GCM session keys, generated fresh per session. Users without the matching key see locked bubbles with ciphertext only — they cannot derive plaintext without the session's AES key.
- **Server Blindness**: The database persists only wrapped (encrypted) session key blobs and public keys. The server never holds a participant's private key, so it cannot unwrap a session key on its own. Note: this protects against a passive database read (e.g. a DB leak) — it does not protect against a compromised server actively substituting public keys during key exchange (see "Public Key Authenticity" below).
- **Session Key Handling**: The raw AES session key exists only transiently in server memory during the wrap step; the reference is dropped immediately after (`del`) and the key is never logged or written to disk. This reduces exposure window but is not a secure-erase guarantee — Python's `del` removes a reference, not the underlying memory contents, so the key may persist briefly in memory, swap, or a crash dump. Treat this as risk reduction, not a hard guarantee.
- **Forward Secrecy**: Not implemented. Each conversation uses one static session key for its lifetime rather than a per-message ratchet (as in Signal's Double Ratchet), so compromising one session key exposes that session's full message history. Real forward secrecy would require per-message key rotation — noted here as a possible future improvement, not a current property of the system.
- **At-Rest Storage in IndexedDB**: Session keys are encrypted at rest using a wrapping key derived from the user's own private key (self-ECDH). This guards against casual inspection of stored data, but anyone with access to read IndexedDB already has the private key sitting alongside it and can derive the same wrapping key — so this is obfuscation against casual browsing of storage, not protection against an attacker who already has local storage access.
- **Public Key Authenticity**: Not independently verified. The server delivers public keys during session setup; nothing currently prevents a compromised server from substituting a different key and executing a man-in-the-middle attack. The Hill Matrix fingerprint panel exists specifically to catch this — but only works if participants compare it **out of band** (e.g. read aloud on a call, compared in person or via a separate channel), not by both trusting what the same app displays on-screen. The UI should prompt users to verify this way explicitly, or the fingerprint check provides no real protection against a malicious server.

---

## 🚀 Setup & Installation

### 1. Configure the Virtual Environment
Create a Python 3.12 virtual environment and install the required dependencies:
```powershell
# Create virtual environment
python -m venv .venv

# Activate the virtual environment
.venv\Scripts\Activate.ps1

# Install requirements
pip install -r backend/requirements.txt
```

### 2. Environment Configurations
Rename `.env.example` to `.env` or create a new one in the root of the project with a secure key:
```ini
SECRET_KEY=your-cryptographic-secret-here
PORT=5000
```

### 3. Run the Server
Launch the Flask development server from the project's root folder:
```powershell
.\.venv\Scripts\python.exe backend\app.py
```
Open your browser and navigate to: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**.

---

## 🛠️ Editor Settings (VS Code)

To fix potential Pylance type analysis or import resolution issues within VS Code, the workspace settings file at `.vscode/settings.json` is pre-configured to look at your virtual environment interpreter and include the `backend/` folder:
```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}\\.venv\\Scripts\\python.exe",
  "python.analysis.extraPaths": [
    "${workspaceFolder}\\backend"
  ]
}
```
