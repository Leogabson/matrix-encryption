(() => {
/**
 * session-crypto.js — Client-side ECIES unwrapping and session key management.
 *
 * Depends on: keystore.js (must be loaded first — provides window.Keystore)
 *
 * ECIES unwrap pipeline (mirrors the Python wrap_key in crypto/ecies.py):
 *   1. Load user's ECDH P-256 private key from IndexedDB via Keystore.
 *   2. Import the ephemeral public key (JWK) from the wrapped blob.
 *   3. ECDH(user_priv, eph_pub) → raw shared secret (32 bytes).
 *   4. HKDF-SHA-256(shared_secret, info="matrix-encryption-session-key-wrap") → 32-byte AES key.
 *   5. AES-256-GCM decrypt the wrapped ciphertext → raw 32-byte session key.
 *   6. Import as AES-GCM CryptoKey.
 *   7. Store in in-memory Map AND encrypted in IndexedDB.
 *
 * Encrypted-at-rest storage (session-keystore IDB):
 *   Storage wrapping key is derived via self-ECDH:
 *     ECDH(my_priv, my_pub) → HKDF(info="matrix-encryption-storage-wrapping-key") → AES-GCM key
 *   This key is deterministic per device/user — no extra secrets to store.
 *
 * Public API
 * ----------
 * window.SessionCrypto = {
 *   unwrapSessionKey(wrappedBlob, username)          → Promise<CryptoKey>
 *   getSessionKey(sessionId)                         → CryptoKey | undefined
 *   loadPersistedSessions(username)                  → Promise<void>
 *   fetchAndUnwrapPendingSessions(token, username)   → Promise<void>
 * }
 */

/* ── Constants ────────────────────────────────────────── */

const ECIES_HKDF_INFO    = 'matrix-encryption-session-key-wrap';
const STORAGE_HKDF_INFO  = 'matrix-encryption-storage-wrapping-key';

const SESSION_IDB_NAME    = 'session-keystore';
const SESSION_IDB_STORE   = 'session-keys';
const SESSION_IDB_VERSION = 1;

const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' };

/* ── In-memory session key store ──────────────────────── */

const _sessionKeys = new Map(); // session_id (number) → CryptoKey (AES-GCM)
const _sessionMeta = new Map(); // session_id (number) → { other_username, hill_matrix_fingerprint, initiator_username, is_initiator, created_at }

/* ── Base64 helpers ───────────────────────────────────── */

function _b64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

function _bytesToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

/* ── IndexedDB helpers (session-keystore) ─────────────── */

function _openSessionDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(SESSION_IDB_NAME, SESSION_IDB_VERSION);

    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(SESSION_IDB_STORE)) {
        db.createObjectStore(SESSION_IDB_STORE, { keyPath: 'sessionId' });
      }
    };

    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = (e) => reject(e.target.error);
  });
}

function _idbPut(record) {
  return _openSessionDB().then(db => {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(SESSION_IDB_STORE, 'readwrite');
      const req = tx.objectStore(SESSION_IDB_STORE).put(record);
      req.onsuccess = () => resolve();
      req.onerror = (e) => reject(e.target.error);
    });
  });
}

function _idbGetAll() {
  return _openSessionDB().then(db => {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(SESSION_IDB_STORE, 'readonly');
      const req = tx.objectStore(SESSION_IDB_STORE).getAll();
      req.onsuccess = (e) => resolve(e.target.result);
      req.onerror = (e) => reject(e.target.error);
    });
  });
}

/* ── HKDF logic (Web Crypto API) ──────────────────────── */

async function _hkdfDerive(sharedSecretKey, infoString) {
  const enc = new TextEncoder();
  const info = enc.encode(infoString);
  const salt = new Uint8Array(0); // empty salt, standard in ECIES

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info,
    },
    sharedSecretKey,
    256 // 32 bytes
  );

  return crypto.subtle.importKey(
    'raw', derivedBits,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

/* ── Self-ECDH key derivation (for storage encryption) ── */

/** Derive a unique local wrapping key using ECDH(my_private, my_public). */
async function _getStorageKey(username) {
  // Load private and public keys
  const [priv, pub] = await Promise.all([
    window.Keystore.getPrivateKey(username),
    window.Keystore.getOrCreateKeypair(username).then(res => res.publicKey)
  ]);

  if (!priv || !pub) {
    throw new Error('User ECDH keys not available for storage encryption');
  }

  // Derive bits using ECDH
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: pub,
    },
    priv,
    256
  );

  const sharedSecret = await crypto.subtle.importKey(
    'raw', derivedBits,
    { name: 'HKDF' },
    false,
    ['deriveKey', 'deriveBits']
  );

  // Derive final AES storage wrapping key
  return _hkdfDerive(sharedSecret, STORAGE_HKDF_INFO);
}

/* ── Encrypted IndexedDB persistence ──────────────────── */

async function _encryptStoredKey(sessionKey, storageKey) {
  const rawKeyBytes = await crypto.subtle.exportKey('raw', sessionKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    storageKey,
    rawKeyBytes
  );

  const ctBytes = new Uint8Array(ciphertext);
  return {
    ciphertext_b64: _bytesToB64(ctBytes.slice(0, -16)),
    tag_b64:        _bytesToB64(ctBytes.slice(-16)),
    iv_b64:         _bytesToB64(iv),
  };
}

async function _decryptStoredKey(record, storageKey) {
  const iv = _b64ToBytes(record.iv_b64);
  const ct = _b64ToBytes(record.ciphertext_b64);
  const tag = _b64ToBytes(record.tag_b64);

  const combined = new Uint8Array(ct.length + tag.length);
  combined.set(ct, 0);
  combined.set(tag, ct.length);

  const rawBytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    storageKey,
    combined
  );

  return crypto.subtle.importKey(
    'raw', rawBytes,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
}

async function _persistSessionKey(sessionId, sessionKey, username) {
  try {
    const storageKey = await _getStorageKey(username);
    const encResult  = await _encryptStoredKey(sessionKey, storageKey);

    const record = {
      sessionId,
      username,
      ciphertext_b64: encResult.ciphertext_b64,
      tag_b64:        encResult.tag_b64,
      iv_b64:         encResult.iv_b64,
      meta:           _sessionMeta.get(sessionId) || null,
    };

    await _idbPut(record);
  } catch (err) {
    console.warn(`[session-crypto] Failed to persist session key for #${sessionId}:`, err);
  }
}

/* ── Ephemeral ECIES unwrapping ───────────────────────── */

/** Import raw ephemeral public key JWK */
async function _importPublicJwk(jwk) {
  return crypto.subtle.importKey('jwk', jwk, ECDH_PARAMS, false, []);
}

/**
 * Unwrap a session key blob using the user's private key.
 *
 * @param {{ eph_pub_jwk, ciphertext_b64, iv_b64, tag_b64 }} wrappedBlob
 * @param {string} username
 * @returns {Promise<CryptoKey>} Unwrapped AES-GCM session key
 */
async function unwrapSessionKey(wrappedBlob, username) {
  if (!window.Keystore) throw new Error('[session-crypto] Keystore not loaded');

  // 1. Load user's private key from ecdh-keystore IDB
  const privateKey = await window.Keystore.getPrivateKey(username);
  if (!privateKey) throw new Error('[session-crypto] User ECDH private key not found');

  // 2. Import ephemeral public key
  const ephemeralPublic = await _importPublicJwk(wrappedBlob.eph_pub_jwk);

  // 3. ECDH key agreement -> raw shared secret bits
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: ephemeralPublic,
    },
    privateKey,
    256 // 32 bytes
  );

  const sharedSecret = await crypto.subtle.importKey(
    'raw', derivedBits,
    { name: 'HKDF' },
    false,
    ['deriveKey', 'deriveBits']
  );

  // 4. HKDF-SHA-256 -> 256-bit AES-GCM wrapping key (same info as Python backend)
  const wrappingKey = await _hkdfDerive(sharedSecret, ECIES_HKDF_INFO);

  // 5. AES-256-GCM decrypt the wrapped blob -> raw session key bytes
  const iv         = _b64ToBytes(wrappedBlob.iv_b64);
  const ciphertext = _b64ToBytes(wrappedBlob.ciphertext_b64);
  const tag        = _b64ToBytes(wrappedBlob.tag_b64);

  // Web Crypto expects ciphertext + tag concatenated
  const ctWithTag = new Uint8Array(ciphertext.length + tag.length);
  ctWithTag.set(ciphertext, 0);
  ctWithTag.set(tag, ciphertext.length);

  const rawSessionKeyBytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    ctWithTag
  );

  return crypto.subtle.importKey(
    'raw', rawSessionKeyBytes,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
}

/* ── Public API ───────────────────────────────────────── */

let _sessionDbPromise = null;

/**
 * Initialize the session database connection.
 * Resolves the database promise which can be awaited before any queries.
 */
function init() {
  if (!_sessionDbPromise) {
    _sessionDbPromise = _openSessionDB();
  }
  return _sessionDbPromise;
}

function _checkInit() {
  if (!window.Keystore) {
    throw new Error('Key store not initialized: Keystore is not defined.');
  }
  if (!_sessionDbPromise) {
    throw new Error('Key store not initialized: Session IDB has not been initialized. Call SessionCrypto.init() first.');
  }
}

/**
 * Unwrap a session key blob and store it in memory + IDB.
 */
async function unwrapAndStore(wrappedBlob, username, sessionId, meta = null) {
  _checkInit();
  const key = await unwrapSessionKey(wrappedBlob, username);
  _sessionKeys.set(sessionId, key);
  if (meta) _sessionMeta.set(sessionId, meta);
  await _persistSessionKey(sessionId, key, username);
  return key;
}

/**
 * Retrieve a session CryptoKey from the in-memory Map.
 */
function getSessionKey(sessionId) {
  _checkInit();
  return _sessionKeys.get(sessionId);
}

/**
 * Load all IDB-persisted session keys for *username* into the in-memory Map.
 */
async function loadPersistedSessions(username) {
  _checkInit();
  if (!username) return;
  try {
    const storageKey = await _getStorageKey(username);
    const records    = await _idbGetAll();
    const mine       = records.filter(r => r.username === username);

    await Promise.all(mine.map(async (record) => {
      try {
        const key = await _decryptStoredKey(record, storageKey);
        _sessionKeys.set(record.sessionId, key);
        if (record.meta) _sessionMeta.set(record.sessionId, record.meta);
      } catch (err) {
        console.warn(`[session-crypto] Could not restore session ${record.sessionId}:`, err);
      }
    }));
  } catch (err) {
    console.warn('[session-crypto] loadPersistedSessions failed:', err);
  }
}

/**
 * Fetch all sessions from the server and unwrap any keys not already in memory.
 */
async function fetchAndUnwrapPendingSessions(token, username) {
  _checkInit();
  if (!token || !username) return;
  try {
    const res = await fetch('/api/session/pending', {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return;

    const sessions = await res.json();

    for (const s of sessions) {
      const sessionId = s.session_id;
      if (_sessionKeys.has(sessionId)) continue;

      const meta = {
        other_username:          s.other_username,
        initiator_username:      s.initiator_username,
        hill_matrix_fingerprint: s.hill_matrix_fingerprint,
        is_initiator:            s.is_initiator,
        created_at:              s.created_at,
      };

      try {
        await unwrapAndStore(s.wrapped_key, username, sessionId, meta);
      } catch (err) {
        console.warn(`[session-crypto] Failed to unwrap session ${sessionId}:`, err);
      }
    }
  } catch (err) {
    console.warn('[session-crypto] fetchAndUnwrapPendingSessions failed:', err);
  }
}

// Expose to other scripts (no module bundler)
window.SessionCrypto = {
  init,
  unwrapAndStore,
  getSessionKey,
  loadPersistedSessions,
  fetchAndUnwrapPendingSessions,
  getSessionMeta: (sessionId) => {
    _checkInit();
    return _sessionMeta.get(sessionId);
  },
  listSessions: () => {
    _checkInit();
    return [..._sessionKeys.keys()]
      .sort((a, b) => b - a)
      .map(id => ({ sessionId: id, meta: _sessionMeta.get(id) ?? null }));
  },
};
})();
