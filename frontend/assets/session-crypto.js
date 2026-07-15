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
        db.createObjectStore(SESSION_IDB_STORE, { keyPath: 'id' });
      }
    };

    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = (e) => reject(e.target.error);
  });
}

async function _idbPut(record) {
  const db = await _openSessionDB();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(SESSION_IDB_STORE, 'readwrite');
    const req = tx.objectStore(SESSION_IDB_STORE).put(record);
    req.onsuccess = () => resolve();
    req.onerror   = (e) => reject(e.target.error);
  });
}

async function _idbGetAll() {
  const db = await _openSessionDB();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(SESSION_IDB_STORE, 'readonly');
    const req = tx.objectStore(SESSION_IDB_STORE).getAll();
    req.onsuccess = (e) => resolve(e.target.result ?? []);
    req.onerror   = (e) => reject(e.target.error);
  });
}

/* ── HKDF helper ──────────────────────────────────────── */

/**
 * Derive a 256-bit AES-GCM key from raw bytes via HKDF-SHA-256.
 *
 * @param {ArrayBuffer} keyMaterial  Raw bytes (e.g. ECDH shared secret).
 * @param {string}      infoString   Application-specific context string.
 * @returns {Promise<CryptoKey>}     AES-GCM 256-bit key (non-extractable).
 */
async function _hkdfDerive(keyMaterial, infoString) {
  const hkdfKey = await crypto.subtle.importKey(
    'raw', keyMaterial, 'HKDF', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name:   'HKDF',
      hash:   'SHA-256',
      salt:   new Uint8Array(32),           // zero salt (matches Python's salt=None → zeros)
      info:   new TextEncoder().encode(infoString),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,   // not extractable
    ['encrypt', 'decrypt']
  );
}

/* ── Storage wrapping key ─────────────────────────────── */

// Cached per username so we only derive once per page load
const _storageKeyCache = new Map(); // username → CryptoKey (AES-GCM)

/**
 * Derive the deterministic storage wrapping key for *username*.
 *
 * Uses self-ECDH: ECDH(my_priv, my_pub) → shared point → HKDF → AES key.
 * The result is unique to this device's keypair but fully reproducible.
 *
 * @param {string} username
 * @returns {Promise<CryptoKey>}
 */
async function _getStorageKey(username) {
  if (_storageKeyCache.has(username)) return _storageKeyCache.get(username);

  // Load the user's own keypair from the ecdh-keystore IDB
  const { privateKey, publicKey } = await window.Keystore.getOrCreateKeypair(username);

  // Self-ECDH: treat own public key as the "other party"
  const selfSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256
  );

  const storageKey = await _hkdfDerive(selfSecret, STORAGE_HKDF_INFO);
  _storageKeyCache.set(username, storageKey);
  return storageKey;
}

/* ── Session key persistence ──────────────────────────── */

/**
 * Encrypt and store a session CryptoKey in IndexedDB.
 *
 * @param {number}    sessionId
 * @param {CryptoKey} sessionCryptoKey  Must be AES-GCM, extractable.
 * @param {string}    username
 */
async function _persistSessionKey(sessionId, sessionCryptoKey, username) {
  try {
    const storageKey = await _getStorageKey(username);

    // Export raw session key bytes (requires extractable: true on import)
    const rawKeyBytes = await crypto.subtle.exportKey('raw', sessionCryptoKey);

    // Encrypt with the storage wrapping key
    const iv             = crypto.getRandomValues(new Uint8Array(12));
    const encWithTag     = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      storageKey,
      rawKeyBytes
    );

    await _idbPut({
      id:        `${username}:${sessionId}`,
      sessionId,
      username,
      encKeyB64: _bytesToB64(encWithTag),
      ivB64:     _bytesToB64(iv),
    });
  } catch (err) {
    console.warn('[session-crypto] Failed to persist session key:', err);
  }
}

/**
 * Decrypt and return a session CryptoKey from an IDB record.
 *
 * @param {{ encKeyB64: string, ivB64: string }} record
 * @param {CryptoKey} storageKey
 * @returns {Promise<CryptoKey>}  AES-GCM, extractable (for future re-persistence).
 */
async function _decryptStoredKey(record, storageKey) {
  const encBytes = _b64ToBytes(record.encKeyB64);
  const iv       = _b64ToBytes(record.ivB64);

  const rawKeyBytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    storageKey,
    encBytes
  );

  return crypto.subtle.importKey(
    'raw', rawKeyBytes,
    { name: 'AES-GCM' },
    true,                            // extractable: needed for future re-persistence
    ['encrypt', 'decrypt']
  );
}

/* ── ECIES unwrap ─────────────────────────────────────── */

/**
 * Import an ECDH P-256 public key from a JWK object.
 *
 * @param {Object} jwk
 * @returns {Promise<CryptoKey>}
 */
async function _importEphPub(jwk) {
  return crypto.subtle.importKey('jwk', jwk, ECDH_PARAMS, false, []);
}

/**
 * Unwrap an ECIES-wrapped session key blob for *username*.
 *
 * Steps mirror the Python wrap_key() in crypto/ecies.py exactly.
 *
 * @param {{ eph_pub_jwk: Object, ciphertext_b64: string, iv_b64: string, tag_b64: string }} wrappedBlob
 * @param {string} username
 * @returns {Promise<CryptoKey>}  AES-GCM CryptoKey ready for encrypt/decrypt.
 */
async function unwrapSessionKey(wrappedBlob, username) {
  if (!window.Keystore) throw new Error('[session-crypto] Keystore not loaded');

  // 1. Load user's private key from ecdh-keystore IDB
  const { privateKey } = await window.Keystore.getOrCreateKeypair(username);

  // 2. Import the ephemeral public key the server generated for this wrap
  const ephPub = await _importEphPub(wrappedBlob.eph_pub_jwk);

  // 3. ECDH(user_priv, eph_pub) → raw shared secret bytes
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: ephPub },
    privateKey,
    256
  );

  // 4. HKDF-SHA-256 → 256-bit AES-GCM wrapping key (same info as Python backend)
  const wrappingKey = await _hkdfDerive(sharedSecret, ECIES_HKDF_INFO);

  // 5. AES-256-GCM decrypt the wrapped blob → raw session key bytes
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

  // 6. Import as AES-GCM CryptoKey (extractable so we can encrypt-then-store in IDB)
  const sessionCryptoKey = await crypto.subtle.importKey(
    'raw', rawSessionKeyBytes,
    { name: 'AES-GCM' },
    true,                           // extractable for IDB persistence
    ['encrypt', 'decrypt']
  );

  return sessionCryptoKey;
}

/* ── Public API ───────────────────────────────────────── */

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
 *
 * @param {{ eph_pub_jwk, ciphertext_b64, iv_b64, tag_b64 }} wrappedBlob
 * @param {string} username
 * @param {number} sessionId
 * @param {Object} [meta]  Optional session metadata to store alongside the key.
 * @returns {Promise<CryptoKey>}
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
 * Returns undefined if the session has not been unwrapped yet.
 *
 * @param {number} sessionId
 * @returns {CryptoKey | undefined}
 */
function getSessionKey(sessionId) {
  _checkInit();
  return _sessionKeys.get(sessionId);
}

/**
 * Load all IDB-persisted session keys for *username* into the in-memory Map.
 * Call once on page load before any session operations.
 *
 * @param {string} username
 * @returns {Promise<void>}
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
      } catch (err) {
        console.warn(`[session-crypto] Could not restore session ${record.sessionId}:`, err);
      }
    }));

    if (mine.length > 0) {
      console.info(`[session-crypto] Restored ${mine.length} session key(s) from IDB`);
    }
  } catch (err) {
    console.warn('[session-crypto] loadPersistedSessions failed:', err);
  }
}

/**
 * Fetch all sessions from the server and unwrap any keys not already in memory.
 *
 * @param {string} token     Bearer token for the API.
 * @param {string} username  Logged-in username (for IDB key scoping).
 * @returns {Promise<void>}
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
      if (_sessionKeys.has(sessionId)) continue; // already in memory from IDB

      const meta = {
        other_username:          s.other_username,
        initiator_username:      s.initiator_username,
        hill_matrix_fingerprint: s.hill_matrix_fingerprint,
        is_initiator:            s.is_initiator,
        created_at:              s.created_at,
      };

      try {
        await unwrapAndStore(s.wrapped_key, username, sessionId, meta);
        console.info(`[session-crypto] Unwrapped session ${sessionId} from server`);
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
  /** Return stored metadata for a session, or undefined. */
  getSessionMeta: (sessionId) => {
    _checkInit();
    return _sessionMeta.get(sessionId);
  },
  /** Return all unwrapped sessions as [{ sessionId, meta }], newest first. */
  listSessions: () => {
    _checkInit();
    return [..._sessionKeys.keys()]
      .sort((a, b) => b - a)
      .map(id => ({ sessionId: id, meta: _sessionMeta.get(id) ?? null }));
  },
};
