/**
 * keystore.js — Client-side ECDH P-256 keypair management.
 *
 * All private keys are stored only in IndexedDB on this device, scoped per
 * username. They are never extracted or sent anywhere. Only the public key
 * (as a JWK JSON string) is uploaded to the server.
 *
 * Public API
 * ----------
 * getOrCreateKeypair(username)  → { privateKey: CryptoKey, publicKey: CryptoKey }
 * getPublicKeyJwk(publicKey)    → Object  (JWK)
 * getPrivateKey(username)       → CryptoKey | null
 */

/* ── IndexedDB helpers ────────────────────────────────── */

const IDB_NAME    = 'ecdh-keystore';
const IDB_STORE   = 'keypairs';
const IDB_VERSION = 1;

/** Open (and if needed initialise) the IndexedDB database. */
function _openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);

    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE, { keyPath: 'username' });
      }
    };

    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = (e) => reject(e.target.error);
  });
}

/** Read a stored keypair record by username.  Returns null if absent. */
async function _loadRecord(username) {
  const db = await _openDB();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(IDB_STORE, 'readonly');
    const req = tx.objectStore(IDB_STORE).get(username);
    req.onsuccess = (e) => resolve(e.target.result ?? null);
    req.onerror   = (e) => reject(e.target.error);
  });
}

/** Persist a keypair record { username, privateKeyJwk, publicKeyJwk }. */
async function _saveRecord(record) {
  const db = await _openDB();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(IDB_STORE, 'readwrite');
    const req = tx.objectStore(IDB_STORE).put(record);
    req.onsuccess = () => resolve();
    req.onerror   = (e) => reject(e.target.error);
  });
}

/* ── ECDH helpers ─────────────────────────────────────── */

const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' };

/** Generate a fresh, non-extractable ECDH P-256 CryptoKeyPair. */
async function _generateKeypair() {
  return crypto.subtle.generateKey(
    ECDH_PARAMS,
    true,                         // extractable — needed to export & persist in IDB
    ['deriveKey', 'deriveBits']
  );
}

/** Import a private-key JWK back into a non-extractable CryptoKey. */
async function _importPrivateJwk(jwk) {
  return crypto.subtle.importKey(
    'jwk', jwk,
    ECDH_PARAMS,
    false,                        // not re-extractable once imported from IDB
    ['deriveKey', 'deriveBits']
  );
}

/** Import a public-key JWK back into a CryptoKey. */
async function _importPublicJwk(jwk) {
  return crypto.subtle.importKey(
    'jwk', jwk,
    ECDH_PARAMS,
    true,
    []
  );
}

/* ── Public API ───────────────────────────────────────── */

let _dbPromise = null;

/**
 * Initialize the database connection.
 * Resolves the database promise which can be awaited before any queries.
 */
function init() {
  if (!_dbPromise) {
    _dbPromise = _openDB();
  }
  return _dbPromise;
}

function _checkInit() {
  if (!_dbPromise) {
    throw new Error('Key store not initialized: Keystore database has not been initialized. Call Keystore.init() first.');
  }
}

/**
 * Return the ECDH keypair for *username*.
 *
 * • On first call for a given username: generate, store in IDB, return.
 * • On subsequent calls: load from IDB and re-import, return.
 *
 * @param {string} username
 * @returns {Promise<{ privateKey: CryptoKey, publicKey: CryptoKey, isNew: boolean }>}
 */
async function getOrCreateKeypair(username) {
  _checkInit();
  if (!username) throw new Error('keystore: username is required');

  const existing = await _loadRecord(username);

  if (existing) {
    // Reuse the stored keypair — re-import from JWK
    const [privateKey, publicKey] = await Promise.all([
      _importPrivateJwk(existing.privateKeyJwk),
      _importPublicJwk(existing.publicKeyJwk),
    ]);
    return { privateKey, publicKey, isNew: false };
  }

  // Generate a fresh keypair and persist it
  const keypair = await _generateKeypair();
  const [privateKeyJwk, publicKeyJwk] = await Promise.all([
    crypto.subtle.exportKey('jwk', keypair.privateKey),
    crypto.subtle.exportKey('jwk', keypair.publicKey),
  ]);

  await _saveRecord({ username, privateKeyJwk, publicKeyJwk });

  return { privateKey: keypair.privateKey, publicKey: keypair.publicKey, isNew: true };
}

/**
 * Export a public CryptoKey as a JWK object.
 *
 * @param {CryptoKey} publicKey
 * @returns {Promise<Object>} JWK
 */
async function getPublicKeyJwk(publicKey) {
  _checkInit();
  return crypto.subtle.exportKey('jwk', publicKey);
}

/**
 * Retrieve only the private CryptoKey for *username* from IndexedDB.
 * Returns null if no keypair has been stored yet.
 *
 * @param {string} username
 * @returns {Promise<CryptoKey|null>}
 */
async function getPrivateKey(username) {
  _checkInit();
  const record = await _loadRecord(username);
  if (!record) return null;
  return _importPrivateJwk(record.privateKeyJwk);
}

// Make functions available globally (no module bundler in use)
window.Keystore = { init, getOrCreateKeypair, getPublicKeyJwk, getPrivateKey };
