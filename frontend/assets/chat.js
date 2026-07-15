/**
 * chat.js – Socket.IO client + AES-GCM helpers for the encrypted chat page.
 *
 * Dependencies (loaded before this script in chat.html):
 *   - socket.io v4 client (CDN)
 *   - keystore.js          → window.Keystore
 *   - session-crypto.js    → window.SessionCrypto
 *   - Web Crypto API (native in all modern browsers)
 */

/* ── Utility helpers ─────────────────────────────────── */
const $ = id => document.getElementById(id);

function b64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

function bytesToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

/* ── Global State ────────────────────────────────────── */
let _cryptoKey = null;         // CryptoKey for Global Room shared key
let _activeSessionId = null;   // null = Global Room, number = active private session ID

async function importRawKey(rawB64) {
  const raw = b64ToBytes(rawB64);
  _cryptoKey = await crypto.subtle.importKey(
    'raw', raw,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

/* ── Generic AES-GCM encrypt/decrypt ─────────────────── */

/**
 * Encrypt *plaintext* with *cryptoKey* (AES-GCM 256).
 * Returns { ciphertext_b64, iv_b64, tag_b64 }.
 */
async function encryptWithKey(plaintext, cryptoKey) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ct  = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    enc.encode(plaintext)
  );
  const ctBytes = new Uint8Array(ct);
  return {
    ciphertext_b64: bytesToB64(ctBytes.slice(0, -16)),
    iv_b64:         bytesToB64(iv),
    tag_b64:        bytesToB64(ctBytes.slice(-16)),
  };
}

/** Encrypt with the Global Room shared key. */
async function encryptText(plaintext) {
  if (!_cryptoKey) throw new Error('No global crypto key loaded');
  return encryptWithKey(plaintext, _cryptoKey);
}

/**
 * Decrypt with *cryptoKey*. Returns plaintext string or an error marker.
 */
async function decryptWithKey({ ciphertext_b64, iv_b64, tag_b64 }, cryptoKey) {
  const iv       = b64ToBytes(iv_b64);
  const ct       = b64ToBytes(ciphertext_b64);
  const tag      = b64ToBytes(tag_b64);
  const combined = new Uint8Array(ct.length + tag.length);
  combined.set(ct, 0);
  combined.set(tag, ct.length);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, combined);
    return new TextDecoder().decode(pt);
  } catch {
    return '⚠ decryption failed';
  }
}

/** Decrypt with the Global Room shared key. */
async function decryptText(fields) {
  if (!_cryptoKey) return '[key not loaded]';
  return decryptWithKey(fields, _cryptoKey);
}

/* ── Matrix Hacker Decryption Animation ──────────────── */
function matrixDecryptAnimate(element, targetText, duration = 1200) {
  const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%/\\+=_';
  const start = performance.now();

  function update(time) {
    const elapsed  = time - start;
    const progress = Math.min(elapsed / duration, 1);
    let resultText = '';
    for (let i = 0; i < targetText.length; i++) {
      if (targetText[i] === ' ' || targetText[i] === '\n') {
        resultText += targetText[i];
      } else if (Math.random() < progress) {
        resultText += targetText[i];
      } else {
        resultText += chars[Math.floor(Math.random() * chars.length)];
      }
    }
    element.textContent = resultText;
    if (progress < 1) requestAnimationFrame(update);
    else element.textContent = targetText;
  }
  requestAnimationFrame(update);
}

/* ── Toast helper ────────────────────────────────────── */
function toast(msg, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  container.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

/* ── Hill matrix renderer ────────────────────────────── */
/**
 * Build a `.hill-matrix-drawer` element from a 2D array of numbers.
 * @param {number[][]} matrix
 * @returns {HTMLElement}
 */
function buildHillMatrixDrawer(matrix) {
  const drawer = document.createElement('div');
  drawer.className = 'hill-matrix-drawer';

  const label = document.createElement('div');
  label.className = 'hm-label';
  label.textContent = 'Hill Cipher Fingerprint';
  drawer.appendChild(label);

  for (const row of matrix) {
    const rowEl = document.createElement('div');
    rowEl.className = 'hill-matrix-row';
    for (const val of row) {
      const cell = document.createElement('span');
      cell.textContent = val;
      rowEl.appendChild(cell);
    }
    drawer.appendChild(rowEl);
  }
  return drawer;
}

/* ── Message Renderers ───────────────────────────────── */

/**
 * Render a standard shared-key (Global Room) message bubble.
 * Preserves the existing Plaintext / Ciphertext / Envelope tabs.
 */
function renderPublicMessage(container, data, isSelf) {
  const wrapper = document.createElement('div');
  wrapper.className = `msg-row ${isSelf ? 'self' : 'other'}`;
  wrapper.dataset.sessionId = 'null';

  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble';

  // Metadata header
  const meta = document.createElement('div');
  meta.className = 'msg-meta';
  const senderSpan = document.createElement('span');
  senderSpan.textContent = `User ID: ${data.user_id}`;
  const timeSpan = document.createElement('span');
  timeSpan.textContent = new Date(data.timestamp).toLocaleTimeString();
  meta.appendChild(senderSpan);
  meta.appendChild(timeSpan);
  bubble.appendChild(meta);

  // Body — starts as monospace ciphertext
  const body = document.createElement('p');
  body.className = 'msg-body';
  body.style.fontFamily = 'var(--font-mono)';
  body.style.color = 'var(--color-accent)';
  body.textContent = data.ciphertext;
  bubble.appendChild(body);

  let plaintextCached = null;
  let hasAnimatedReveal = false;

  // Tabs
  const controls = document.createElement('div');
  controls.className = 'msg-controls';

  const tabPlain   = document.createElement('button');
  tabPlain.className = 'msg-tab';
  tabPlain.textContent = 'Plaintext';

  const tabCipher  = document.createElement('button');
  tabCipher.className = 'msg-tab active';
  tabCipher.textContent = 'Ciphertext';

  const btnEnvelope = document.createElement('button');
  btnEnvelope.className = 'msg-tab';
  btnEnvelope.textContent = 'Cryptographic Envelope';

  controls.append(tabPlain, tabCipher, btnEnvelope);
  bubble.appendChild(controls);

  // Envelope drawer
  const envelopeDrawer = document.createElement('div');
  envelopeDrawer.className = 'envelope-details';
  envelopeDrawer.style.display = 'none';
  envelopeDrawer.innerHTML = `
    <div class="envelope-field">
      <span>Initialization Vector (IV/Nonce)</span>
      <span>${data.iv}</span>
    </div>
    <div class="envelope-field">
      <span>Auth Tag</span>
      <span>${data.tag}</span>
    </div>
    <div class="envelope-field">
      <span>Raw Ciphertext</span>
      <span>${data.ciphertext}</span>
    </div>
  `;
  bubble.appendChild(envelopeDrawer);

  // Background decrypt
  decryptText({ ciphertext_b64: data.ciphertext, iv_b64: data.iv, tag_b64: data.tag })
    .then(pt => { plaintextCached = pt; });

  tabPlain.addEventListener('click', () => {
    if (tabPlain.classList.contains('active')) return;
    tabPlain.classList.add('active');
    tabCipher.classList.remove('active');
    body.style.fontFamily = 'var(--font-body)';
    body.style.color = '';
    if (plaintextCached) {
      if (!hasAnimatedReveal) { matrixDecryptAnimate(body, plaintextCached); hasAnimatedReveal = true; }
      else body.textContent = plaintextCached;
    } else {
      body.textContent = '[decryption failed]';
    }
  });

  tabCipher.addEventListener('click', () => {
    tabCipher.classList.add('active');
    tabPlain.classList.remove('active');
    body.style.fontFamily = 'var(--font-mono)';
    body.style.color = 'var(--color-accent)';
    body.textContent = data.ciphertext;
  });

  btnEnvelope.addEventListener('click', () => {
    btnEnvelope.classList.toggle('active');
    envelopeDrawer.style.display = envelopeDrawer.style.display === 'none' ? 'flex' : 'none';
    container.scrollTop = container.scrollHeight;
  });

  wrapper.appendChild(bubble);
  container.appendChild(wrapper);
  container.scrollTop = container.scrollHeight;
}

/**
 * Render a private session message that we CAN decrypt.
 * Auto-decrypts with matrixDecryptAnimate and shows the Hill matrix fingerprint.
 */
function renderPrivateMessage(container, data, isSelf, sessionKey) {
  const wrapper = document.createElement('div');
  wrapper.className = `msg-row ${isSelf ? 'self' : 'other'}`;
  wrapper.dataset.sessionId = String(data.session_id);

  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble';

  // Private tag pill
  const tag = document.createElement('div');
  tag.className = 'msg-private-tag';
  tag.innerHTML = `🔒 Private &middot; Session #${data.session_id}`;
  bubble.appendChild(tag);

  // Metadata header
  const meta = document.createElement('div');
  meta.className = 'msg-meta';
  const senderSpan = document.createElement('span');
  senderSpan.textContent = `User ID: ${data.user_id}`;
  const timeSpan = document.createElement('span');
  timeSpan.textContent = new Date(data.timestamp).toLocaleTimeString();
  meta.appendChild(senderSpan);
  meta.appendChild(timeSpan);
  bubble.appendChild(meta);

  // Body — will be filled by decryption below
  const body = document.createElement('p');
  body.className = 'msg-body';
  body.style.fontFamily = 'var(--font-mono)';
  body.style.color = 'var(--color-accent)';
  body.style.opacity = '0.5';
  body.textContent = '⌛ Decrypting…';
  bubble.appendChild(body);

  // Hill matrix toggle + drawer
  const fingerprint = data.hill_matrix_fingerprint;
  if (fingerprint) {
    const matrixControls = document.createElement('div');
    matrixControls.className = 'msg-controls';
    matrixControls.style.borderTop = 'none';
    matrixControls.style.paddingTop = '0';

    const matrixBtn = document.createElement('button');
    matrixBtn.className = 'hill-matrix-btn msg-tab';
    matrixBtn.textContent = '⊞ Fingerprint';
    matrixControls.appendChild(matrixBtn);
    bubble.appendChild(matrixControls);

    const drawer = buildHillMatrixDrawer(fingerprint);
    bubble.appendChild(drawer);

    matrixBtn.addEventListener('click', () => {
      matrixBtn.classList.toggle('active');
      drawer.style.display = drawer.style.display === 'none' ? 'flex' : 'none';
      container.scrollTop = container.scrollHeight;
    });
  }

  wrapper.appendChild(bubble);
  container.appendChild(wrapper);
  container.scrollTop = container.scrollHeight;

  // Decrypt asynchronously and animate
  decryptWithKey(
    { ciphertext_b64: data.ciphertext, iv_b64: data.iv, tag_b64: data.tag },
    sessionKey
  ).then(plaintext => {
    body.style.opacity = '1';
    body.style.fontFamily = 'var(--font-body)';
    body.style.color = '';
    matrixDecryptAnimate(body, plaintext);
  });
}

/**
 * Render a private session message we CANNOT decrypt.
 * Shows a locked header and the raw ciphertext as visible gibberish.
 */
function renderLockedMessage(container, data, isSelf) {
  const wrapper = document.createElement('div');
  wrapper.className = `msg-row ${isSelf ? 'self' : 'other'}`;
  wrapper.dataset.sessionId = String(data.session_id);

  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble msg-locked';

  // Metadata header
  const meta = document.createElement('div');
  meta.className = 'msg-meta';
  const senderSpan = document.createElement('span');
  senderSpan.textContent = `User ID: ${data.user_id}`;
  const timeSpan = document.createElement('span');
  timeSpan.textContent = new Date(data.timestamp).toLocaleTimeString();
  meta.appendChild(senderSpan);
  meta.appendChild(timeSpan);
  bubble.appendChild(meta);

  // Locked header
  const header = document.createElement('div');
  header.className = 'locked-header';
  header.textContent = '🔒 Encrypted — not for you';
  bubble.appendChild(header);

  // Ciphertext gibberish (truncated, faded out)
  const ct = document.createElement('div');
  ct.className = 'locked-ciphertext';
  ct.textContent = data.ciphertext;
  bubble.appendChild(ct);

  wrapper.appendChild(bubble);
  container.appendChild(wrapper);
  container.scrollTop = container.scrollHeight;
}

/**
 * Route an incoming message to the correct renderer based on session_id
 * and whether we hold the session key in memory.
 *
 * @param {HTMLElement} container  The #msg-list element.
 * @param {Object}      data       Message payload from server.
 * @param {boolean}     isSelf     Whether this message was sent by the local user.
 */
function renderMessage(container, data, isSelf) {
  const sessionId = data.session_id ?? null;

  if (sessionId === null) {
    // ── Public / Global Room message ──────────────────────
    renderPublicMessage(container, data, isSelf);
  } else {
    // ── Private session message ───────────────────────────
    const sessionKey = window.SessionCrypto?.getSessionKey(sessionId);
    if (sessionKey) {
      renderPrivateMessage(container, data, isSelf, sessionKey);
    } else {
      renderLockedMessage(container, data, isSelf);
    }
  }

  // Apply current filter to the last child added to container
  const lastChild = container.lastElementChild;
  if (lastChild && lastChild.classList.contains('msg-row')) {
    if (_activeSessionId === null) {
      lastChild.style.display = (lastChild.dataset.sessionId === 'null') ? '' : 'none';
    } else {
      lastChild.style.display = (lastChild.dataset.sessionId === String(_activeSessionId)) ? '' : 'none';
    }
  }
}

/* ── DOM Filtering & Header UI ────────────────────────── */

/** Apply CSS visibility to show/hide messages in #msg-list. */
function applyMessageFilter(activeSessionId) {
  const msgRows = document.querySelectorAll('#msg-list .msg-row');
  msgRows.forEach(row => {
    const rowSessionId = row.dataset.sessionId;
    if (activeSessionId === null) {
      row.style.display = (rowSessionId === 'null') ? '' : 'none';
    } else {
      row.style.display = (rowSessionId === String(activeSessionId)) ? '' : 'none';
    }
  });
  const msgList = $('msg-list');
  msgList.scrollTop = msgList.scrollHeight;
}

/** Render side-by-side matrices inside #fp-grid. */
function showFingerprintPanel(fingerprint, otherUsername) {
  const grid = $('fp-grid');
  if (!grid) return;
  grid.innerHTML = '';

  const buildFpCol = (title, fp) => {
    const col = document.createElement('div');
    col.className = 'fp-matrix-col';
    const label = document.createElement('div');
    label.className = 'fp-matrix-label';
    label.textContent = title;
    col.appendChild(label);

    const mDiv = document.createElement('div');
    mDiv.className = 'fp-matrix';
    for (const row of fp) {
      const rowEl = document.createElement('div');
      rowEl.className = 'fp-matrix-row';
      for (const val of row) {
        const cell = document.createElement('span');
        cell.textContent = val;
        rowEl.appendChild(cell);
      }
      mDiv.appendChild(rowEl);
    }
    col.appendChild(mDiv);
    return col;
  };

  const col1 = buildFpCol('Your Fingerprint', fingerprint);
  const sep  = document.createElement('div');
  sep.className = 'fp-sep';
  sep.textContent = ' ⇄ ';
  const col2 = buildFpCol(`Ask ${otherUsername} to confirm`, fingerprint);

  grid.append(col1, sep, col2);
  $('fingerprint-panel').style.display = 'flex';
}

/** Switch views dynamically and update the chat header. */
function selectChannel(selectedId) {
  _activeSessionId = selectedId;
  const list = $('session-list');

  // Sync sidebar active styling
  list.querySelectorAll('.session-item').forEach(item => {
    const itemSid = item.dataset.sessionId;
    if ((selectedId === null && itemSid === 'null') || (selectedId !== null && itemSid === String(selectedId))) {
      item.classList.add('active');
    } else {
      item.classList.remove('active');
    }
  });

  const headerTitle = $('chat-header-title');
  const badge       = $('secured-badge');
  const btnVerify   = $('verify-keys-btn');
  const btnBack     = $('back-global-btn');
  const btnNew      = $('new-session-btn');
  const fpPanel     = $('fingerprint-panel');

  if (selectedId === null) {
    // 🌐 Global Room Mode
    headerTitle.textContent = 'Global Room';
    badge.textContent       = 'AES-GCM secured';
    badge.className         = 'secured-badge';
    btnVerify.style.display = 'none';
    btnBack.style.display   = 'none';
    btnNew.style.display    = '';
    fpPanel.style.display   = 'none';
    toast('Active channel: Global Room', 'info');
  } else {
    // 🔐 Private E2EE Mode
    const meta = window.SessionCrypto?.getSessionMeta(selectedId);
    const other = meta?.other_username ?? `Session #${selectedId}`;
    headerTitle.textContent = `🔐 ${other} (Session #${selectedId})`;
    badge.textContent       = 'E2EE secured';
    badge.className         = 'secured-badge';
    btnVerify.style.display = '';
    btnBack.style.display   = '';
    btnNew.style.display    = 'none';

    if (meta && meta.hill_matrix_fingerprint) {
      showFingerprintPanel(meta.hill_matrix_fingerprint, other);
    } else {
      fpPanel.style.display = 'none';
    }
    toast(`Active channel: Session #${selectedId} with ${other}`, 'info');
  }

  // Filter existing messages in the chat history
  applyMessageFilter(selectedId);
}

/* ── Session picker ──────────────────────────────────── */

/**
 * Rebuild the sidebar session list from SessionCrypto.listSessions().
 * Called after init and on each new_session event.
 */
function buildSessionPicker() {
  const list = $('session-list');
  if (!list || !window.SessionCrypto) return;

  // Keep only the Global Room entry, remove any previous session items
  const existing = list.querySelectorAll('.session-item:not(#session-global)');
  existing.forEach(el => el.remove());

  const sessions = window.SessionCrypto.listSessions();
  for (const { sessionId, meta } of sessions) {
    const item = document.createElement('div');
    item.className = 'session-item';
    item.dataset.sessionId = sessionId;

    const labelEl = document.createElement('span');
    labelEl.className = 'session-item-label';

    const other = meta?.other_username ?? `Session #${sessionId}`;
    labelEl.textContent = `🔐 ${other}`;

    const subEl = document.createElement('span');
    subEl.className = 'session-item-sub';
    subEl.textContent = `Session #${sessionId} · E2EE`;

    item.appendChild(labelEl);
    item.appendChild(subEl);

    // Sync active class
    if (_activeSessionId === sessionId) {
      item.classList.add('active');
    }

    item.addEventListener('click', () => {
      selectChannel(sessionId);
    });

    list.appendChild(item);
  }

  // Wire up the Global Room item click
  const globalItem = $('session-global');
  if (globalItem) {
    const fresh = globalItem.cloneNode(true);
    globalItem.replaceWith(fresh);
    if (_activeSessionId === null) {
      fresh.classList.add('active');
    } else {
      fresh.classList.remove('active');
    }
    fresh.addEventListener('click', () => {
      selectChannel(null);
    });
  }
}

/* ── User Picker Modal ────────────────────────────────── */

async function openUserPicker(token, username) {
  const modal = $('user-picker-modal');
  const container = $('picker-user-list');
  if (!modal || !container) return;

  modal.style.display = 'flex';
  container.innerHTML = '<div class="modal-empty">Loading users…</div>';

  try {
    const res = await fetch('/api/auth/users', {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) throw new Error('Could not fetch user list');

    const users = await res.json();
    container.innerHTML = '';

    if (users.length === 0) {
      container.innerHTML = '<div class="modal-empty">No other users online yet.</div>';
      return;
    }

    users.forEach(user => {
      const row = document.createElement('div');
      row.className = 'user-row';
      if (!user.has_public_key) {
        row.classList.add('no-key');
        row.title = 'This user has not generated a public key yet (needs login/refresh).';
      }

      const initial = (user.username || '?').substring(0, 1).toUpperCase();
      const avatar = document.createElement('div');
      avatar.className = 'user-avatar';
      avatar.textContent = initial;

      const info = document.createElement('div');
      info.className = 'user-info';
      const name = document.createElement('div');
      name.className = 'user-name';
      name.textContent = user.username;
      info.appendChild(name);

      const statusBadge = document.createElement('div');
      if (user.has_public_key) {
        statusBadge.className = 'user-key-badge';
        statusBadge.textContent = '● Key ready';
      } else {
        statusBadge.className = 'user-key-missing';
        statusBadge.textContent = '○ Key missing';
      }
      info.appendChild(statusBadge);

      const spinner = document.createElement('div');
      spinner.className = 'user-row-spinner';

      const arrow = document.createElement('span');
      arrow.className = 'user-row-arrow';
      arrow.textContent = '→';

      row.append(avatar, info, spinner, arrow);
      container.appendChild(row);

      // Trigger session start on valid user click
      if (user.has_public_key) {
        row.addEventListener('click', async () => {
          row.classList.add('loading');
          row.style.pointerEvents = 'none';

          try {
            // Gated by the shared initialization complete signal
            if (window.cryptoInitPromise) {
              await window.cryptoInitPromise;
            }

            if (!window.SessionCrypto) {
              throw new Error('Cryptography module (SessionCrypto) not loaded. Please refresh the page.');
            }

            const startRes = await fetch('/api/session/start', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
              },
              body: JSON.stringify({ participant_username: user.username })
            });

            if (!startRes.ok) {
              const errData = await startRes.json();
              throw new Error(errData.error || 'Failed to start session');
            }

            const data = await startRes.json();
            const meta = {
              other_username:          user.username,
              initiator_username:      username,
              hill_matrix_fingerprint: data.hill_matrix_fingerprint,
              is_initiator:            true,
              created_at:              data.created_at,
            };

            await window.SessionCrypto.unwrapAndStore(
              data.wrapped_key,
              username,
              data.session_id,
              meta
            );

            // Rebuild picker and view the new channel
            buildSessionPicker();
            modal.style.display = 'none';
            selectChannel(data.session_id);

          } catch (err) {
            console.error('[chat] POST /api/session/start failed:', err);
            toast(err.message, 'error');
            row.classList.remove('loading');
            row.style.pointerEvents = '';
          }
        });
      }
    });

  } catch (err) {
    container.innerHTML = `<div class="modal-empty" style="color:var(--color-danger)">Error: ${err.message}</div>`;
  }
}

/* ── Loading state helper ────────────────────────────── */
function showChatLoading(isLoading) {
  const btn = $('new-session-btn');
  if (btn) {
    if (isLoading) {
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner" style="width:12px;height:12px;margin-right:6px;border-top-color:var(--color-accent)"></span>⌛ Initializing keys…';
    } else {
      btn.disabled = false;
      btn.innerHTML = '🔐 Start Secure Session';
    }
  }
}

/* ── Main init ───────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  const token    = sessionStorage.getItem('token');
  const userId   = parseInt(sessionStorage.getItem('user_id') || '0', 10);
  const username = sessionStorage.getItem('username') || '';
  const keyB64   = sessionStorage.getItem('aes_key');

  if (!token) { window.location.href = '/login.html'; return; }

  // 1. Set loading state immediately on button to block user actions
  showChatLoading(true);

  if (keyB64) {
    importRawKey(keyB64);
  } else {
    toast('No AES key found – messages will not be decryptable', 'error');
  }

  // ── Create exactly ONE shared "initialization complete" signal promise ────
  window.cryptoInitPromise = (async () => {
    if (window.Keystore) {
      await window.Keystore.init();
    }
    if (window.SessionCrypto) {
      await window.SessionCrypto.init();
      if (username) {
        // Load local keys from IndexedDB
        await window.SessionCrypto.loadPersistedSessions(username);
      }
    }
  })();

  // ── Recover pending sessions after shared init resolves ───────────────────
  window.cryptoInitPromise.then(async () => {
    try {
      if (window.SessionCrypto && username) {
        const pendingRes = await fetch('/api/session/pending', {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (pendingRes.ok) {
          const sessions = await pendingRes.json();
          for (const s of sessions) {
            const sessionId = s.session_id;
            if (window.SessionCrypto.getSessionKey(sessionId)) continue;

            const meta = {
              other_username:          s.other_username,
              initiator_username:      s.initiator_username,
              hill_matrix_fingerprint: s.hill_matrix_fingerprint,
              is_initiator:            s.is_initiator,
              created_at:              s.created_at,
            };

            try {
              await window.SessionCrypto.unwrapAndStore(s.wrapped_key, username, sessionId, meta);
              console.info(`[session-crypto] Unwrapped session ${sessionId} on startup`);
            } catch (err) {
              console.warn(`[session-crypto] Failed to unwrap session ${sessionId} during startup:`, err);
            }
          }
        }
      }
    } catch (err) {
      console.error('[chat] Pending session recovery failed:', err);
    } finally {
      // 2. Hide loading state once databases are fully open and keys recovered
      showChatLoading(false);
      buildSessionPicker();
    }
  }).catch((initErr) => {
    console.error('[chat] Secure initialization failed:', initErr);
    toast(`Security setup failed: ${initErr.message}`, 'error');
    showChatLoading(false);
    buildSessionPicker();
  });

  const msgList  = $('msg-list');
  const msgInput = $('msg-input');
  const sendBtn  = $('send-btn');
  const status   = $('socket-status');

  /* ── Modal Close / Overlay Wire-ups ─────────────────── */
  const pickerModal = $('user-picker-modal');
  $('new-session-btn').addEventListener('click', () => {
    openUserPicker(token, username);
  });
  $('picker-close-btn').addEventListener('click', () => {
    pickerModal.style.display = 'none';
  });
  pickerModal.addEventListener('click', (e) => {
    if (e.target === pickerModal) pickerModal.style.display = 'none';
  });

  // Header Actions Wire-up
  $('back-global-btn').addEventListener('click', () => {
    selectChannel(null);
  });
  $('verify-keys-btn').addEventListener('click', () => {
    const fpPanel = $('fingerprint-panel');
    fpPanel.style.display = fpPanel.style.display === 'none' ? 'flex' : 'none';
  });
  $('fp-close-btn').addEventListener('click', () => {
    $('fingerprint-panel').style.display = 'none';
  });

  /* ── Load history ──────────────────────────────────── */
  try {
    fetch('/api/chat/history', {
      headers: { Authorization: `Bearer ${token}` },
    }).then(res => {
      if (res.ok) {
        return res.json();
      }
    }).then(msgs => {
      if (msgs) {
        msgs.forEach(m => renderMessage(msgList, m, m.user_id === userId));
        applyMessageFilter(null);
      }
    });
  } catch { /* ignore */ }

  /* ── Socket.IO connection (Connected immediately, but events await init) ── */
  const socket = io({ auth: { token } });

  socket.on('connect', () => {
    status.textContent  = '● Connected';
    status.className    = 'badge badge-green';
    toast('Socket.IO connected ✓', 'success');
    if (window.__updateTransport) {
      window.__updateTransport(socket.io.engine.transport.name);
    }
    socket.io.engine.on('upgrade', () => {
      if (window.__updateTransport) {
        window.__updateTransport(socket.io.engine.transport.name);
      }
    });
  });

  socket.on('disconnect', () => {
    status.textContent = '● Disconnected';
    status.className   = 'badge badge-red';
    if (window.__updateTransport) window.__updateTransport('—');
  });

  socket.on('connect_error', (err) => {
    status.textContent = '● Error';
    status.className   = 'badge badge-red';
    toast(`Connection error: ${err.message}`, 'error');
    if (window.__updateTransport) window.__updateTransport('—');
  });

  socket.on('new_message', (data) => {
    renderMessage(msgList, data, data.user_id === userId);
  });

  // ── New session notification (participant side) ─────────────────────
  socket.on('new_session', async (data) => {
    const sessionId = data.session_id;

    try {
      // Gated by the shared initialization complete signal
      if (window.cryptoInitPromise) {
        await window.cryptoInitPromise;
      }

      if (window.SessionCrypto && username) {
        const meta = {
          other_username:          data.initiator_username,
          initiator_username:      data.initiator_username,
          hill_matrix_fingerprint: data.hill_matrix_fingerprint,
          is_initiator:            false,
          created_at:              data.created_at,
        };
        await window.SessionCrypto.unwrapAndStore(
          data.wrapped_key,
          username,
          sessionId,
          meta
        );
        // Re-render the list of sessions
        buildSessionPicker();
        toast(
          `🔐 New session #${sessionId} from ${data.initiator_username} — key unwrapped`,
          'success'
        );
      } else {
        toast(`New session #${sessionId} from ${data.initiator_username}`, 'info');
      }
    } catch (err) {
      console.error('[chat] new_session unwrap failed:', err);
      toast(`Failed to unwrap session #${sessionId} key`, 'error');
    }
  });

  /* ── Send message ──────────────────────────────────── */
  async function sendMessage() {
    const text = msgInput.value.trim();
    if (!text) return;

    let encrypted;
    if (_activeSessionId !== null && window.SessionCrypto) {
      // Private session: encrypt with the session's AES key
      const sessionKey = window.SessionCrypto.getSessionKey(_activeSessionId);
      if (!sessionKey) {
        toast('Session key not available — switch to Global Room or wait for key', 'error');
        return;
      }
      encrypted = await encryptWithKey(text, sessionKey);
    } else {
      // Global Room: encrypt with the shared demo key
      if (!_cryptoKey) {
        toast('No key loaded', 'error');
        return;
      }
      encrypted = await encryptText(text);
    }

    socket.emit('send_message', {
      token,
      session_id: _activeSessionId,
      ...encrypted,
    });

    msgInput.value = '';
    msgInput.focus();
  }

  sendBtn.addEventListener('click', sendMessage);
  msgInput.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
});
