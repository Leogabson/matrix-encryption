/**
 * chat.js – Socket.IO client + AES-GCM helpers for the encrypted chat page.
 *
 * Dependencies (loaded via CDN in chat.html):
 *   - socket.io v4 client
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

/* ── AES-GCM via Web Crypto ──────────────────────────── */
let _cryptoKey = null; // CryptoKey object shared for this session

async function importRawKey(rawB64) {
  const raw = b64ToBytes(rawB64);
  _cryptoKey = await crypto.subtle.importKey(
    'raw', raw,
    { name: 'AES-GCM' },
    false,       // not extractable after import
    ['encrypt', 'decrypt']
  );
}

async function encryptText(plaintext) {
  if (!_cryptoKey) throw new Error('No crypto key loaded');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    _cryptoKey,
    enc.encode(plaintext)
  );
  // ct is ciphertext || 16-byte tag (browser format)
  const ctBytes = new Uint8Array(ct);
  const ciphertext = ctBytes.slice(0, -16);
  const tag       = ctBytes.slice(-16);
  return {
    ciphertext_b64: bytesToB64(ciphertext),
    iv_b64:         bytesToB64(iv),
    tag_b64:        bytesToB64(tag),
  };
}

async function decryptText({ ciphertext_b64, iv_b64, tag_b64 }) {
  if (!_cryptoKey) return '[key not loaded]';
  const iv  = b64ToBytes(iv_b64);
  const ct  = b64ToBytes(ciphertext_b64);
  const tag = b64ToBytes(tag_b64);
  // Re-join ciphertext + tag for Web Crypto
  const combined = new Uint8Array(ct.length + tag.length);
  combined.set(ct, 0);
  combined.set(tag, ct.length);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      _cryptoKey,
      combined
    );
    return new TextDecoder().decode(pt);
  } catch {
    return '⚠ decryption failed';
  }
}

/* ── Matrix Hacker Decryption Animation ──────────────── */
function matrixDecryptAnimate(element, targetText, duration = 1200) {
  const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%/\\+=_';
  const start = performance.now();
  
  function update(time) {
    const elapsed = time - start;
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
    
    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      element.textContent = targetText;
    }
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

/* ── Render E2EE Sophisticated Message Bubble ───────── */
function renderMessage(container, data, isSelf) {
  const wrapper = document.createElement('div');
  wrapper.className = `msg-row ${isSelf ? 'self' : 'other'}`;

  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble';

  // 1. Metadata Header
  const meta = document.createElement('div');
  meta.className = 'msg-meta';
  
  const senderSpan = document.createElement('span');
  senderSpan.textContent = `User ID: ${data.user_id}`;
  
  const timeSpan = document.createElement('span');
  timeSpan.textContent = new Date(data.timestamp).toLocaleTimeString();
  
  meta.appendChild(senderSpan);
  meta.appendChild(timeSpan);
  bubble.appendChild(meta);

  // 2. Message Body
  const body = document.createElement('p');
  body.className = 'msg-body';
  body.textContent = '🔒 Encrypted...';
  bubble.appendChild(body);

  // Cache decrypted plaintext
  let plaintextCached = null;

  // 3. E2EE Interactive Controls
  const controls = document.createElement('div');
  controls.className = 'msg-controls';

  const tabPlain = document.createElement('button');
  tabPlain.className = 'msg-tab active';
  tabPlain.textContent = 'Plaintext';

  const tabCipher = document.createElement('button');
  tabCipher.className = 'msg-tab';
  tabCipher.textContent = 'Ciphertext';

  const btnEnvelope = document.createElement('button');
  btnEnvelope.className = 'msg-tab';
  btnEnvelope.textContent = 'Cryptographic Envelope';

  controls.appendChild(tabPlain);
  controls.appendChild(tabCipher);
  controls.appendChild(btnEnvelope);
  bubble.appendChild(controls);

  // 4. Envelope Expandable Drawer
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

  // Perform Decryption & Animation
  decryptText({ ciphertext_b64: data.ciphertext, iv_b64: data.iv, tag_b64: data.tag })
    .then(pt => {
      plaintextCached = pt;
      
      // Automatic hacker unscrambling effect on receipt
      if (tabPlain.classList.contains('active')) {
        matrixDecryptAnimate(body, plaintextCached);
      }
    });

  // Tab Listeners
  tabPlain.addEventListener('click', () => {
    tabPlain.classList.add('active');
    tabCipher.classList.remove('active');
    body.style.fontFamily = 'var(--font-body)';
    body.style.color = '';
    body.textContent = plaintextCached || '[decryption failed]';
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

/* ── Main init ───────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', async () => {
  const token    = sessionStorage.getItem('token');
  const userId   = parseInt(sessionStorage.getItem('user_id') || '0', 10);
  const keyB64   = sessionStorage.getItem('aes_key');

  if (!token) { window.location.href = '/login.html'; return; }

  if (keyB64) {
    await importRawKey(keyB64);
  } else {
    toast('No AES key found – messages will not be decryptable', 'error');
  }

  const msgList  = $('msg-list');
  const msgInput = $('msg-input');
  const sendBtn  = $('send-btn');
  const status   = $('socket-status');

  /* ── Load history ──────────────────────────────────── */
  try {
    const res = await fetch('/api/chat/history', {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.ok) {
      const msgs = await res.json();
      msgs.forEach(m => renderMessage(msgList, m, m.user_id === userId));
    }
  } catch { /* ignore */ }

  /* ── Socket.IO connection ──────────────────────────── */
  const socket = io({ auth: { token } });

  socket.on('connect', () => {
    status.textContent  = '● Connected';
    status.className    = 'badge badge-green';
    toast('Socket.IO connected ✓', 'success');
  });

  socket.on('disconnect', () => {
    status.textContent = '● Disconnected';
    status.className   = 'badge badge-red';
  });

  socket.on('connect_error', (err) => {
    status.textContent = '● Error';
    status.className   = 'badge badge-red';
    toast(`Connection error: ${err.message}`, 'error');
  });

  socket.on('new_message', (data) => {
    renderMessage(msgList, data, data.user_id === userId);
  });

  /* ── Send message ──────────────────────────────────── */
  async function sendMessage() {
    const text = msgInput.value.trim();
    if (!text || !_cryptoKey) return;
    const encrypted = await encryptText(text);
    socket.emit('send_message', { token, ...encrypted });
    msgInput.value = '';
    msgInput.focus();
  }

  sendBtn.addEventListener('click', sendMessage);
  msgInput.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
});
