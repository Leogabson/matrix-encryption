/**
 * cipherlab.js – client-side logic for the Cipher Lab demo page.
 * Calls the backend REST API endpoints to encrypt / decrypt using
 * AES-GCM and the Hill Cipher.
 */

const $ = id => document.getElementById(id);

/* ── Toast ────────────────────────────────────────────── */
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

/* ── Generic API call ─────────────────────────────────── */
async function callApi(endpoint, body) {
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

/* ── Copy-to-clipboard helper ─────────────────────────── */
function copyText(text) {
  navigator.clipboard.writeText(text).then(() => toast('Copied to clipboard ✓', 'success'));
}

/* ── AES-GCM section ──────────────────────────────────── */
function initAes() {
  const encryptBtn  = $('aes-encrypt-btn');
  const decryptBtn  = $('aes-decrypt-btn');

  encryptBtn?.addEventListener('click', async () => {
    const plaintext = $('aes-plaintext').value.trim();
    const keyInput  = $('aes-key').value.trim();
    if (!plaintext) { toast('Enter plaintext first', 'error'); return; }

    encryptBtn.disabled = true;
    try {
      const body = { plaintext };
      if (keyInput) body.key_b64 = keyInput;

      const data = await callApi('/api/cipherlab/aes/encrypt', body);

      $('aes-key').value            = data.key_b64;
      $('aes-result-ct').textContent = data.ciphertext_b64;
      $('aes-result-iv').textContent = data.iv_b64;
      $('aes-result-tag').textContent = data.tag_b64;
      $('aes-result-box').hidden     = false;
      toast('Encrypted ✓', 'success');
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      encryptBtn.disabled = false;
    }
  });

  decryptBtn?.addEventListener('click', async () => {
    const key_b64        = $('aes-key').value.trim();
    const ciphertext_b64 = $('aes-dec-ct').value.trim();
    const iv_b64         = $('aes-dec-iv').value.trim();
    const tag_b64        = $('aes-dec-tag').value.trim();

    if (!key_b64 || !ciphertext_b64 || !iv_b64 || !tag_b64) {
      toast('Fill in all decrypt fields', 'error'); return;
    }

    decryptBtn.disabled = true;
    try {
      const data = await callApi('/api/cipherlab/aes/decrypt', { key_b64, ciphertext_b64, iv_b64, tag_b64 });
      $('aes-dec-result').textContent = data.plaintext;
      $('aes-dec-result-box').hidden  = false;
      toast('Decrypted ✓', 'success');
    } catch (e) {
      toast(`Decryption failed: ${e.message}`, 'error');
    } finally {
      decryptBtn.disabled = false;
    }
  });

  // Copy buttons
  $('copy-ct')?.addEventListener('click',  () => copyText($('aes-result-ct').textContent));
  $('copy-iv')?.addEventListener('click',  () => copyText($('aes-result-iv').textContent));
  $('copy-tag')?.addEventListener('click', () => copyText($('aes-result-tag').textContent));
}

/* ── Hill Cipher section ──────────────────────────────── */
function parseMatrix(str) {
  // Accept JSON array or whitespace-separated rows like "6 24 1 / 13 16 10 / 20 17 15"
  str = str.trim();
  if (str.startsWith('[')) return JSON.parse(str);
  return str.split('/').map(row => row.trim().split(/\s+/).map(Number));
}

function initHill() {
  const encryptBtn = $('hill-encrypt-btn');
  const decryptBtn = $('hill-decrypt-btn');

  encryptBtn?.addEventListener('click', async () => {
    const plaintext = $('hill-plaintext').value.trim();
    const matrixStr = $('hill-matrix').value.trim();
    if (!plaintext || !matrixStr) { toast('Enter plaintext and key matrix', 'error'); return; }

    encryptBtn.disabled = true;
    try {
      const key_matrix = parseMatrix(matrixStr);
      const data = await callApi('/api/cipherlab/hill/encrypt', { plaintext, key_matrix });
      $('hill-result').textContent    = data.ciphertext;
      $('hill-result-box').hidden     = false;
      toast('Encrypted ✓', 'success');
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      encryptBtn.disabled = false;
    }
  });

  decryptBtn?.addEventListener('click', async () => {
    const ciphertext = $('hill-ciphertext').value.trim();
    const matrixStr  = $('hill-matrix').value.trim();
    if (!ciphertext || !matrixStr) { toast('Enter ciphertext and key matrix', 'error'); return; }

    decryptBtn.disabled = true;
    try {
      const key_matrix = parseMatrix(matrixStr);
      const data = await callApi('/api/cipherlab/hill/decrypt', { ciphertext, key_matrix });
      $('hill-dec-result').textContent = data.plaintext;
      $('hill-dec-result-box').hidden  = false;
      toast('Decrypted ✓', 'success');
    } catch (e) {
      toast(`Decryption failed: ${e.message}`, 'error');
    } finally {
      decryptBtn.disabled = false;
    }
  });
}

/* ── Boot ─────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initAes();
  initHill();
});
