// ===== Module: auth =====
// Passcode login screen logic — checks auth on load, shows login if needed.

let _loginPin = '';
let _loginBusy = false;
const _LOGIN_PIN_MAX = 10;  // keypad supports 6–10 digits; longer passcodes via UI only

// Check auth on page load — show login screen or main app
(async function checkAuthOnLoad() {
  try {
    const r = await fetch('/api/auth/check');
    const d = await r.json();
    if (d.authenticated) {
      // Already authenticated — stash the CSRF token for state-changing calls
      if (d.csrf) sessionStorage.setItem('decloud_csrf', d.csrf);
      hideLoginScreen();
    } else {
      // Need to log in
      showLoginScreen();
    }
  } catch (e) {
    // If auth check fails (network error, etc.), assume not authenticated
    // but only show login if we get a clear 401
    console.warn('Auth check failed:', e);
  }
})();

function showLoginScreen() {
  const login = document.getElementById('login-screen');
  if (login) login.style.display = 'flex';
  // Hide all app screens
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  renderLoginDots();
  checkBiometricsForLogin();
}

function hideLoginScreen() {
  const login = document.getElementById('login-screen');
  if (login) login.style.display = 'none';
  // Show home screen
  const home = document.getElementById('home-screen');
  if (home) home.classList.add('active');
}

function renderLoginDots() {
  const dots = document.getElementById('login-dots');
  if (!dots) return;
  dots.innerHTML = '';
  for (let i = 0; i < Math.max(_loginPin.length, 1); i++) {
    const span = document.createElement('span');
    span.className = 'login-dot' + (i < _loginPin.length ? ' filled' : '');
    dots.appendChild(span);
  }
}

function loginPress(key) {
  if (_loginBusy) return;
  if (_loginPin.length >= _LOGIN_PIN_MAX) return;
  _loginPin += key;
  renderLoginDots();
  // Clear any previous error
  const err = document.getElementById('login-error');
  if (err) err.classList.remove('show');
}

function loginGo() {
  if (_loginBusy) return;
  if (_loginPin.length < 6) {
    loginFail('Passcode is at least 6 digits');
    return;
  }
  submitLogin();
}

function loginBack() {
  if (_loginBusy) return;
  if (_loginPin.length > 0) {
    _loginPin = _loginPin.slice(0, -1);
    renderLoginDots();
    const err = document.getElementById('login-error');
    if (err) err.classList.remove('show');
  }
}

async function submitLogin() {
  _loginBusy = true;
  const err = document.getElementById('login-error');
  try {
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin: _loginPin }),
    });
    const d = await r.json();
    if (r.ok && d.ok) {
      // Store the session token (not the PIN) for the cross-origin Bearer
      // fallback and the CSRF token for state-changing requests.
      // The PIN must never live in browser storage.
      if (d.session) {
        sessionStorage.setItem('decloud_session', d.session);
      }
      if (d.csrf) {
        sessionStorage.setItem('decloud_csrf', d.csrf);
      }
      // Success — reload to get the main app with auth cookie set
      window.location.reload();
      return;
    }
    // Failed — show error and shake
    loginFail(d.error || 'Invalid passcode');
  } catch (e) {
    loginFail('Network error — try again');
  }
}

function loginFail(msg) {
  _loginBusy = false;
  _loginPin = '';
  renderLoginDots();
  const err = document.getElementById('login-error');
  if (err) {
    err.textContent = msg;
    err.classList.add('show');
  }
  // Shake the card
  const card = document.querySelector('.login-card');
  if (card) {
    card.classList.remove('shake');
    void card.offsetWidth; // trigger reflow to restart animation
    card.classList.add('shake');
  }
  // Haptic feedback
  if (navigator.vibrate) navigator.vibrate(100);
}

async function logout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } catch (e) {
    console.warn('Logout request failed:', e);
  }
  sessionStorage.removeItem('decloud_session');
  sessionStorage.removeItem('decloud_csrf');
  window.location.reload();
}

// Expose for inline onclick handlers
window.logout = logout;
window.loginPress = loginPress;
window.loginBack = loginBack;
window.loginGo = loginGo;

// ─── WebAuthn / Biometrics ────────────────────────────────────────────────

function _bufFromB64(b64) {
  var b = b64.replace(/-/g, '+').replace(/_/g, '/');
  while (b.length % 4) b += '=';
  var bin = atob(b);
  var arr = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}

function _b64FromBuf(buf) {
  var bytes = new Uint8Array(buf);
  var bin = '';
  for (var i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function checkBiometricsForLogin() {
  if (!window.PublicKeyCredential) return;
  try {
    const r = await fetch('/api/auth/webauthn/status');
    const d = await r.json();
    const bioSection = document.getElementById('login-biometric-section');
    if (bioSection) {
      bioSection.style.display = (d.enabled ? 'block' : 'none');
    }
  } catch (e) {
    console.warn('WebAuthn status check failed:', e);
  }
}

async function loginWithBiometrics() {
  if (!window.PublicKeyCredential) {
    loginFail('Biometrics not supported on this browser');
    return;
  }
  const err = document.getElementById('login-error');
  if (err) err.classList.remove('show');

  try {
    // 1. Get assertion options from server
    const optRes = await fetch('/api/auth/webauthn/login/options', { method: 'POST' });
    const options = await optRes.json();
    if (!optRes.ok || options.error) {
      loginFail(options.error || 'Biometric authentication failed');
      return;
    }

    // Convert challenge and credential IDs to ArrayBuffer
    options.challenge = _bufFromB64(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map(c => Object.assign({}, c, {
        id: _bufFromB64(c.id)
      }));
    }

    // 2. Prompt authenticator (Windows Hello, Touch ID, Face ID, etc.)
    const assertion = await navigator.credentials.get({ publicKey: options });
    if (!assertion) {
      loginFail('Biometric prompt canceled');
      return;
    }

    // 3. Send signed assertion to server for verification
    const verifyPayload = {
      id: assertion.id,
      rawId: _b64FromBuf(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: _b64FromBuf(assertion.response.clientDataJSON),
        authenticatorData: _b64FromBuf(assertion.response.authenticatorData),
        signature: _b64FromBuf(assertion.response.signature)
      }
    };

    const verRes = await fetch('/api/auth/webauthn/login/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(verifyPayload)
    });
    const verData = await verRes.json();

    if (verRes.ok && verData.ok) {
      if (verData.session) sessionStorage.setItem('decloud_session', verData.session);
      if (verData.csrf) sessionStorage.setItem('decloud_csrf', verData.csrf);
      window.location.reload();
      return;
    }

    loginFail(verData.error || 'Biometric verification rejected');
  } catch (e) {
    console.error('Biometric login error:', e);
    loginFail(e.name === 'NotAllowedError' ? 'Biometric prompt canceled' : 'Biometric error');
  }
}

async function checkWebAuthnSettings() {
  const statusEl = document.getElementById('bio-settings-status');
  const removeBtn = document.getElementById('bio-remove-btn');
  if (!statusEl) return;

  if (!window.PublicKeyCredential) {
    statusEl.textContent = 'Biometric authentication (WebAuthn) is not supported by this browser.';
    if (removeBtn) removeBtn.style.display = 'none';
    return;
  }

  try {
    const r = await fetch('/api/auth/webauthn/status');
    const d = await r.json();
    if (d.enabled) {
      statusEl.textContent = `✓ Biometric authentication active (${d.count} device${d.count > 1 ? 's' : ''} enrolled).`;
      if (removeBtn) removeBtn.style.display = 'inline-block';
    } else {
      statusEl.textContent = 'No biometric devices enrolled yet. Register this device below.';
      if (removeBtn) removeBtn.style.display = 'none';
    }
  } catch (e) {
    statusEl.textContent = 'Unable to check biometric status.';
  }
}

async function registerBiometrics() {
  const note = document.getElementById('bio-status-note');
  if (note) {
    note.textContent = 'Prompting device authenticator…';
    note.className = 'settings-note';
  }

  if (!window.PublicKeyCredential) {
    if (note) {
      note.textContent = '✗ WebAuthn is not supported on this browser';
      note.className = 'settings-note settings-note-err';
    }
    return;
  }

  try {
    const csrf = sessionStorage.getItem('decloud_csrf') || '';
    const optRes = await fetch('/api/auth/webauthn/register/options', {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrf }
    });
    const options = await optRes.json();
    if (!optRes.ok || options.error) {
      if (note) {
        note.textContent = '✗ ' + (options.error || 'Failed to start registration');
        note.className = 'settings-note settings-note-err';
      }
      return;
    }

    options.challenge = _bufFromB64(options.challenge);
    options.user.id = _bufFromB64(options.user.id);

    const credential = await navigator.credentials.create({ publicKey: options });
    if (!credential) {
      if (note) {
        note.textContent = '✗ Registration canceled';
        note.className = 'settings-note settings-note-err';
      }
      return;
    }

    const verifyPayload = {
      id: credential.id,
      rawId: _b64FromBuf(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: _b64FromBuf(credential.response.clientDataJSON),
        attestationObject: _b64FromBuf(credential.response.attestationObject)
      }
    };

    const verRes = await fetch('/api/auth/webauthn/register/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf
      },
      body: JSON.stringify(verifyPayload)
    });
    const verData = await verRes.json();

    if (verRes.ok && verData.ok) {
      if (note) {
        note.textContent = '✓ Device registered! You can now log in using biometrics.';
        note.className = 'settings-note settings-note-ok';
      }
      checkWebAuthnSettings();
    } else {
      if (note) {
        note.textContent = '✗ ' + (verData.error || 'Verification failed');
        note.className = 'settings-note settings-note-err';
      }
    }
  } catch (e) {
    if (note) {
      note.textContent = '✗ ' + (e.name === 'NotAllowedError' ? 'Prompt canceled' : e.message);
      note.className = 'settings-note settings-note-err';
    }
  }
}

async function removeBiometrics() {
  if (!confirm('Remove all biometric devices enrolled for DeCloud?')) return;
  const note = document.getElementById('bio-status-note');
  try {
    const csrf = sessionStorage.getItem('decloud_csrf') || '';
    const r = await fetch('/api/auth/webauthn/remove', {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrf }
    });
    const d = await r.json();
    if (r.ok && d.ok) {
      if (note) {
        note.textContent = '✓ Biometric credentials removed';
        note.className = 'settings-note settings-note-ok';
      }
      checkWebAuthnSettings();
    } else {
      if (note) {
        note.textContent = '✗ ' + (d.error || 'Failed to remove credentials');
        note.className = 'settings-note settings-note-err';
      }
    }
  } catch (e) {
    if (note) {
      note.textContent = '✗ Network error';
      note.className = 'settings-note settings-note-err';
    }
  }
}

window.loginWithBiometrics = loginWithBiometrics;
window.checkWebAuthnSettings = checkWebAuthnSettings;
window.registerBiometrics = registerBiometrics;
window.removeBiometrics = removeBiometrics;

