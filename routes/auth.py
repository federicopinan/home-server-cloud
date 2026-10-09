"""Authentication routes: passcode login and WebAuthn biometrics for DeCloud."""
from flask import Blueprint, jsonify, request, make_response
from shared import (
    app, DECLOUD_PIN, limiter, SESSIONS, SESSION_TTL_SECONDS, MAX_SESSIONS,
    _LOGIN_ATTEMPTS, _LOGIN_BACKOFF_WINDOW, _LOGIN_BACKOFF_MAX,
    _csrf_for_token, _purge_expired_sessions, _is_authenticated, BASE_DIR,
)
import hmac
import secrets
import time
import base64
import json
from datetime import datetime

bp = Blueprint('auth', __name__)


def _client_addr():
    return request.remote_addr or 'unknown'

def _record_failure(addr: str) -> float:
    """Record a failed attempt for an address; return seconds to back off."""
    now = time.time()
    attempts = [t for t in _LOGIN_ATTEMPTS.get(addr, []) if now - t < _LOGIN_BACKOFF_WINDOW]
    attempts.append(now)
    _LOGIN_ATTEMPTS[addr] = attempts
    # Exponential backoff once past the threshold
    over = max(0, len(attempts) - _LOGIN_BACKOFF_MAX)
    return min(8.0, 0.5 * (2 ** over)) if over else 0.0

def _clear_failures(addr: str):
    _LOGIN_ATTEMPTS.pop(addr, None)

@bp.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")  # Prevent passcode brute-force
def login():
    """Authenticate with the passcode. Sets a session-token cookie on success."""
    if not DECLOUD_PIN:
        return jsonify({'ok': True, 'message': 'Open mode — no passcode required'})

    addr = _client_addr()
    data = request.get_json(silent=True) or {}
    pin = data.get('pin', '')
    if not isinstance(pin, str) or not pin:
        return jsonify({'error': 'Invalid passcode'}), 401

    if not hmac.compare_digest(pin, DECLOUD_PIN):
        backoff = _record_failure(addr)
        if backoff > 0:
            time.sleep(backoff)
        return jsonify({'error': 'Invalid passcode'}), 401

    _clear_failures(addr)

    # Mint a fresh opaque session token. The passcode never leaves the server.
    token = secrets.token_urlsafe(32)
    _purge_expired_sessions()
    # Bound the session table so an attacker cannot fill memory with tokens
    if len(SESSIONS) >= MAX_SESSIONS:
        oldest = sorted(SESSIONS.items(), key=lambda kv: kv[1])[:1]
        for old_token, _ in oldest:
            SESSIONS.pop(old_token, None)
    SESSIONS[token] = time.time() + SESSION_TTL_SECONDS

    resp = make_response(jsonify({
        'ok': True,
        'session': token,
        'csrf': _csrf_for_token(token),
    }))
    resp.set_cookie(
        'decloud_session', token,
        httponly=True, samesite='Strict',
        secure=request.is_secure,  # HTTPS only when the request is HTTPS
        max_age=SESSION_TTL_SECONDS,
        path='/',
    )
    return resp

@bp.route('/api/auth/check', methods=['GET'])
def check_auth():
    """Check if the current session is authenticated."""
    if not DECLOUD_PIN:
        return jsonify({'authenticated': True, 'open_mode': True})

    token = request.cookies.get('decloud_session')
    if not token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()
    valid = bool(token) and token in SESSIONS and SESSIONS.get(token, 0) > time.time()
    if valid:
        return jsonify({
            'authenticated': True,
            'open_mode': False,
            'csrf': _csrf_for_token(token),
        })
    return jsonify({'authenticated': False, 'open_mode': False}), 401

@bp.route('/api/auth/logout', methods=['POST'])
def logout():
    """Invalidate the current session token."""
    token = request.cookies.get('decloud_session')
    if not token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()
    if token:
        SESSIONS.pop(token, None)
    resp = make_response(jsonify({'ok': True}))
    resp.delete_cookie('decloud_session')
    return resp


# ─── WebAuthn / Biometric Authentication ─────────────────────────────────

WEBAUTHN_FILE = BASE_DIR / 'webauthn_credentials.json'
_WEBAUTHN_CHALLENGES: dict[str, float] = {}  # challenge -> expiry epoch


def _load_webauthn_creds() -> list[dict]:
    if WEBAUTHN_FILE.exists():
        try:
            return json.loads(WEBAUTHN_FILE.read_text(encoding='utf-8'))
        except Exception:
            return []
    return []


def _save_webauthn_creds(creds: list[dict]):
    WEBAUTHN_FILE.write_text(json.dumps(creds, indent=2), encoding='utf-8')


def _purge_challenges():
    now = time.time()
    for ch in [ch for ch, exp in _WEBAUTHN_CHALLENGES.items() if exp <= now]:
        _WEBAUTHN_CHALLENGES.pop(ch, None)


def _b64url_decode(s: str) -> bytes:
    if isinstance(s, bytes):
        s = s.decode('utf-8')
    s = s.replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s)


def _verify_client_data_challenge(client_data_raw, expected_type):
    try:
        if isinstance(client_data_raw, str):
            try:
                decoded = _b64url_decode(client_data_raw)
            except Exception:
                decoded = client_data_raw.encode('utf-8')
        else:
            decoded = client_data_raw
        parsed = json.loads(decoded)
        if parsed.get('type') != expected_type:
            return False, f"Invalid type: expected {expected_type}, got {parsed.get('type')}"
        challenge = parsed.get('challenge')
        _purge_challenges()
        if not challenge or challenge not in _WEBAUTHN_CHALLENGES:
            return False, 'Invalid or expired challenge'
        _WEBAUTHN_CHALLENGES.pop(challenge, None)
        return True, None
    except Exception as e:
        return False, str(e)


@bp.route('/api/auth/webauthn/status', methods=['GET'])
def webauthn_status():
    """Return whether any WebAuthn credentials are registered."""
    creds = _load_webauthn_creds()
    return jsonify({
        'enabled': len(creds) > 0,
        'count': len(creds),
    })


@bp.route('/api/auth/webauthn/register/options', methods=['POST'])
def webauthn_register_options():
    """Generate registration options for navigator.credentials.create(). Requires auth."""
    if not _is_authenticated():
        return jsonify({'error': 'Authentication required'}), 401

    _purge_challenges()
    challenge = secrets.token_urlsafe(32)
    _WEBAUTHN_CHALLENGES[challenge] = time.time() + 120  # 2 minutes TTL

    rp_host = request.host.split(':')[0]
    options = {
        'challenge': challenge,
        'rp': {
            'name': 'DeCloud',
            'id': rp_host,
        },
        'user': {
            'id': secrets.token_hex(16),
            'name': 'decloud-admin',
            'displayName': 'DeCloud Admin',
        },
        'pubKeyCredParams': [
            {'alg': -7, 'type': 'public-key'},   # ES256
            {'alg': -257, 'type': 'public-key'}, # RS256
        ],
        'authenticatorSelection': {
            'authenticatorAttachment': 'platform',
            'userVerification': 'preferred',
            'residentKey': 'preferred',
        },
        'timeout': 60000,
        'attestation': 'none',
    }
    return jsonify(options)


@bp.route('/api/auth/webauthn/register/verify', methods=['POST'])
def webauthn_register_verify():
    """Verify and store a new WebAuthn credential. Requires auth."""
    if not _is_authenticated():
        return jsonify({'error': 'Authentication required'}), 401

    data = request.get_json(silent=True) or {}
    cred_id = data.get('id', '')
    response_data = data.get('response', {})
    client_data = response_data.get('clientDataJSON', '')

    if not cred_id or not client_data:
        return jsonify({'error': 'Invalid credential data'}), 400

    ok, err = _verify_client_data_challenge(client_data, 'webauthn.create')
    if not ok:
        return jsonify({'error': f'Registration failed: {err}'}), 400

    creds = _load_webauthn_creds()
    # Check if credential already registered
    if not any(c.get('id') == cred_id for c in creds):
        creds.append({
            'id': cred_id,
            'label': data.get('label') or f'Device {len(creds) + 1}',
            'created_at': datetime.utcnow().isoformat() + 'Z',
        })
        _save_webauthn_creds(creds)

    return jsonify({
        'ok': True,
        'message': 'Biometric device registered successfully',
    })


@bp.route('/api/auth/webauthn/login/options', methods=['POST'])
@limiter.limit("10 per minute")
def webauthn_login_options():
    """Generate assertion options for navigator.credentials.get()."""
    creds = _load_webauthn_creds()
    if not creds:
        return jsonify({'error': 'No biometric credentials registered on this server'}), 400

    _purge_challenges()
    challenge = secrets.token_urlsafe(32)
    _WEBAUTHN_CHALLENGES[challenge] = time.time() + 120

    rp_host = request.host.split(':')[0]
    options = {
        'challenge': challenge,
        'rpId': rp_host,
        'timeout': 60000,
        'userVerification': 'preferred',
        'allowCredentials': [
            {'id': c['id'], 'type': 'public-key', 'transports': ['internal']}
            for c in creds
        ],
    }
    return jsonify(options)


@bp.route('/api/auth/webauthn/login/verify', methods=['POST'])
@limiter.limit("10 per minute")
def webauthn_login_verify():
    """Verify biometric assertion and mint session."""
    data = request.get_json(silent=True) or {}
    cred_id = data.get('id', '')
    response_data = data.get('response', {})
    client_data = response_data.get('clientDataJSON', '')

    if not cred_id or not client_data:
        return jsonify({'error': 'Invalid assertion data'}), 400

    creds = _load_webauthn_creds()
    if not any(c.get('id') == cred_id for c in creds):
        return jsonify({'error': 'Unrecognized credential'}), 401

    ok, err = _verify_client_data_challenge(client_data, 'webauthn.get')
    if not ok:
        return jsonify({'error': f'Authentication failed: {err}'}), 401

    # Mint session token
    token = secrets.token_urlsafe(32)
    _purge_expired_sessions()
    if len(SESSIONS) >= MAX_SESSIONS:
        oldest = sorted(SESSIONS.items(), key=lambda kv: kv[1])[:1]
        for old_token, _ in oldest:
            SESSIONS.pop(old_token, None)
    SESSIONS[token] = time.time() + SESSION_TTL_SECONDS

    resp = make_response(jsonify({
        'ok': True,
        'session': token,
        'csrf': _csrf_for_token(token),
    }))
    resp.set_cookie(
        'decloud_session', token,
        httponly=True, samesite='Strict',
        secure=request.is_secure,
        max_age=SESSION_TTL_SECONDS,
        path='/',
    )
    return resp


@bp.route('/api/auth/webauthn/remove', methods=['POST'])
def webauthn_remove():
    """Clear all registered WebAuthn credentials. Requires auth."""
    if not _is_authenticated():
        return jsonify({'error': 'Authentication required'}), 401

    _save_webauthn_creds([])
    return jsonify({
        'ok': True,
        'message': 'All biometric credentials removed',
    })

