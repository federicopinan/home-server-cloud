"""Tests for WebAuthn biometric authentication routes."""
import json
import base64
import pytest
from routes.auth import _WEBAUTHN_CHALLENGES, WEBAUTHN_FILE


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')


@pytest.fixture(autouse=True)
def clean_webauthn_file():
    if WEBAUTHN_FILE.exists():
        WEBAUTHN_FILE.unlink()
    _WEBAUTHN_CHALLENGES.clear()
    yield
    if WEBAUTHN_FILE.exists():
        WEBAUTHN_FILE.unlink()
    _WEBAUTHN_CHALLENGES.clear()


class TestWebAuthn:
    def test_status_empty(self, client):
        r = client.get('/api/auth/webauthn/status')
        assert r.status_code == 200
        assert r.get_json() == {'enabled': False, 'count': 0}

    def test_register_options_requires_auth(self, client):
        r = client.post('/api/auth/webauthn/register/options')
        assert r.status_code == 401

    def test_register_flow(self, client, auth_headers):
        # 1. Get options
        r = client.post('/api/auth/webauthn/register/options', headers=auth_headers)
        assert r.status_code == 200
        data = r.get_json()
        challenge = data['challenge']
        assert challenge in _WEBAUTHN_CHALLENGES

        # 2. Mock clientDataJSON with the challenge
        client_data = json.dumps({
            'type': 'webauthn.create',
            'challenge': challenge,
            'origin': 'http://localhost:8899'
        }).encode('utf-8')
        client_data_b64 = _b64url_encode(client_data)

        # 3. Verify
        cred_id = 'test-cred-id-12345'
        payload = {
            'id': cred_id,
            'response': {
                'clientDataJSON': client_data_b64,
                'attestationObject': _b64url_encode(b'dummy-attestation')
            }
        }
        vr = client.post('/api/auth/webauthn/register/verify', json=payload, headers=auth_headers)
        assert vr.status_code == 200
        assert vr.get_json()['ok'] is True

        # 4. Check status
        st = client.get('/api/auth/webauthn/status').get_json()
        assert st['enabled'] is True
        assert st['count'] == 1

    def test_login_flow(self, client, auth_headers):
        # First register a credential
        r = client.post('/api/auth/webauthn/register/options', headers=auth_headers)
        challenge = r.get_json()['challenge']
        client_data = json.dumps({
            'type': 'webauthn.create',
            'challenge': challenge,
            'origin': 'http://localhost:8899'
        }).encode('utf-8')
        cred_id = 'biometric-key-abc'
        client.post('/api/auth/webauthn/register/verify', json={
            'id': cred_id,
            'response': {'clientDataJSON': _b64url_encode(client_data)}
        }, headers=auth_headers)

        # Now test login options (public endpoint)
        l_opt = client.post('/api/auth/webauthn/login/options')
        assert l_opt.status_code == 200
        l_data = l_opt.get_json()
        login_challenge = l_data['challenge']
        assert any(c['id'] == cred_id for c in l_data['allowCredentials'])

        # Now test login verify (public endpoint)
        login_client_data = json.dumps({
            'type': 'webauthn.get',
            'challenge': login_challenge,
            'origin': 'http://localhost:8899'
        }).encode('utf-8')

        login_payload = {
            'id': cred_id,
            'response': {
                'clientDataJSON': _b64url_encode(login_client_data),
                'authenticatorData': _b64url_encode(b'auth-data'),
                'signature': _b64url_encode(b'signature')
            }
        }
        l_ver = client.post('/api/auth/webauthn/login/verify', json=login_payload)
        assert l_ver.status_code == 200
        ver_resp = l_ver.get_json()
        assert ver_resp['ok'] is True
        assert 'session' in ver_resp
        assert 'decloud_session' in l_ver.headers.get('Set-Cookie', '')

    def test_remove_webauthn(self, client, auth_headers):
        # Register one
        r = client.post('/api/auth/webauthn/register/options', headers=auth_headers)
        challenge = r.get_json()['challenge']
        client_data = json.dumps({'type': 'webauthn.create', 'challenge': challenge}).encode('utf-8')
        client.post('/api/auth/webauthn/register/verify', json={
            'id': 'cred-to-delete',
            'response': {'clientDataJSON': _b64url_encode(client_data)}
        }, headers=auth_headers)

        assert client.get('/api/auth/webauthn/status').get_json()['enabled'] is True

        # Remove
        rem = client.post('/api/auth/webauthn/remove', headers=auth_headers)
        assert rem.status_code == 200
        assert client.get('/api/auth/webauthn/status').get_json()['enabled'] is False
