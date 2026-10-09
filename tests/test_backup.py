"""Tests for DeCloud Backup and Restore routes."""
import io
import json
import zipfile
import pytest


class TestBackupRestore:
    def test_backup_requires_auth(self, client):
        r = client.get('/api/system/backup')
        assert r.status_code == 401

    def test_backup_generation_success(self, client, auth_headers):
        r = client.get('/api/system/backup', headers=auth_headers)
        assert r.status_code == 200
        assert r.mimetype == 'application/zip'
        
        # Verify it's a valid zip archive
        buf = io.BytesIO(r.data)
        with zipfile.ZipFile(buf, 'r') as zf:
            names = zf.namelist()
            assert 'backup_manifest.json' in names
            manifest = json.loads(zf.read('backup_manifest.json'))
            assert manifest.get('app') == 'DeCloud'

    def test_restore_requires_auth(self, client):
        r = client.post('/api/system/restore')
        assert r.status_code in (401, 403)

    def test_restore_rejects_missing_file(self, client, auth_headers):
        r = client.post('/api/system/restore', headers=auth_headers)
        assert r.status_code == 400
        assert 'No backup file provided' in r.get_json()['error']

    def test_restore_rejects_unsafe_paths(self, client, auth_headers):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('../evil.txt', 'malicious content')
        buf.seek(0)

        data = {'file': (buf, 'backup.zip')}
        r = client.post(
            '/api/system/restore',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        assert r.status_code == 400
        assert 'Unsafe archive path' in r.get_json()['error']

    def test_restore_valid_archive(self, client, auth_headers):
        buf = io.BytesIO()
        test_settings = {'theme': 'dark', 'test_key': 'test_val'}
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('config/settings.json', json.dumps(test_settings))
            zf.writestr('backup_manifest.json', json.dumps({'app': 'DeCloud'}))
        buf.seek(0)

        data = {'file': (buf, 'backup.zip')}
        r = client.post(
            '/api/system/restore',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        assert r.status_code == 200
        res = r.get_json()
        assert res.get('ok') is True
        assert 'settings.json' in res.get('restored', [])
