"""DeCloud — Backup and Restore route blueprint."""
import io
import os
import json
import zipfile
from datetime import datetime
from pathlib import Path
from flask import Blueprint, jsonify, request, send_file
from shared import BASE_DIR, SETTINGS_FILE, AUDIO_DIR, TELEMETRY_DIR, limiter

bp = Blueprint('backup', __name__)


@bp.route('/api/system/backup', methods=['GET'])
@limiter.limit("10 per minute")
def export_backup():
    """Generate and download a compressed zip archive of user data and config."""
    buf = io.BytesIO()
    manifest = {
        'app': 'DeCloud',
        'version': '0.0.2',
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'files': []
    }

    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Settings
        if SETTINGS_FILE.exists():
            zf.write(SETTINGS_FILE, 'config/settings.json')
            manifest['files'].append('config/settings.json')

        # Environment config
        env_file = BASE_DIR / '.env'
        if env_file.exists():
            zf.write(env_file, 'config/.env')
            manifest['files'].append('config/.env')

        # Usage data
        usage_file = BASE_DIR / 'usage.json'
        if usage_file.exists():
            zf.write(usage_file, 'data/usage.json')
            manifest['files'].append('data/usage.json')

        # WebAuthn credentials
        webauthn_file = BASE_DIR / 'webauthn_credentials.json'
        if webauthn_file.exists():
            zf.write(webauthn_file, 'config/webauthn_credentials.json')
            manifest['files'].append('config/webauthn_credentials.json')

        # Telemetry directory
        if TELEMETRY_DIR.exists():
            for f in TELEMETRY_DIR.glob('*'):
                if f.is_file():
                    arcname = f'telemetry/{f.name}'
                    zf.write(f, arcname)
                    manifest['files'].append(arcname)

        # Audiobooks positions and bookmarks
        if AUDIO_DIR.exists():
            for f in AUDIO_DIR.glob('*_position.json'):
                arcname = f'audio_cache/{f.name}'
                zf.write(f, arcname)
                manifest['files'].append(arcname)
            for f in AUDIO_DIR.glob('*_settings.json'):
                arcname = f'audio_cache/{f.name}'
                zf.write(f, arcname)
                manifest['files'].append(arcname)

        # Write manifest
        zf.writestr('backup_manifest.json', json.dumps(manifest, indent=2))

    buf.seek(0)
    filename = f"decloud-backup-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.zip"
    return send_file(
        buf,
        mimetype='application/zip',
        as_attachment=True,
        download_name=filename
    )


@bp.route('/api/system/restore', methods=['POST'])
@limiter.limit("5 per minute")
def restore_backup():
    """Upload and restore data from a valid DeCloud zip backup."""
    if 'file' not in request.files:
        return jsonify({'error': 'No backup file provided'}), 400

    uploaded_file = request.files['file']
    if not uploaded_file.filename.endswith('.zip'):
        return jsonify({'error': 'Invalid file format (must be a .zip file)'}), 400

    try:
        file_bytes = uploaded_file.read()
        zf = zipfile.ZipFile(io.BytesIO(file_bytes))
    except Exception as e:
        return jsonify({'error': f'Invalid or corrupted zip archive: {e}'}), 400

    # Path traversal and Zip Slip security validation
    namelist = zf.namelist()
    for name in namelist:
        norm = os.path.normpath(name)
        if norm.startswith('..') or os.path.isabs(norm):
            return jsonify({'error': f'Unsafe archive path detected: {name}'}), 400

    restored = []

    # 1. Restore settings.json
    if 'config/settings.json' in namelist:
        data = zf.read('config/settings.json')
        SETTINGS_FILE.write_bytes(data)
        restored.append('settings.json')

    # 2. Restore usage.json
    if 'data/usage.json' in namelist:
        data = zf.read('data/usage.json')
        (BASE_DIR / 'usage.json').write_bytes(data)
        restored.append('usage.json')

    # 2b. Restore webauthn_credentials.json
    if 'config/webauthn_credentials.json' in namelist:
        data = zf.read('config/webauthn_credentials.json')
        (BASE_DIR / 'webauthn_credentials.json').write_bytes(data)
        restored.append('webauthn_credentials.json')

    # 3. Restore audiobooks bookmarks and playback positions
    AUDIO_DIR.mkdir(exist_ok=True)
    for name in namelist:
        if name.startswith('audio_cache/') and (name.endswith('_position.json') or name.endswith('_settings.json')):
            filename = os.path.basename(name)
            if filename:
                data = zf.read(name)
                (AUDIO_DIR / filename).write_bytes(data)
                restored.append(f'audio_cache/{filename}')

    # 4. Restore telemetry data
    if any(name.startswith('telemetry/') for name in namelist):
        TELEMETRY_DIR.mkdir(exist_ok=True)
        for name in namelist:
            if name.startswith('telemetry/') and not name.endswith('/'):
                filename = os.path.basename(name)
                if filename:
                    data = zf.read(name)
                    (TELEMETRY_DIR / filename).write_bytes(data)
                    restored.append(f'telemetry/{filename}')

    # 5. Restore .env (preserving backup copy of prior .env)
    if 'config/.env' in namelist:
        env_content = zf.read('config/.env').decode('utf-8', errors='ignore')
        env_file = BASE_DIR / '.env'
        if env_file.exists():
            (BASE_DIR / '.env.bak').write_bytes(env_file.read_bytes())
        env_file.write_text(env_content, encoding='utf-8')
        restored.append('.env')

    return jsonify({
        'ok': True,
        'message': f'Successfully restored {len(restored)} items',
        'restored': restored
    })
