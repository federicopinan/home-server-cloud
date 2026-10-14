"""Configuration hardening tests."""
import os

import pytest


def test_remote_host_without_pin_is_rejected(monkeypatch):
    from shared import validate_security_config

    with pytest.raises(SystemExit, match='DECLOUD_PIN'):
        validate_security_config(
            host='0.0.0.0', pin='', secret_key='x' * 64,
        )


def test_remote_host_rejects_short_secret():
    from shared import validate_security_config

    with pytest.raises(SystemExit, match='SECRET_KEY'):
        validate_security_config(
            host='0.0.0.0', pin='secure-passcode', secret_key='short',
        )


def test_localhost_allows_ephemeral_secret():
    from shared import validate_security_config

    assert validate_security_config(
        host='127.0.0.1', pin='secure-passcode', secret_key='',
    ) is False
