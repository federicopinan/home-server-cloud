"""Tests for Windows System Tray integration (tray.py)."""
import sys
import pytest

@pytest.mark.skipif(sys.platform != 'win32', reason="Windows-only system tray test")
def test_tray_module_initialization():
    import tray
    assert tray.PORT > 0
    assert isinstance(tray.get_status_text(), str)
    assert isinstance(tray.get_toggle_text(), str)
    
    icon = tray.create_tray_icon()
    assert icon is not None
    assert icon.name == "decloud"
    assert len(icon.menu.items) >= 5
