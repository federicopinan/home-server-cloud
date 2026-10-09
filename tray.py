#!/usr/bin/env python3
"""DeCloud — Windows System Tray Manager.

Provides a system tray (notification area) icon to monitor and manage
DeCloud seamlessly in the background without needing a console window.

Features:
  - Visual status indicator (Running / Stopped)
  - One-click launch in browser (http://localhost:PORT)
  - Start / Stop / Restart actions
  - Copy passcode to clipboard
  - Graceful exit
"""
import os
import sys
import time
import subprocess
import webbrowser
from pathlib import Path
from PIL import Image

try:
    import pystray
    from pystray import MenuItem, Menu
except ImportError:
    print("pystray is required for the system tray: pip install pystray", file=sys.stderr)
    sys.exit(1)

APP_DIR = Path(__file__).parent.resolve()
ICON_PATH = APP_DIR / "static" / "icons" / "icon-192.png"

_server_proc = None


def get_port() -> int:
    """Read configured port from .env or fallback to 8899."""
    env_file = APP_DIR / ".env"
    if env_file.exists():
        try:
            for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("DECLOUD_PORT="):
                    val = line.split("=", 1)[1].strip()
                    if val.isdigit():
                        return int(val)
        except Exception:
            pass
    return int(os.environ.get("DECLOUD_PORT", "8899"))


PORT = get_port()


def get_pin() -> str:
    """Read configured PIN from .env."""
    env_file = APP_DIR / ".env"
    if env_file.exists():
        try:
            for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("DECLOUD_PIN="):
                    return line.split("=", 1)[1].strip()
        except Exception:
            pass
    return ""


def is_server_running(port: int = PORT) -> bool:
    """Check if DeCloud server is currently responding on the port."""
    import urllib.request
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/")
        with urllib.request.urlopen(req, timeout=1) as resp:
            return resp.status == 200
    except Exception:
        return False


def start_server() -> bool:
    """Start DeCloud server in background without a console window."""
    global _server_proc
    if is_server_running(PORT):
        return True

    py_exe = sys.executable
    pyw_exe = Path(py_exe).parent / "pythonw.exe"
    exe = str(pyw_exe) if pyw_exe.exists() else py_exe
    creationflags = 0x08000000  # CREATE_NO_WINDOW

    try:
        _server_proc = subprocess.Popen(
            [exe, str(APP_DIR / "app.py")],
            cwd=str(APP_DIR),
            creationflags=creationflags
        )
    except Exception as e:
        print(f"Error starting DeCloud: {e}", file=sys.stderr)
        return False

    # Wait up to 5 seconds for it to respond
    for _ in range(10):
        time.sleep(0.5)
        if is_server_running(PORT):
            return True
    return False


def stop_server():
    """Stop DeCloud server process."""
    global _server_proc
    if _server_proc and _server_proc.poll() is None:
        try:
            _server_proc.terminate()
            _server_proc.wait(timeout=2)
        except Exception:
            pass
        _server_proc = None

    # Also terminate any running instance of app.py owned by current workspace
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmd = proc.info.get('cmdline') or []
                if any('app.py' in str(arg) for arg in cmd) and proc.pid != os.getpid():
                    proc.terminate()
            except Exception:
                pass
    except Exception:
        pass


def copy_to_clipboard(text: str):
    """Copy text to Windows clipboard."""
    if not text:
        return
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        root.destroy()
    except Exception:
        try:
            subprocess.run(
                ['powershell', '-WindowStyle', 'Hidden', '-Command', f'Set-Clipboard -Value "{text}"'],
                check=False,
                creationflags=0x08000000
            )
        except Exception:
            pass


def on_open_browser(icon=None, item=None):
    """Open DeCloud in default web browser."""
    if not is_server_running(PORT):
        start_server()
    webbrowser.open(f"http://localhost:{PORT}")


def on_toggle_server(icon=None, item=None):
    """Toggle server state between Running and Stopped."""
    running = is_server_running(PORT)
    if running:
        stop_server()
        if icon:
            icon.notify("Servidor detenido", "DeCloud")
    else:
        if start_server():
            if icon:
                icon.notify(f"Servidor iniciado en http://localhost:{PORT}", "DeCloud")
        else:
            if icon:
                icon.notify("No se pudo iniciar el servidor", "DeCloud Error")


def on_copy_pin(icon=None, item=None):
    """Copy access PIN to clipboard."""
    pin = get_pin()
    if pin:
        copy_to_clipboard(pin)
        if icon:
            icon.notify(f"PIN ({pin}) copiado al portapapeles", "DeCloud")
    else:
        if icon:
            icon.notify("Modo abierto: sin PIN configurado", "DeCloud")


def on_quit(icon, item=None):
    """Exit tray app and stop server."""
    stop_server()
    icon.stop()


def get_status_text(item=None) -> str:
    """Return dynamic label showing current server status."""
    running = is_server_running(PORT)
    return f"Estado: {'Activo [ON]' if running else 'Detenido [OFF]'} (puerto {PORT})"


def get_toggle_text(item=None) -> str:
    """Return dynamic action label for start/stop."""
    return "Detener Servidor" if is_server_running(PORT) else "Iniciar Servidor"


def create_tray_icon() -> pystray.Icon:
    """Create and return configured pystray Icon instance."""
    if ICON_PATH.exists():
        image = Image.open(ICON_PATH)
    else:
        # Fallback 64x64 solid cyan image if icon file is missing
        image = Image.new("RGBA", (64, 64), (6, 182, 212, 255))

    menu = Menu(
        MenuItem(get_status_text, None, enabled=False),
        Menu.SEPARATOR,
        MenuItem("Abrir en Navegador", on_open_browser, default=True),
        MenuItem(get_toggle_text, on_toggle_server),
        MenuItem("Copiar PIN de acceso", on_copy_pin),
        Menu.SEPARATOR,
        MenuItem("Salir", on_quit)
    )

    return pystray.Icon("decloud", image, "DeCloud - Personal Cloud", menu)


def main():
    icon = create_tray_icon()
    # Auto-start server when tray starts if not already running
    if not is_server_running(PORT):
        start_server()
    icon.run()


if __name__ == "__main__":
    main()
