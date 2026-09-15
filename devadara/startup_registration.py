"""
startup_registration.py

Registers (or unregisters) DEVADARA to launch automatically at Windows
logon, via the per-user Registry Run key
(HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run).

Why this mechanism specifically: it needs no Administrator rights, only
runs for the user who's actually logged in (no protection theatre for a
session nobody's using), and - unlike a scheduled task - is directly
visible and removable by anyone via Task Manager's "Startup Apps" tab, not
just through this tool. That transparency matters for a security tool:
you should always be able to see and disable what starts with your PC
without needing to trust DEVADARA's own UI to tell you the truth.

The registered command points at startup_protect_cli.py, launched with
pythonw.exe (no console window) so nothing pops up at every login - see
devadara/startup_protect.py for where the resulting activity actually
goes (data/scan_log.jsonl) instead of a window. Once Step 7 packages this
as a standalone .exe, the exact same functions here start pointing at that
.exe instead (see _resolve_launch_command) - nothing else about this
module needs to change.

This module never runs anything itself - it only edits the one registry
value that controls whether Windows will run it for you.
"""

import os
import sys

import winreg

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAUNCHER_SCRIPT = os.path.join(PROJECT_ROOT, "startup_protect_cli.py")

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "DevadaraVirusGuard"


def _resolve_launch_command():
    """
    Build the command line Windows should run at logon.

    If this code is itself running inside a PyInstaller-frozen build
    (Step 7), sys.executable IS the packaged app - launch that directly.
    Otherwise (today, running from source), launch startup_protect_cli.py
    with pythonw.exe from the same Python installation that's running this
    code right now, so it's the same environment/dependencies already in
    use - falling back to whatever interpreter is currently running if a
    pythonw.exe can't be found next to it (unusual, but better than
    silently registering a broken command).
    """
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'

    pythonw_path = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(pythonw_path):
        pythonw_path = sys.executable

    return f'"{pythonw_path}" "{LAUNCHER_SCRIPT}"'


def is_in_startup():
    """Returns True if DEVADARA currently has a startup entry registered."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, VALUE_NAME)
        return True
    except FileNotFoundError:
        return False


def get_registered_command():
    """Returns the currently-registered launch command, or None if not registered."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ) as key:
            value, _value_type = winreg.QueryValueEx(key, VALUE_NAME)
        return value
    except FileNotFoundError:
        return None


def add_to_startup():
    """
    Register DEVADARA to launch at Windows logon. Safe to call repeatedly -
    it just overwrites the existing value with the current (correct)
    command, rather than creating duplicate entries.

    Returns the command that was registered.
    """
    command = _resolve_launch_command()
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_WRITE) as key:
        winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, command)
    return command


def remove_from_startup():
    """
    Unregister DEVADARA from Windows startup. Returns True if an entry was
    removed, False if it wasn't registered in the first place (not an
    error - the end state you wanted is already true).
    """
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_WRITE) as key:
            winreg.DeleteValue(key, VALUE_NAME)
        return True
    except FileNotFoundError:
        return False
