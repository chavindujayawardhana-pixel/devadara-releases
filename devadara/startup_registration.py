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

The registered command points at gui_app.py (the GUI entry point),
launched with pythonw.exe (no console window) plus an --autostart flag -
a normal launch, main window and all, except that it hides itself to the
tray after a few seconds unless you interact with it; see
devadara_gui/main_window.py for the tray icon that lets it keep running
in the background once closed with X. Once Step 7 packages this as a
standalone .exe, the exact same functions here start pointing at that
.exe instead (see _resolve_launch_command) - nothing else about this
module needs to change.

This module never runs anything itself - it only edits the one registry
value that controls whether Windows will run it for you.
"""

import os
import sys

import winreg

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAUNCHER_SCRIPT = os.path.join(PROJECT_ROOT, "gui_app.py")

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
APPROVED_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
VALUE_NAME = "DevadaraVirusGuard"

# Appended to the registered command so gui_app.py can tell a Windows-logon
# launch apart from a manual one - only the logon launch auto-hides to the
# tray after a few seconds (see gui_app.py / MainWindow.schedule_auto_hide).
AUTOSTART_FLAG = "--autostart"


def _resolve_launch_command():
    """
    Build the command line Windows should run at logon.

    If this code is itself running inside a PyInstaller-frozen build
    (Step 7), sys.executable IS the packaged app - launch that directly.
    Otherwise (today, running from source), launch gui_app.py with
    pythonw.exe from the same Python installation that's running this
    code right now, so it's the same environment/dependencies already in
    use - falling back to whatever interpreter is currently running if a
    pythonw.exe can't be found next to it (unusual, but better than
    silently registering a broken command).
    """
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" {AUTOSTART_FLAG}'

    pythonw_path = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(pythonw_path):
        pythonw_path = sys.executable

    return f'"{pythonw_path}" "{LAUNCHER_SCRIPT}" {AUTOSTART_FLAG}'


def _is_disabled_in_task_manager():
    """
    Task Manager's Startup apps "Disable" leaves the Run value in place
    and instead writes a 12-byte REG_BINARY under StartupApproved\\Run:
    first byte 0x02/0x06 = enabled, 0x03 = disabled (odd low bit), last 8
    bytes a FILETIME. A missing/empty/unreadable value means enabled
    (Windows' own default).
    """
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, APPROVED_KEY_PATH, 0, winreg.KEY_READ) as key:
            value, _value_type = winreg.QueryValueEx(key, VALUE_NAME)
    except OSError:
        return False
    return isinstance(value, bytes) and len(value) > 0 and bool(value[0] & 1)


def _clear_task_manager_disable():
    """Delete our StartupApproved\\Run value - Windows treats a missing
    value as enabled, so this undoes a Task Manager "Disable"."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, APPROVED_KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, VALUE_NAME)
    except FileNotFoundError:
        pass


def is_in_startup():
    """Returns True if DEVADARA currently has a startup entry registered
    AND Windows will actually launch it (not disabled in Task Manager)."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, VALUE_NAME)
    except FileNotFoundError:
        return False
    return not _is_disabled_in_task_manager()


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
    _clear_task_manager_disable()
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
