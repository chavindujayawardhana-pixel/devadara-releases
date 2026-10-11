"""
app_paths.py

The one place DEVADARA decides where its files live, split by whether the
app may change them:

- APP_DIR   - read-only program files shipped with the app: YARA rules,
              the ML model, tools/yara64.exe, the bundled known-bad and
              trusted-publisher lists, icons. In a packaged build these are
              covered by the signed integrity manifest, so nothing at
              runtime may write here.
- STATE_DIR - everything the app writes at runtime: GUI settings, the scan
              log, the ignore list, memory hashes, the quarantine.
- INSTALL_ROOT - the folder the user installed/runs from (where the
              integrity manifest sits next to the exe in a packaged build).

Running from source (python gui_app.py), all three resolve to exactly the
paths the modules used before this file existed: APP_DIR and INSTALL_ROOT
are the project root, STATE_DIR is <project root>/data.

In a PyInstaller --onedir build (sys.frozen): INSTALL_ROOT is the folder
holding the exe, APP_DIR is PyInstaller's bundle folder (sys._MEIPASS,
the _internal folder), and STATE_DIR is %LOCALAPPDATA%\\DEVADARA - per
user, writable without admin rights even when installed under Program
Files, and outside the signed install folder.
"""

import os
import sys

FROZEN = bool(getattr(sys, "frozen", False))

if FROZEN:
    INSTALL_ROOT = os.path.dirname(os.path.abspath(sys.executable))
    APP_DIR = getattr(sys, "_MEIPASS", INSTALL_ROOT)
    STATE_DIR = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "DEVADARA")
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
    except OSError:
        pass  # each writer already degrades on a failed write
else:
    INSTALL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    APP_DIR = INSTALL_ROOT
    STATE_DIR = os.path.join(INSTALL_ROOT, "data")


def app_file(*parts):
    """A read-only program file, e.g. app_file("data", "yara_rules")."""
    return os.path.join(APP_DIR, *parts)


def state_file(*parts):
    """A file the app writes at runtime, e.g. state_file("scan_log.jsonl")."""
    return os.path.join(STATE_DIR, *parts)
