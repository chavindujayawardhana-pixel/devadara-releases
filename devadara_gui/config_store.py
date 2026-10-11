"""
config_store.py

GUI-owned settings persistence for the Protection page's Downloads/USB
Auto-Scan toggles - deliberately a GUI-layer concern, not a core
devadara/ module (the detection engines don't need to know these
preferences exist, they just get started or not, per watcher, based on
what's stored here).

Reads/writes data/gui_state.json, which already exists on disk (from a
prior GUI implementation, see project history) with more keys than this
module's DEFAULTS mentions - load-then-update()/save() preserves those
untouched, this module just never reads them.

Same atomic-write pattern used throughout the codebase (devadara/memory.py,
devadara/quarantine.py, ...): write to a temp file, then os.replace().
"""

import json
import os

from devadara.app_paths import state_file

CONFIG_PATH = state_file("gui_state.json")

# Settings › General (settings_page.py). Auto-delete has exactly these two
# values - never a third, and nothing in the app ever deletes on its own.
TRAY_NOTIFICATIONS_KEY = "tray_notifications"
AUTO_DELETE_KEY = "auto_delete"
AUTO_DELETE_ASK = "ask"      # Delete Permanently works, behind its confirmation (default)
AUTO_DELETE_NEVER = "never"  # every Delete action in the GUI is disabled

DEFAULTS = {
    "downloads_autoscan_enabled": True,
    "usb_autoscan_enabled": True,
    TRAY_NOTIFICATIONS_KEY: True,
    AUTO_DELETE_KEY: AUTO_DELETE_ASK,
}


def tray_notifications_on(config_store):
    return config_store is None or config_store.get(TRAY_NOTIFICATIONS_KEY, True) is not False


def delete_allowed(config_store):
    """False only for an explicit "never" - any other stored value reads as
    the default "ask"."""
    return config_store is None or config_store.get(AUTO_DELETE_KEY) != AUTO_DELETE_NEVER


class ConfigStore:
    def __init__(self):
        self._data = dict(DEFAULTS)
        self._load()

    def _load(self):
        if not os.path.exists(CONFIG_PATH):
            return
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                self._data.update(loaded)
        except (OSError, json.JSONDecodeError):
            pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
            temp_path = CONFIG_PATH + ".tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
            os.replace(temp_path, CONFIG_PATH)
        except OSError:
            pass

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        self._data[key] = value
        self._save()
