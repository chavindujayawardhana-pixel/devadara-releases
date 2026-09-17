"""
config_store.py

GUI-owned settings persistence (Section 31 of the design spec: startup,
protection toggles, notification preferences must survive relaunch). This
is deliberately a GUI-layer concern, not a core devadara/ module - none of
the detection engines need to know these preferences exist, they just get
started or not, per module, based on what's stored here.

Windows Startup and the exception list are NOT duplicated here: Windows
Startup's source of truth is the real registry key
(devadara.startup_registration.is_in_startup()), and exceptions already
have their own store (devadara.exceptions / data/scan_exceptions.json) -
re-persisting either here would risk the two disagreeing.

Same atomic-write pattern used throughout the codebase (devadara/memory.py,
devadara/quarantine.py, ...): write to a temp file, then os.replace().
"""

import json
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "data", "gui_state.json")

DEFAULTS = {
    "realtime_protection_enabled": True,
    "behavior_monitoring_enabled": True,
    "downloads_autoscan_enabled": True,
    "usb_autoscan_enabled": True,
    "minimize_to_tray": False,
    "notifications_enabled": True,
    "notify_scan_completed": True,
    "notify_threat_detected": True,
    "notify_usb_scan_completed": True,
    "notify_protection_status": True,
    "last_scan_at": None,
    "last_scan_summary": None,
}


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

    def set_many(self, **kwargs):
        self._data.update(kwargs)
        self._save()
