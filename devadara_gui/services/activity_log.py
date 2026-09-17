"""
activity_log.py

Backs the Dashboard's "Recent Activity" list - a real, persisted record of
what the GUI itself has done (scans run, threats quarantined, protection
toggled, ...), distinct from devadara/scan_log.py (which records raw
findings a human hasn't acted on yet). Same atomic JSON read/write pattern
as the rest of the codebase.
"""

import json
import os
import uuid
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_PATH = os.path.join(PROJECT_ROOT, "data", "gui_activity_log.json")

MAX_ENTRIES = 200


def _load():
    if not os.path.exists(LOG_PATH):
        return []
    try:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _save(entries):
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        temp_path = LOG_PATH + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(entries[-MAX_ENTRIES:], f, indent=2)
        os.replace(temp_path, LOG_PATH)
    except OSError:
        pass


def add_event(kind, title, detail=""):
    """
    kind: a short tag ("scan_completed", "threat_detected", "threat_quarantined",
    "usb_scan_completed", "protection_changed", ...) - used only to pick an
    icon/weight, never shown directly.
    """
    entries = _load()
    entries.append({
        "id": uuid.uuid4().hex,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "kind": kind,
        "title": title,
        "detail": detail,
    })
    _save(entries)


def recent_events(limit=None):
    """Most recent first."""
    entries = list(reversed(_load()))
    return entries[:limit] if limit else entries
