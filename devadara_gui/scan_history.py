"""
scan_history.py

When DEVADARA last finished a scan - the one place that reads it, so the
Dashboard and the sidebar always agree. Stored in gui_state.json
(config_store) under "last_scan" ({"at", "kind"}) and "last_full_scan"
({"at"}). New key names on purpose: the "last_scan_at" left in
gui_state.json by the GUI that was removed is never read.
"""

LAST_SCAN_KEY = "last_scan"
LAST_FULL_SCAN_KEY = "last_full_scan"

NO_SCAN_YET = "No scan yet"
NEVER = "Never"


def format_when(iso_timestamp):
    """"2026-10-11T14:02:33" -> "2026-10-11 14:02" (same format as the App
    integrity strip). Anything else -> None."""
    if not isinstance(iso_timestamp, str) or len(iso_timestamp) < 16:
        return None
    return iso_timestamp.replace("T", " ")[:16]


def _entry(config_store, key):
    value = config_store.get(key) if config_store is not None else None
    if isinstance(value, dict) and format_when(value.get("at")):
        return value
    return None


def last_scan(config_store):
    """{"at", "kind"} of the last finished scan, or None."""
    return _entry(config_store, LAST_SCAN_KEY)


def last_scan_text(config_store):
    """"Last scan: 2026-10-11 14:02 (Quick Scan)" or "No scan yet"."""
    entry = last_scan(config_store)
    if entry is None:
        return NO_SCAN_YET
    kind = entry.get("kind")
    return f"Last scan: {format_when(entry['at'])}" + (f" ({kind})" if kind else "")
