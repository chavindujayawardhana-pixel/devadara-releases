"""
scan_history.py

When DEVADARA last finished a scan - the one place that reads it, so the
Dashboard and the sidebar always agree. Stored in gui_state.json
(config_store) under "last_scan" ({"at", "kind"}) and "last_full_scan"
({"at"}). New key names on purpose: the "last_scan_at" left in
gui_state.json by the GUI that was removed is never read.
"""

from datetime import datetime

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


def last_full_scan_text(config_store):
    """"2026-10-11" (date only - the time doesn't fit the Dashboard's stat
    card at its 17pt value font), or "Never"."""
    entry = _entry(config_store, LAST_FULL_SCAN_KEY)
    return format_when(entry["at"])[:10] if entry else NEVER


def last_full_scan_tooltip(config_store):
    """The full date and time for the stat card's tooltip, or ""."""
    entry = _entry(config_store, LAST_FULL_SCAN_KEY)
    return f"Last full scan: {format_when(entry['at'])}" if entry else ""


# A manual Full Scan whose default selection wasn't changed - the only
# kind that counts as a full scan.
FULL_SCAN_KIND = "Full Scan"


def record_finished_scan(config_store, kind, when=None):
    """Called by the Scan page when a scan FINISHES (never when stopped).
    kind: "Quick Scan" / "Full Scan" / "Scan Downloads" / "Scan USB" /
    "Custom scan" / "Startup scan"; per-file Downloads/USB auto-scans pass
    no kind and are never recorded. Stores only the time and the kind."""
    if config_store is None or not kind:
        return
    at = (when or datetime.now()).isoformat(timespec="seconds")
    config_store.set(LAST_SCAN_KEY, {"at": at, "kind": kind})
    if kind == FULL_SCAN_KIND:
        config_store.set(LAST_FULL_SCAN_KEY, {"at": at})
