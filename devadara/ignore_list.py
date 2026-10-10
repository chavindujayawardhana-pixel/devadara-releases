"""
ignore_list.py

Files the user chose to Ignore on the Results page - pinned to BOTH the
file's path AND its content fingerprint (SHA256). scan_engine.evaluate_file()
skips a file only when the file at that path still has exactly the
fingerprint it had when it was ignored; the moment its content changes (or
something else is put at that path), it's scanned normally again. That's
the difference from the older, path-only devadara/exceptions.py, which
would also skip whatever later replaced the file.

Stored locally in data/ignored_files.json (per-machine, git-ignored).
Entries are only ever added after a human confirmed it in the GUI; nothing
in DEVADARA adds one on its own.
"""

import json
import os
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IGNORE_PATH = os.path.join(PROJECT_ROOT, "data", "ignored_files.json")

# Re-read only when the file on disk changes - evaluate_file() asks for
# every file of a scan, so one small stat per call instead of a JSON parse.
_cache = {"stamp": None, "path": None, "entries": {}}


def _key(path):
    return os.path.normcase(os.path.abspath(path))


def _load():
    try:
        stat = os.stat(IGNORE_PATH)
        stamp = (stat.st_mtime_ns, stat.st_size)
    except OSError:
        return {}
    if _cache["stamp"] == stamp and _cache["path"] == IGNORE_PATH:
        return _cache["entries"]
    try:
        with open(IGNORE_PATH, "r", encoding="utf-8") as f:
            entries = json.load(f)
        if not isinstance(entries, dict):
            entries = {}
    except (OSError, json.JSONDecodeError):
        entries = {}
    _cache.update(stamp=stamp, path=IGNORE_PATH, entries=entries)
    return entries


def _save(entries):
    os.makedirs(os.path.dirname(IGNORE_PATH), exist_ok=True)
    temp_path = IGNORE_PATH + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)
    os.replace(temp_path, IGNORE_PATH)
    _cache["stamp"] = None


def add(path, file_hash, threat_name=None):
    """Ignore exactly this content at exactly this path."""
    entries = dict(_load())
    entries[_key(path)] = {
        "path": os.path.abspath(path),
        "hash": file_hash,
        "threat_name": threat_name,
        "added": datetime.now().isoformat(timespec="seconds"),
    }
    _save(entries)


def remove(path):
    entries = dict(_load())
    if _key(path) not in entries:
        return False
    del entries[_key(path)]
    _save(entries)
    return True


def is_ignored(path, file_hash):
    entry = _load().get(_key(path))
    return entry is not None and file_hash is not None and entry.get("hash") == file_hash


def list_ignored():
    return list(_load().values())
