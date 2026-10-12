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
import shutil
from datetime import datetime

from devadara.app_paths import state_file

IGNORE_PATH = state_file("ignored_files.json")

# Re-read only when the file on disk changes - evaluate_file() asks for
# every file of a scan, so one small stat per call instead of a JSON parse.
_cache = {"stamp": None, "path": None, "entries": {}}


def _key(path):
    return os.path.normcase(os.path.abspath(path))


def _read_file():
    """(entries, broken) straight from disk. Entries that aren't a dict with
    a string path are dropped - is_ignored() must never trip over them."""
    try:
        with open(IGNORE_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        return {}, False
    except (OSError, ValueError):
        return {}, True
    if not isinstance(raw, dict):
        return {}, True
    entries = {k: v for k, v in raw.items()
               if isinstance(v, dict) and isinstance(v.get("path"), str)}
    return entries, False


def _load():
    try:
        stat = os.stat(IGNORE_PATH)
        stamp = (stat.st_mtime_ns, stat.st_size)
    except OSError:
        return {}
    if _cache["stamp"] == stamp and _cache["path"] == IGNORE_PATH:
        return _cache["entries"]
    entries, _broken = _read_file()
    _cache.update(stamp=stamp, path=IGNORE_PATH, entries=entries)
    return entries


def file_status():
    """"ok", "missing" or "broken" (exists but can't be read as a list of
    entries) - so Settings › Exceptions can say why the list looks empty."""
    if not os.path.exists(IGNORE_PATH):
        return "missing"
    return "broken" if _read_file()[1] else "ok"


def _save(entries):
    os.makedirs(os.path.dirname(IGNORE_PATH), exist_ok=True)
    # A broken file is kept as .broken once, never silently overwritten.
    if os.path.exists(IGNORE_PATH) and _read_file()[1]:
        try:
            shutil.copy2(IGNORE_PATH, IGNORE_PATH + ".broken")
        except OSError:
            pass
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


def is_listed(path):
    """The stored entry for this path (whatever its fingerprint), or None."""
    return _load().get(_key(path))


def list_ignored():
    return list(_load().values())
