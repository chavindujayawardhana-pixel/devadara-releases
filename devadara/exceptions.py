"""
exceptions.py

Manages scan exceptions (files and folders that should not be scanned).
"""
import json
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EXCEPTIONS_FILE = os.path.join(PROJECT_ROOT, "data", "scan_exceptions.json")
_cached_exceptions = None

def _ensure_data_dir():
    os.makedirs(os.path.dirname(_EXCEPTIONS_FILE), exist_ok=True)

def load_exceptions():
    global _cached_exceptions
    if not os.path.exists(_EXCEPTIONS_FILE):
        _cached_exceptions = []
        return _cached_exceptions
    try:
        with open(_EXCEPTIONS_FILE, "r", encoding="utf-8") as f:
            _cached_exceptions = json.load(f)
            return _cached_exceptions
    except (json.JSONDecodeError, OSError):
        _cached_exceptions = []
        return _cached_exceptions

def _save_exceptions(paths):
    global _cached_exceptions
    _ensure_data_dir()
    with open(_EXCEPTIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(paths, f, indent=2)
    _cached_exceptions = paths

def add_exception(path):
    path = os.path.abspath(path)
    paths = load_exceptions()
    if path not in paths:
        paths.append(path)
        _save_exceptions(paths)

def remove_exception(path):
    path = os.path.abspath(path)
    paths = load_exceptions()
    if path in paths:
        paths.remove(path)
        _save_exceptions(paths)
        return True
    return False

def is_excepted(path):
    global _cached_exceptions
    if _cached_exceptions is None:
        load_exceptions()
    path = os.path.abspath(path)
    for exc in _cached_exceptions:
        if path == exc or path.startswith(exc + os.sep):
            return True
    return False
