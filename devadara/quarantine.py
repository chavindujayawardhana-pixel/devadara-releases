"""
quarantine.py

This is DEVADARA's "isolation ward" layer - once a file is confirmed as a
threat, this is what actually neutralizes it: encrypt its bytes and move
it out of its original location, rather than deleting it outright. The
file is preserved (in case a verdict turns out to be a false positive and
needs restoring) but rendered harmless where it sits (can't be
double-clicked and run, won't match another AV engine's signatures, and -
importantly - won't get caught and deleted by Windows Defender's
real-time protection the way a raw malicious file dropped into a plain
folder almost certainly would).

Encryption uses `cryptography`'s Fernet (AES-128-CBC + HMAC), with a
random key generated per file. Worth being honest about what this key
storage does and doesn't buy you: the key lives in data/quarantine_index.
json right next to the encrypted file, on the same machine - anyone who
can read that index can decrypt any quarantined file. That's true of every
local quarantine system, not a shortcut specific to this one. What real
AES actually buys you here (vs. a simpler scramble) is that the quarantine
file won't superficially look like recoverable malware to a casual scan or
heuristic - it's neutralization made rigorous, not secrecy against
whoever already has access to this machine's data folder.

Every operation here is only ever triggered by an explicit "y" from a
human in one of the CLIs - never automatically, and never from
startup_protect.py's unattended path (see that module for why nothing
there ever auto-confirms anything). quarantine_file() is always
reversible via restore_file(); only delete_permanently() is not, and nothing
in this codebase calls it without you typing the id yourself.
"""

import hashlib
import json
import os
import sys
import uuid
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken

from devadara.app_paths import state_file

QUARANTINE_DIR = state_file("quarantine")
INDEX_PATH = state_file("quarantine_index.json")


def _safe_print(text):
    # Every message below can carry a real file path (file_path,
    # destination, original_path, ...) - confirmed live that a real
    # Windows file name can contain a character this console's codepage
    # can't render (e.g. a literal Greek letter used stylistically in a
    # filename), which crashes a plain print() with UnicodeEncodeError.
    # Fall back to a lossy re-encode rather than crashing mid-quarantine
    # over a display-only message.
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        print(str(text).encode(encoding, errors="replace").decode(encoding))


def _load_index():
    if not os.path.exists(INDEX_PATH):
        return {}
    try:
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        _safe_print(f"[WARNING] Could not parse JSON in: {INDEX_PATH}")
        return {}


def _save_index(index):
    os.makedirs(os.path.dirname(INDEX_PATH), exist_ok=True)
    temp_path = INDEX_PATH + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)
    os.replace(temp_path, INDEX_PATH)


def _verify_roundtrip(quarantine_path, key, original_bytes):
    try:
        with open(quarantine_path, "rb") as f:
            encrypted = f.read()
        decrypted = Fernet(key).decrypt(encrypted)
    except (OSError, InvalidToken):
        return False
    return decrypted == original_bytes


def quarantine_file(file_path, file_hash=None, threat_name=None, tier=None, source=None):
    """
    Encrypt file_path and move it into the quarantine store.

    file_hash/threat_name/tier/source: whatever DEVADARA already knows
    about why this file was flagged - stored alongside the entry purely
    for your own reference when reviewing the quarantine list later.

    Returns the new quarantine entry's id on success, or None on failure
    (file locked, permission denied, etc.) - never raises. The original
    file is only ever deleted AFTER the encrypted copy is written back out
    and verified byte-for-byte to decrypt to the same content - a failed
    or interrupted quarantine leaves the original untouched rather than
    risking the only copy of the file.
    """
    try:
        with open(file_path, "rb") as f:
            original_bytes = f.read()
    except OSError as exc:
        _safe_print(f"[QUARANTINE ERROR] Could not read '{file_path}': {exc}")
        return None

    key = Fernet.generate_key()
    encrypted = Fernet(key).encrypt(original_bytes)

    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    entry_id = uuid.uuid4().hex
    quarantine_filename = f"{entry_id}.qtn"
    quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_filename)

    try:
        with open(quarantine_path, "wb") as f:
            f.write(encrypted)
    except OSError as exc:
        _safe_print(f"[QUARANTINE ERROR] Could not write quarantine file: {exc}")
        return None

    if not _verify_roundtrip(quarantine_path, key, original_bytes):
        _safe_print("[QUARANTINE ERROR] Verification failed after writing - original file left untouched.")
        try:
            os.remove(quarantine_path)
        except OSError:
            pass
        return None

    try:
        os.remove(file_path)
    except OSError as exc:
        _safe_print(f"[QUARANTINE WARNING] Quarantined a copy, but could not remove the original "
                    f"at '{file_path}': {exc}. The original is still there - remove it by hand.")

    index = _load_index()
    index[entry_id] = {
        "id": entry_id,
        "original_path": os.path.abspath(file_path),
        "quarantine_filename": quarantine_filename,
        "hash": file_hash,
        "key": key.decode("ascii"),
        "quarantined_at": datetime.now().isoformat(timespec="seconds"),
        "threat_name": threat_name,
        "tier": tier,
        "source": source,
    }
    _save_index(index)

    _safe_print(f"[QUARANTINE] Moved and encrypted: {file_path}")
    return entry_id


def list_quarantined():
    """Returns all quarantine entries, as a list of dicts."""
    return list(_load_index().values())


def restore_file(entry_id, restore_path=None):
    """
    Decrypt a quarantined file and move it back out of quarantine.

    restore_path: where to write it - defaults to its original location.
    Pass this explicitly if the original path is no longer suitable (e.g.
    something else now occupies it).

    Refuses to overwrite an existing file at the destination (returns
    False) rather than silently clobbering whatever's there now - pass a
    different restore_path if that happens. Verifies the decrypted
    content's hash matches what was recorded at quarantine time before
    writing anything out.

    Returns True on success.
    """
    index = _load_index()
    entry = index.get(entry_id)
    if entry is None:
        _safe_print(f"[QUARANTINE ERROR] No quarantined file with id '{entry_id}'.")
        return False

    destination = restore_path or entry["original_path"]
    if os.path.exists(destination):
        _safe_print(f"[QUARANTINE ERROR] '{destination}' already exists - won't overwrite. "
                    "Restore to a different path instead.")
        return False

    quarantine_path = os.path.join(QUARANTINE_DIR, entry["quarantine_filename"])
    try:
        with open(quarantine_path, "rb") as f:
            encrypted = f.read()
        decrypted = Fernet(entry["key"].encode("ascii")).decrypt(encrypted)
    except (OSError, InvalidToken) as exc:
        _safe_print(f"[QUARANTINE ERROR] Could not decrypt quarantined file: {exc}")
        return False

    if entry.get("hash") and hashlib.sha256(decrypted).hexdigest() != entry["hash"]:
        _safe_print("[QUARANTINE ERROR] Restored content doesn't match the recorded hash - refusing to write it out.")
        return False

    os.makedirs(os.path.dirname(destination) or ".", exist_ok=True)
    try:
        with open(destination, "wb") as f:
            f.write(decrypted)
    except OSError as exc:
        _safe_print(f"[QUARANTINE ERROR] Could not write restored file to '{destination}': {exc}")
        return False

    try:
        os.remove(quarantine_path)
    except OSError:
        pass
    del index[entry_id]
    _save_index(index)

    _safe_print(f"[QUARANTINE] Restored to: {destination}")
    return True


def delete_permanently(entry_id):
    """
    Permanently erase a quarantined file and its metadata. This is the one
    genuinely irreversible action in this module - quarantine_file() is
    always undoable via restore_file(), this is not. Nothing in this
    codebase calls this without a human typing the id themselves (see
    quarantine_cli.py).
    """
    index = _load_index()
    entry = index.get(entry_id)
    if entry is None:
        _safe_print(f"[QUARANTINE ERROR] No quarantined file with id '{entry_id}'.")
        return False

    quarantine_path = os.path.join(QUARANTINE_DIR, entry["quarantine_filename"])
    try:
        os.remove(quarantine_path)
    except OSError as exc:
        _safe_print(f"[QUARANTINE ERROR] Could not delete quarantine file: {exc}")
        return False

    del index[entry_id]
    _save_index(index)
    _safe_print(f"[QUARANTINE] Permanently deleted: {entry.get('original_path')}")
    return True


def confirm_and_quarantine(file_path, file_hash=None, threat_name=None, tier=None, source=None):
    """
    Ask "quarantine this file now? [y/N]" and act on the answer. Shared by
    every CLI that identifies a threat with a concrete file+hash, so the
    prompt and behavior are identical everywhere. This is deliberately a
    SEPARATE question from "mark as a confirmed threat?" (see the various
    *_cli.py files) - remembering a hash and touching a file on disk are
    different levels of consequence and each gets its own explicit yes.

    Returns True if the file was quarantined.
    """
    answer = input("Quarantine this file now (encrypt + move out of place)? [y/N]: ").strip().lower()
    if answer != "y":
        print("  Left in place - not quarantined.")
        return False

    entry_id = quarantine_file(file_path, file_hash=file_hash, threat_name=threat_name, tier=tier, source=source)
    return entry_id is not None
