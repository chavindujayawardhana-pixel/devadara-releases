"""
memory.py

This is DEVADARA's "memory cells" layer - modeled after how your immune
system remembers a pathogen after fighting it once, so next time it reacts
instantly instead of mounting a slow response from scratch.

Unlike data/known_bad_hashes.json (a fixed list bundled with the app),
data/memory_hashes.json GROWS over time: every time a threat is confirmed -
by an exact hash match, the ML model (with your confirmation), or you
manually marking a file as bad - we record its hash here. Future scans then
catch it instantly via simple hash matching, without needing to run the
(slower, less certain) ML model again.

Nothing in this file ever deletes or touches your actual files - it only
manages DEVADARA's own local JSON memory.
"""

import json
import os
from datetime import datetime

from devadara.hash_scanner import load_known_bad_hashes

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KNOWN_BAD_HASHES_PATH = os.path.join(PROJECT_ROOT, "data", "known_bad_hashes.json")
MEMORY_PATH = os.path.join(PROJECT_ROOT, "data", "memory_hashes.json")


def load_memory():
    """
    Load DEVADARA's learned memory of confirmed threats.

    Returns a dictionary shaped like:
        {
            "somehash...": {
                "threat_name": "...",
                "source": "hash_match" | "ml_model" | "user_confirmed",
                "date_added": "2026-09-14T13:40:00"
            },
            ...
        }

    If the file doesn't exist yet or is empty/corrupted, we return an empty
    dictionary rather than crashing - a fresh memory is safer than a crash.
    """
    if not os.path.exists(MEMORY_PATH):
        return {}

    try:
        with open(MEMORY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"[WARNING] Could not parse memory file at {MEMORY_PATH}, starting fresh.")
        return {}


def save_memory(memory):
    """
    Write the memory dictionary back to disk.

    We write to a temporary file first, then rename it into place with
    os.replace(). This avoids corrupting memory_hashes.json if the program
    crashes or is closed partway through writing - a half-written JSON
    file would break every future scan otherwise.
    """
    os.makedirs(os.path.dirname(MEMORY_PATH), exist_ok=True)
    temp_path = MEMORY_PATH + ".tmp"

    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(memory, f, indent=2)

    os.replace(temp_path, MEMORY_PATH)


def remember_threat(file_hash, threat_name, source):
    """
    Record a confirmed threat so future scans recognize it instantly by
    hash alone, without needing the ML model again.

    file_hash: the SHA256 hash of the confirmed-bad file
    threat_name: a human-readable description (e.g. the file name, or a
                 threat family name if you know it)
    source: one of "hash_match", "ml_model", or "user_confirmed" - just a
            label recording how this was detected, for your own reference
    """
    memory = load_memory()

    memory[file_hash] = {
        "threat_name": threat_name,
        "source": source,
        "date_added": datetime.now().isoformat(timespec="seconds"),
    }

    save_memory(memory)
    print(f"[MEMORY] Remembered new threat: {threat_name} ({file_hash[:16]}...)")


def forget_threat(file_hash):
    """
    Remove a hash from memory. Useful if something was remembered by
    mistake (e.g. a false positive you accidentally confirmed).
    """
    memory = load_memory()

    if file_hash in memory:
        removed = memory.pop(file_hash)
        save_memory(memory)
        print(f"[MEMORY] Forgot: {removed['threat_name']} ({file_hash[:16]}...)")
    else:
        print("[MEMORY] That hash wasn't in memory.")


def get_combined_known_bad_hashes():
    """
    Combine the bundled seed database (data/known_bad_hashes.json) with
    everything DEVADARA has learned on its own (data/memory_hashes.json)
    into one simple {hash: description} dictionary, ready to hand to
    hash_scanner.scan_folder().

    This is the function the rest of the app should use for scanning, so
    every scan automatically benefits from everything remembered so far.
    """
    seed_hashes = load_known_bad_hashes(KNOWN_BAD_HASHES_PATH)
    memory = load_memory()

    combined = dict(seed_hashes)  # start with a copy of the seed database
    for file_hash, entry in memory.items():
        combined[file_hash] = entry["threat_name"]

    return combined
