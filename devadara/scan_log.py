"""
scan_log.py

This is where DEVADARA writes down what it noticed while nobody was
watching - specifically, everything startup_protect.py finds while running
unattended at boot (see that module's docstring for why it can't just ask
"mark as threat? [y/N]" the way the interactive CLIs do).

Findings are appended to data/scan_log.jsonl, one JSON object per line
(easy to append to safely, easy to tail/grep by hand if you want to look
without going through Python at all). Nothing here ever confirms a threat
or touches devadara/memory.py on its own - it only records what was seen,
for a human to review later (see startup_cli.py's "review-log" command).
"""

import json
import os
import uuid
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(PROJECT_ROOT, "data", "scan_log.jsonl")


def append_finding(source, tier, file_path=None, file_hash=None, **extra):
    """
    Record one finding. Never raises - a logging failure shouldn't crash
    the background protection process.

    source: where this came from, e.g. "boot_sweep", "downloads_watch",
            "usb_watch", "behavior_alert"
    tier: "known_bad" | "malware" | "suspicious" | "behavior_alert"
    file_path / file_hash: the file involved, if there is a single one
    **extra: any additional context worth keeping (threat_name, publisher,
             confidence, suspect_processes, sample_files, ...) - stored
             as-is under "details".

    Returns the entry's id (str), or None if writing failed.
    """
    entry = {
        "id": uuid.uuid4().hex,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "source": source,
        "tier": tier,
        "file_path": file_path,
        "hash": file_hash,
        "details": extra,
    }

    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as exc:
        print(f"[WARNING] Could not write to scan log: {exc}")
        return None

    return entry["id"]


def read_findings():
    """
    Read all findings currently in the log, oldest first.

    Returns a list of entry dictionaries. A corrupted line is skipped (with
    a warning) rather than breaking the whole read - one bad line shouldn't
    hide every other finding from you.
    """
    if not os.path.exists(LOG_PATH):
        return []

    findings = []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"[WARNING] Skipping unreadable line {line_number} in scan log.")

    return findings


def remove_findings(ids_to_remove):
    """
    Remove the given finding ids from the log - used once you've reviewed
    them (confirmed as a threat, or dismissed) so review-log doesn't keep
    showing you the same entries forever.

    Rewrites the log via a temp file + os.replace(), same crash-safety
    pattern as devadara/memory.py's save_memory().
    """
    if not ids_to_remove:
        return

    remaining = [entry for entry in read_findings() if entry.get("id") not in ids_to_remove]

    temp_path = LOG_PATH + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        for entry in remaining:
            f.write(json.dumps(entry) + "\n")

    os.replace(temp_path, LOG_PATH)
