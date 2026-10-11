"""
scan_log.py

This is where DEVADARA writes down what it noticed while nobody was
watching - everything the GUI's auto-scans (Downloads/USB/startup sweep)
and the CLI-only startup_protect.py find unattended (see that module's
docstring for why it can't just ask "mark as threat? [y/N]" the way the
interactive CLIs do).

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

from devadara.app_paths import state_file

LOG_PATH = state_file("scan_log.jsonl")
# Suspend/resume/kill actions a human confirmed on a behavior alert (GUI) -
# kept OUT of scan_log.jsonl, which review-log walks as findings to confirm
# or quarantine; an action record is history, not a finding.
PROCESS_ACTIONS_PATH = state_file("process_actions.jsonl")


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


# scan_engine tiers worth recording. "trusted_signed", "safe", "not_pe" and
# "unreadable" are not actionable - logging every clean file would make the
# log useless for spotting what actually needs review.
LOGGABLE_TIERS = {"known_bad", "malware", "suspicious"}


def record_scan_result(result, source):
    """
    Log one scan_engine.evaluate_file() result if its tier is worth
    reviewing - the one shared result -> entry mapping, used by both
    startup_protect.py and the GUI's auto-scans so their entries can't
    drift apart. Returns the tier if logged, None otherwise.
    """
    if result["tier"] not in LOGGABLE_TIERS:
        return None

    ml = result.get("ml") or {}
    signature = result.get("signature") or {}
    append_finding(
        source=source,
        tier=result["tier"],
        file_path=result["file_path"],
        file_hash=result["hash"],
        threat_name=result.get("threat_name"),
        confidence=ml.get("confidence"),
        publisher=signature.get("publisher"),
        downgraded_from_malware=result.get("downgraded_from_malware", False),
    )
    return result["tier"]


def record_behavior_alert(alert_info):
    """
    Log one behavior_monitor alert - the one shared alert -> entry mapping,
    used by both startup_protect.py and the GUI. Suspects are stored as
    "PID n (name)" strings (extra keys a caller added, e.g. the GUI's
    exe/create_time, are deliberately not logged). Returns the entry id.
    """
    suspects = [f"PID {s['pid']} ({s['name']})" for s in alert_info["suspect_processes"]]
    return append_finding(
        source="behavior_alert",
        tier="behavior_alert",
        file_path=alert_info["folder"],
        event_count=alert_info["event_count"],
        window_seconds=alert_info["window_seconds"],
        sample_files=alert_info["sample_files"],
        suspect_processes=suspects,
    )


def record_process_action(action, pid, name, exe, result):
    """Append one human-confirmed suspend/resume/kill (or a refused attempt)
    to PROCESS_ACTIONS_PATH. Never raises."""
    entry = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "action": action,
        "pid": pid,
        "name": name,
        "exe": exe,
        "result": result,
    }
    try:
        os.makedirs(os.path.dirname(PROCESS_ACTIONS_PATH), exist_ok=True)
        with open(PROCESS_ACTIONS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as exc:
        print(f"[WARNING] Could not write to process action log: {exc}")


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
