"""
process_scan_cli.py

A simple command-line test tool for Process Memory Scanning (V2). Run this
from your terminal like:

    python process_scan_cli.py

It sweeps every currently-running process for a handful of behavioral
tells a legitimate process shouldn't have (see devadara/process_scanner.py
for exactly what and why - a process named like a core Windows service
but running from the wrong folder, a process running from a user-writable
"drop" location, a document/browser process that spawned a shell/script
interpreter, or a process whose backing .exe has vanished since launch),
then runs each flagged process's .exe through DEVADARA's full pipeline
(see devadara/scan_engine.py): Hash Check -> YARA Rules Check -> Digital
Signature Check -> ML Model Check.

None of the four behavioral checks alone proves anything - they exist to
pick out a handful of processes worth a closer look, out of however many
are normally running. For anything flagged, you'll be asked whether to
suspend the still-running process (same suspend/kill/resume flow as
monitor_cli.py - Step 4) and, separately, whether to remember/quarantine
its exe file if the scan pipeline flagged it too. Nothing is ever
suspended, killed, remembered, or quarantined without your explicit input.
"""

import os
import sys

from devadara.behavior_monitor import kill_process, resume_process, suspend_process
from devadara.memory import get_combined_known_bad_hashes, remember_threat
from devadara.ml_scanner import load_model_and_features
from devadara.process_scanner import evaluate_suspicious_processes, list_suspicious_processes
from devadara.quarantine import confirm_and_quarantine
from devadara.signature_scanner import load_trusted_publishers


def _safe_print(text=""):
    # A process name/exe path is attacker-controlled input in the exact
    # scenario this tool exists to catch, so it can't be assumed to be
    # renderable in this console's codepage - see the identical issue
    # (and fix) already found in persistence_scan_cli.py.
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        print(str(text).encode(encoding, errors="replace").decode(encoding))


def _safe_input(prompt):
    try:
        return input(prompt)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        safe_prompt = prompt.encode(encoding, errors="replace").decode(encoding)
        return input(safe_prompt)


def _detail(result):
    if result["yara"]:
        rule_names = ", ".join(m["rule"] for m in result["yara"])
        return f"YARA: {rule_names}"
    return f"{result['ml']['confidence']:.1%} confidence"


def _handle_suspend(pid, name):
    answer = _safe_input(f"\nSuspend process PID {pid} ({name}) now? [y/N]: ").strip().lower()
    if answer != "y":
        _safe_print("  Left running - not suspended.")
        return

    if not suspend_process(pid):
        return

    _safe_print(f"  Process {pid} ({name}) is suspended (paused, not killed).")
    _safe_print("  Take a moment to review it (e.g. in Task Manager) before deciding.")
    decision = _safe_input("  [K]ill it, [R]esume it, or press Enter to leave it suspended: ").strip().lower()
    if decision == "k":
        if kill_process(pid):
            _safe_print(f"  Process {pid} killed.")
    elif decision == "r":
        if resume_process(pid):
            _safe_print(f"  Process {pid} resumed.")
    else:
        _safe_print(f"  Left process {pid} suspended - resume or kill it later via Task Manager.")


def main():
    _safe_print("=== DEVADARA - Process Memory Scan (V2) ===")

    known_bad_hashes = get_combined_known_bad_hashes()
    _safe_print(f"[INFO] Loaded {len(known_bad_hashes)} known-bad hash(es) (seed + memory).")

    trusted_publishers = load_trusted_publishers()
    _safe_print(f"[INFO] Loaded {len(trusted_publishers)} trusted publisher(s).")

    model, feature_columns = load_model_and_features()
    if model is None:
        _safe_print("[INFO] Continuing with hash/YARA/signature-only scanning (no ML model).")

    _safe_print("\n[INFO] Sweeping running processes for suspicious behavior...")
    flagged = list_suspicious_processes()
    _safe_print(f"[INFO] {len(flagged)} process(es) flagged for review.")

    if not flagged:
        _safe_print("Nothing suspicious found.")
        _safe_print("=" * 60)
        return

    _safe_print("[INFO] Evaluating flagged process(es)' exe file(s) through the scan pipeline...")
    evaluate_suspicious_processes(flagged, known_bad_hashes, model, feature_columns, trusted_publishers)

    _safe_print("\n[SCAN RESULTS]")
    for entry in flagged:
        _safe_print(f"\n  PID {entry['pid']}: {entry['name']}")
        _safe_print(f"    exe: {entry['exe']}")
        _safe_print("    Flagged because:")
        for reason in entry["reasons"]:
            _safe_print(f"      - {reason}")

        result = entry["scan"]
        if result is None:
            _safe_print("    [SCAN] Not run - exe file no longer exists on disk.")
        else:
            tier = result["tier"]
            if tier in ("known_bad", "malware", "suspicious"):
                threat_name = result["threat_name"] or _detail(result)
                _safe_print(f"    [SCAN] [{tier:>10}] {threat_name}")
                if result["downgraded_from_malware"]:
                    _safe_print("      (downgraded from 'malware': whitelisted publisher name, "
                                "but signature chain unverified)")

                answer = _safe_input(
                    f"\nMark this exe (tier: {tier}) as a confirmed threat? [y/N]: "
                ).strip().lower()
                if answer == "y" and tier != "known_bad":
                    source = "yara" if result["yara"] else "ml_model"
                    label = "YARA" if result["yara"] else "ML"
                    threat_name = f"{label}-flagged ({tier}): {os.path.basename(entry['exe'])}"
                    remember_threat(result["hash"], threat_name=threat_name, source=source)
                    confirm_and_quarantine(
                        entry["exe"], file_hash=result["hash"], threat_name=threat_name,
                        tier=tier, source="process_scan_cli",
                    )
                elif answer == "y":
                    confirm_and_quarantine(
                        entry["exe"], file_hash=result["hash"], threat_name=result["threat_name"],
                        tier="known_bad", source="process_scan_cli",
                    )
                else:
                    _safe_print("  Skipped - not remembered.")
            else:
                _safe_print(f"    [SCAN] [{tier:>10}] Nothing concrete found by the file pipeline.")

        _handle_suspend(entry["pid"], entry["name"])

    _safe_print("=" * 60)


if __name__ == "__main__":
    main()
