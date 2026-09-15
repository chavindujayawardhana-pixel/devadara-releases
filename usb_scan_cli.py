"""
usb_scan_cli.py

A simple command-line test tool for Step 5 (USB drive auto-scan). Run this
from your terminal like:

    python usb_scan_cli.py

It watches for removable drives (USB flash drives, SD cards, etc.) being
plugged in, and automatically scans every file on one the moment it
appears, using DEVADARA's full pipeline (see devadara/scan_engine.py):
Hash Check -> YARA Rules Check -> Digital Signature Check -> ML Model
Check. Nothing gets deleted; this is detection and reporting only.

For anything flagged as "malware" or "suspicious", you'll be asked whether
to remember it as a confirmed threat (Step 3's memory database) - nothing
is added to memory without your explicit "yes".

Press Ctrl+C to stop watching.
"""

import os
import time

from devadara.memory import get_combined_known_bad_hashes, remember_threat
from devadara.ml_scanner import load_model_and_features
from devadara.quarantine import confirm_and_quarantine
from devadara.scan_engine import evaluate_file
from devadara.signature_scanner import load_trusted_publishers
from devadara.usb_monitor import start_usb_monitoring


def scan_drive(drive_path, known_bad_hashes, model, feature_columns, trusted_publishers):
    print()
    print("=" * 60)
    print(f"!!! REMOVABLE DRIVE CONNECTED: {drive_path} !!!")
    print("=" * 60)

    known_bad_findings = []
    trusted_signed_count = 0
    to_review = []  # (result,) for "malware" and "suspicious" tiers
    files_scanned = 0

    for current_folder, _subfolders, file_names in os.walk(drive_path):
        for file_name in file_names:
            full_path = os.path.join(current_folder, file_name)

            result = evaluate_file(full_path, known_bad_hashes, model, feature_columns, trusted_publishers)
            files_scanned += 1

            tier = result["tier"]
            if tier == "unreadable" or tier == "not_pe":
                continue
            if tier == "known_bad":
                known_bad_findings.append(result)
            elif tier == "trusted_signed":
                trusted_signed_count += 1
            elif tier in ("malware", "suspicious"):
                to_review.append(result)

    print(f"[INFO] Scanned {files_scanned} file(s).")

    print("\n[HASH SCAN]")
    if not known_bad_findings:
        print("No known threats found by hash scan.")
    else:
        print(f"!!! {len(known_bad_findings)} THREAT(S) FOUND (hash match) !!!")
        for result in known_bad_findings:
            print(f"  File:   {result['file_path']}")
            print(f"  Hash:   {result['hash']}")
            print(f"  Threat: {result['threat_name']}")
            confirm_and_quarantine(
                result["file_path"], file_hash=result["hash"], threat_name=result["threat_name"],
                tier="known_bad", source="usb_scan_cli",
            )

    print(f"\n[SIGNATURE] {trusted_signed_count} file(s) skipped ML - valid trusted signature.")
    if model is None:
        print("[ML SCAN] Skipped - no model loaded (YARA/hash findings below are unaffected).")

    print("\n[SCAN RESULTS]")
    if not to_review:
        print("No suspicious or malicious files found.")
        print("=" * 60)
        return

    def _detail(result):
        # A result can reach "malware"/"suspicious" via YARA alone, with no
        # ML result at all (e.g. a ransom note or script - see
        # scan_engine.evaluate_file()), so this can't just read confidence.
        if result["yara"]:
            rule_names = ", ".join(m["rule"] for m in result["yara"])
            return f"YARA: {rule_names}"
        return f"{result['ml']['confidence']:.1%} confidence"

    for result in to_review:
        print(f"  [{result['tier']:>10}] ({_detail(result)})  {result['file_path']}")
        if result["downgraded_from_malware"]:
            print("    (downgraded from 'malware': whitelisted publisher name, but signature chain unverified)")

    print(f"\n!!! {len(to_review)} FILE(S) FLAGGED FOR REVIEW !!!")
    print("Review each flagged file below. YARA matches are concrete evidence found in the")
    print("file itself; the ML model is probabilistic and can be wrong - either way, only")
    print("confirm files you genuinely believe are malicious.")
    for result in to_review:
        answer = input(
            f"\nMark '{result['file_path']}' (tier: {result['tier']}, {_detail(result)}) "
            "as a confirmed threat? [y/N]: "
        ).strip().lower()

        if answer == "y":
            source = "yara" if result["yara"] else "ml_model"
            label = "YARA" if result["yara"] else "ML"
            threat_name = f"{label}-flagged ({result['tier']}): {os.path.basename(result['file_path'])}"
            remember_threat(result["hash"], threat_name=threat_name, source=source)
            confirm_and_quarantine(
                result["file_path"], file_hash=result["hash"], threat_name=threat_name,
                tier=result["tier"], source="usb_scan_cli",
            )
        else:
            print("  Skipped - not remembered.")
    print("=" * 60)


def main():
    print("=== DEVADARA - USB Drive Auto-Scan (Step 5) ===")

    known_bad_hashes = get_combined_known_bad_hashes()
    print(f"[INFO] Loaded {len(known_bad_hashes)} known-bad hash(es) (seed + memory).")

    trusted_publishers = load_trusted_publishers()
    print(f"[INFO] Loaded {len(trusted_publishers)} trusted publisher(s).")

    model, feature_columns = load_model_and_features()
    if model is None:
        print("[INFO] Continuing with hash-only scanning (no ML model).")

    def on_drive_connected(drive_path):
        scan_drive(drive_path, known_bad_hashes, model, feature_columns, trusted_publishers)

    monitor = start_usb_monitoring(on_drive_connected)
    print("[INFO] Watching for removable drives (USB sticks, SD cards, ...)...")
    print("[INFO] Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping USB monitor...")
        monitor.stop()
        monitor.join()
        print("[INFO] Stopped.")


if __name__ == "__main__":
    main()
