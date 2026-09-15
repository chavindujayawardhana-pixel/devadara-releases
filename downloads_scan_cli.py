"""
downloads_scan_cli.py

A simple command-line test tool for Step 5 (Downloads-folder auto-scan).
Run this from your terminal like:

    python downloads_scan_cli.py

It watches a folder (your real Downloads folder by default) and
automatically scans any new file the moment it finishes arriving, using
DEVADARA's full pipeline (see devadara/scan_engine.py): Hash Check ->
YARA Rules Check -> Digital Signature Check -> ML Model Check. Nothing
gets deleted; this is detection and reporting only.

For anything flagged "malware" or "suspicious" (by YARA or the ML model),
you'll be asked whether you want to remember it as a confirmed threat
(Step 3's memory database) - nothing is added to memory without your
explicit "yes".

Press Ctrl+C to stop watching.
"""

import os
import time

from devadara.downloads_monitor import start_monitoring_downloads
from devadara.memory import get_combined_known_bad_hashes, remember_threat
from devadara.ml_scanner import load_model_and_features
from devadara.quarantine import confirm_and_quarantine
from devadara.scan_engine import evaluate_file
from devadara.signature_scanner import load_trusted_publishers

DEFAULT_DOWNLOADS_FOLDER = os.path.join(os.path.expanduser("~"), "Downloads")


def scan_new_file(file_path, known_bad_hashes, model, feature_columns, trusted_publishers):
    print()
    print("=" * 60)
    print(f"NEW FILE: {file_path}")

    result = evaluate_file(file_path, known_bad_hashes, model, feature_columns, trusted_publishers)
    tier = result["tier"]

    if tier == "unreadable":
        print("[ERROR] Could not read this file (in use, or no permission) - skipping.")
        print("=" * 60)
        return

    print("[HASH SCAN] No match in known-bad hashes.")

    if tier == "known_bad":
        print("!!! THREAT FOUND (hash match) !!!")
        print(f"  Hash:   {result['hash']}")
        print(f"  Threat: {result['threat_name']}")
        confirm_and_quarantine(
            file_path, file_hash=result["hash"], threat_name=result["threat_name"],
            tier="known_bad", source="downloads_scan_cli",
        )
        print("=" * 60)
        return

    if result["yara"]:
        rule_names = ", ".join(m["rule"] for m in result["yara"])
        print(f"[YARA] Matched: {rule_names}")
    else:
        print("[YARA] No pattern matches.")

    signature = result["signature"]
    if tier == "trusted_signed":
        print(f"[SIGNATURE] Valid, trusted signature from '{signature['publisher']}' - skipping ML check.")
        print("=" * 60)
        return
    elif signature is not None:
        print(f"[SIGNATURE] {signature['status']}" + (f" (publisher: {signature['publisher']})" if signature['publisher'] else ""))

    if tier == "not_pe":
        if model is None:
            print("[ML SCAN] Skipped - no model loaded.")
        else:
            print("[ML SCAN] Not a Windows executable - this layer doesn't judge it.")
        print("=" * 60)
        return

    # A "malware"/"suspicious" tier can come from YARA alone, with the ML
    # layer never reached at all (e.g. YARA already set a floor before the
    # signature/model checks ran) - see scan_engine.evaluate_file().
    if result["ml"] is None:
        print("[ML SCAN] Not reached - verdict set by YARA.")
        confidence = None
    else:
        confidence = result["ml"]["confidence"]
        print(f"[ML SCAN] [{tier:>10}] ({confidence:.1%} confidence of malware)")
        if result["downgraded_from_malware"]:
            print("  (downgraded from 'malware' to 'suspicious': certificate claims a whitelisted")
            print("   publisher, but its signature chain did not fully validate - needs a human look)")

    if tier == "safe":
        print("=" * 60)
        return

    print()
    print("Review carefully - YARA matches are concrete evidence found in the file itself;")
    print("the ML model is probabilistic and can be wrong - either way, only confirm files")
    print("you genuinely believe are malicious.")
    detail = f"confidence {confidence:.1%}" if confidence is not None else "YARA match, no ML result"
    answer = input(
        f"\nMark '{file_path}' (tier: {tier}, {detail}) as a confirmed threat? [y/N]: "
    ).strip().lower()

    if answer == "y":
        source = "yara" if result["yara"] else "ml_model"
        label = "YARA" if result["yara"] else "ML"
        threat_name = f"{label}-flagged ({tier}): {os.path.basename(file_path)}"
        remember_threat(result["hash"], threat_name=threat_name, source=source)
        confirm_and_quarantine(
            file_path, file_hash=result["hash"], threat_name=threat_name,
            tier=tier, source="downloads_scan_cli",
        )
    else:
        print("  Skipped - not remembered.")
    print("=" * 60)


def main():
    print("=== DEVADARA - Downloads Folder Auto-Scan (Step 5) ===")

    known_bad_hashes = get_combined_known_bad_hashes()
    print(f"[INFO] Loaded {len(known_bad_hashes)} known-bad hash(es) (seed + memory).")

    trusted_publishers = load_trusted_publishers()
    print(f"[INFO] Loaded {len(trusted_publishers)} trusted publisher(s).")

    model, feature_columns = load_model_and_features()
    if model is None:
        print("[INFO] Continuing with hash-only scanning (no ML model).")

    folder_to_watch = input(
        f"Enter the folder to watch (press Enter for '{DEFAULT_DOWNLOADS_FOLDER}'): "
    ).strip() or DEFAULT_DOWNLOADS_FOLDER

    if not os.path.isdir(folder_to_watch):
        print(f"[ERROR] '{folder_to_watch}' is not a valid folder.")
        return

    def on_new_file(file_path):
        scan_new_file(file_path, known_bad_hashes, model, feature_columns, trusted_publishers)

    observer = start_monitoring_downloads(folder_to_watch, on_new_file)
    print(f"[INFO] Watching '{folder_to_watch}' for new files...")
    print("[INFO] Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping monitor...")
        observer.stop()
        observer.join()
        print("[INFO] Stopped.")


if __name__ == "__main__":
    main()
