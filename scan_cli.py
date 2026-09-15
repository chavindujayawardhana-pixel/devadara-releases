"""
scan_cli.py

A simple command-line test tool for Step 1 (the hash scanner), now upgraded
to also use Step 3's memory database. Run this from your terminal like:

    python scan_cli.py

It will ask you which folder to scan, then print out any matches found
against our local known-bad-hashes database (the bundled seed list PLUS
everything DEVADARA has remembered from past confirmed threats). For each
match, you'll be asked whether to quarantine it (see devadara/quarantine.py)
- a hash match is the most certain kind of finding DEVADARA can produce,
but nothing is ever touched without your explicit "y".

Later, this same logic will be reused by the GUI (Step 6).
"""

import os

from devadara.hash_scanner import scan_folder
from devadara.memory import get_combined_known_bad_hashes
from devadara.quarantine import confirm_and_quarantine


def main():
    print("=== DEVADARA - Hash-Based Scanner (Step 1 + Memory) ===")

    folder_to_scan = input("Enter the full path of a folder to scan: ").strip()

    if not os.path.isdir(folder_to_scan):
        print(f"[ERROR] '{folder_to_scan}' is not a valid folder.")
        return

    # This merges the bundled seed list with everything remembered so far.
    known_bad_hashes = get_combined_known_bad_hashes()
    print(f"[INFO] Loaded {len(known_bad_hashes)} known-bad hash(es) (seed + memory).")

    findings = scan_folder(folder_to_scan, known_bad_hashes)

    print()
    if not findings:
        print("No threats found. Everything looks clean.")
    else:
        print(f"!!! {len(findings)} THREAT(S) FOUND !!!")
        for finding in findings:
            print(f"  File:   {finding['file_path']}")
            print(f"  Hash:   {finding['hash']}")
            print(f"  Threat: {finding['threat_name']}")
            confirm_and_quarantine(
                finding["file_path"],
                file_hash=finding["hash"],
                threat_name=finding["threat_name"],
                tier="known_bad",
                source="scan_cli",
            )
            print()


if __name__ == "__main__":
    main()
