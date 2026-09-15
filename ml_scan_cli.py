"""
ml_scan_cli.py

A simple command-line test tool for Step 2 (the ML model), in isolation -
this tool deliberately skips the hash and digital-signature layers (see
devadara/scan_engine.py for the full pipeline used by the auto-scan tools)
so you can see exactly what the raw ML model thinks of a file, structure
alone. That means a file the signature layer would normally vouch for can
still show up here as "malware" or "suspicious" - that's expected, not a
bug, and is exactly the gap devadara/scan_engine.py closes.
Run this from your terminal like:

    python ml_scan_cli.py

It will ask you for a folder, then run the ML model against every
.exe/.dll file found there (non-executable files are skipped, since the
model only understands Windows PE files). Nothing gets deleted - this is
detection and reporting only, same as the hash scanner.

Verdicts are reported in three tiers instead of a binary malicious/safe
split: "malware" (>=85% confidence), "suspicious" (60-85%, needs manual
review), and "safe" (<60%). At the end, for each "malware" or "suspicious"
file, you'll be asked whether you want to remember it as a confirmed
threat (Step 3's memory database). Nothing is ever added to memory
automatically - only your explicit "yes" does that, matching the
project's "manual confirmation only" rule. Be aware the ML model can be
wrong sometimes (see Step 2's false positives on real Windows driver
files) - only confirm files you actually believe are malicious.
"""

import os

from devadara.hash_scanner import compute_sha256
from devadara.ml_scanner import load_model_and_features, predict_file
from devadara.memory import remember_threat
from devadara.quarantine import confirm_and_quarantine


def main():
    print("=== DEVADARA - ML-Based Scanner (Step 2) ===")

    model, feature_columns = load_model_and_features()
    if model is None:
        return  # load_model_and_features() already printed a warning

    folder_to_scan = input("Enter the full path of a folder to scan: ").strip()

    if not os.path.isdir(folder_to_scan):
        print(f"[ERROR] '{folder_to_scan}' is not a valid folder.")
        return

    pe_files_checked = 0
    flagged = []

    for current_folder, _subfolders, file_names in os.walk(folder_to_scan):
        for file_name in file_names:
            full_path = os.path.join(current_folder, file_name)

            result = predict_file(full_path, model, feature_columns)

            if not result["is_pe"]:
                continue  # not an executable file - this layer skips it

            pe_files_checked += 1
            print(f"  [{result['tier']:>10}] ({result['confidence']:.1%} confidence)  {full_path}")

            if result["tier"] in ("malware", "suspicious"):
                flagged.append((full_path, result["tier"], result["confidence"]))

    print()
    print(f"[INFO] Checked {pe_files_checked} executable file(s).")
    if not flagged:
        print("No suspicious or malicious files found.")
        return

    print(f"!!! {len(flagged)} FILE(S) FLAGGED FOR REVIEW !!!")
    for path, tier, confidence in flagged:
        print(f"  [{tier:>10}] {path}  (confidence: {confidence:.1%})")

    # Manual confirmation step - nothing gets remembered without your "yes".
    print()
    print("Review each flagged file below. The ML model can be wrong, so")
    print("only confirm files you genuinely believe are malicious.")
    for path, tier, confidence in flagged:
        answer = input(
            f"\nMark '{path}' (tier: {tier}, confidence {confidence:.1%}) as a confirmed threat? [y/N]: "
        ).strip().lower()

        if answer == "y":
            file_hash = compute_sha256(path)
            if file_hash is None:
                print(f"[ERROR] Could not hash '{path}' - skipping.")
                continue
            remember_threat(
                file_hash,
                threat_name=f"ML-flagged ({tier}): {os.path.basename(path)}",
                source="ml_model",
            )
            confirm_and_quarantine(path, file_hash=file_hash, threat_name=f"ML-flagged ({tier})", tier=tier, source="ml_scan_cli")
        else:
            print("  Skipped - not remembered.")


if __name__ == "__main__":
    main()
