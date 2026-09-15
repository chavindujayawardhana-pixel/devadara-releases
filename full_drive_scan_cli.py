"""
full_drive_scan_cli.py

A simple command-line test tool for Full Drive Scan - an on-demand "scan
this whole drive" tool, the same idea as SMADAV's "Scan All Drive". Run
this from your terminal like:

    python full_drive_scan_cli.py

Unlike usb_scan_cli.py (which reacts automatically the instant a USB
drive is plugged in), this scans a drive YOU pick, on demand - and a
drive can be far bigger than a USB stick: 126,000+ files were found in
just the first 30 seconds of walking C:\\ on the machine this was built
on, without even finishing. At that scale, two costs already documented
in the rest of this codebase start to matter a lot:

  - YARA runs against every file regardless of type (~48ms each, see
    devadara/yara_scanner.py) - even hash+YARA alone can take hours
    across several hundred thousand files.
  - devadara/signature_scanner.py's Authenticode check costs 1-4 SECONDS
    per executable-shaped file, by design (it shells out to PowerShell) -
    with thousands of .exe/.dll files on a drive like C:\\, that alone can
    run for hours.

So, same trade-off real AV full-scans make (Windows Defender, SMADAV
itself), you're asked Quick or Full up front:

  - Quick: hashes every file and checks it against known-bad hashes, and
    runs YARA against it (devadara/hash_scanner.py + devadara/yara_scanner.py
    directly - NOT devadara/scan_engine.py, so nothing about the shared
    pipeline used by every other DEVADARA tool changes). Only a hash match
    or a YARA rule match is reported - both are concrete evidence. A file
    that doesn't hit either isn't claimed "safe", because the signature
    and ML checks that would normally back that claim never ran.
  - Full: devadara/scan_engine.py's complete Hash -> YARA -> Signature ->
    ML pipeline, identical to every other DEVADARA scanner - thorough, but
    can genuinely take hours on a large drive. The ML model isn't even
    loaded for a Quick scan, since it's never used - no reason to pay that
    (sometimes 20-30s) startup cost for a mode that won't touch it.

A run can be stopped safely at any time with Ctrl+C - whatever was found
up to that point is still reported, not lost. Nothing gets deleted; for
anything flagged, you'll be asked whether to remember/quarantine it, same
confirm-first rule as every other DEVADARA tool.
"""

import os
import sys
import time

import psutil

from devadara.hash_scanner import compute_sha256
from devadara.memory import get_combined_known_bad_hashes, remember_threat
from devadara.ml_scanner import load_model_and_features
from devadara.quarantine import confirm_and_quarantine
from devadara.scan_engine import evaluate_file
from devadara.signature_scanner import load_trusted_publishers
from devadara.yara_scanner import highest_severity_tier, scan_file

PROGRESS_EVERY_N_FILES = 1000


def _safe_print(text=""):
    # A drive-wide scan is far more likely than a single folder to hit a
    # file name this console's codepage can't render - same crash already
    # found (and fixed) in persistence_scan_cli.py/process_scan_cli.py.
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


def _format_elapsed(seconds):
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _quick_evaluate(file_path, known_bad_hashes):
    """
    Hash + YARA only - see module docstring for why. Returns a result
    dict shaped like a subset of scan_engine.evaluate_file()'s output
    (same "tier"/"yara"/"ml" keys) so the SAME reporting code below
    handles both modes without branching. tier is None (not "safe") for a
    file that hit neither check, since Quick mode never verified enough
    to claim "safe".
    """
    base = {"file_path": file_path, "ml": None, "downgraded_from_malware": False}

    file_hash = compute_sha256(file_path)
    if file_hash is None:
        return {**base, "hash": None, "tier": "unreadable", "threat_name": None, "yara": []}

    if file_hash in known_bad_hashes:
        return {**base, "hash": file_hash, "tier": "known_bad",
                "threat_name": known_bad_hashes[file_hash], "yara": []}

    matches = scan_file(file_path)
    tier = highest_severity_tier(matches)
    threat_name = None
    if tier == "malware":
        threat_name = "YARA: " + ", ".join(m["rule"] for m in matches if m["severity"] == "high")

    return {**base, "hash": file_hash, "tier": tier, "threat_name": threat_name, "yara": matches}


def _detail(result):
    # In Quick mode a "malware"/"suspicious" result always came from YARA
    # (ML never runs), so this never falls through to the ml branch there.
    if result["yara"]:
        rule_names = ", ".join(m["rule"] for m in result["yara"])
        return f"YARA: {rule_names}"
    return f"{result['ml']['confidence']:.1%} confidence"


def scan_drive(drive_path, quick, known_bad_hashes, model, feature_columns, trusted_publishers):
    _safe_print()
    _safe_print("=" * 60)
    _safe_print(f"Scanning {drive_path} ({'Quick' if quick else 'Full'} mode)")
    _safe_print("=" * 60)

    known_bad_findings = []
    trusted_signed_count = 0
    clean_count = 0
    to_review = []
    files_scanned = 0
    start_time = time.time()
    interrupted = False

    try:
        for current_folder, _subfolders, file_names in os.walk(drive_path):
            for file_name in file_names:
                full_path = os.path.join(current_folder, file_name)

                if quick:
                    result = _quick_evaluate(full_path, known_bad_hashes)
                else:
                    result = evaluate_file(full_path, known_bad_hashes, model, feature_columns, trusted_publishers)
                files_scanned += 1

                tier = result["tier"]
                if tier == "known_bad":
                    known_bad_findings.append(result)
                elif tier == "trusted_signed":
                    trusted_signed_count += 1
                elif tier in ("malware", "suspicious"):
                    to_review.append(result)
                elif tier == "safe":
                    clean_count += 1
                # "unreadable" / "not_pe" / None (quick mode, no match): not counted, not flagged

                if files_scanned % PROGRESS_EVERY_N_FILES == 0:
                    elapsed = _format_elapsed(time.time() - start_time)
                    _safe_print(
                        f"[INFO] {files_scanned:,} file(s) scanned so far "
                        f"({len(known_bad_findings)} known threat(s), {len(to_review)} flagged) "
                        f"- elapsed {elapsed}"
                    )
    except KeyboardInterrupt:
        interrupted = True
        _safe_print(f"\n[INFO] Scan interrupted - reporting results from the {files_scanned:,} file(s) "
                    "scanned so far.")

    elapsed = _format_elapsed(time.time() - start_time)
    label = "Partial scan (interrupted)" if interrupted else "Scan complete"
    _safe_print(f"\n[INFO] {label}: {files_scanned:,} file(s) in {elapsed}.")

    _safe_print("\n[HASH SCAN]")
    if not known_bad_findings:
        _safe_print("No known threats found by hash scan.")
    else:
        _safe_print(f"!!! {len(known_bad_findings)} THREAT(S) FOUND (hash match) !!!")
        for result in known_bad_findings:
            _safe_print(f"  File:   {result['file_path']}")
            _safe_print(f"  Hash:   {result['hash']}")
            _safe_print(f"  Threat: {result['threat_name']}")
            confirm_and_quarantine(
                result["file_path"], file_hash=result["hash"], threat_name=result["threat_name"],
                tier="known_bad", source="full_drive_scan_cli",
            )

    if quick:
        _safe_print("\n[INFO] Quick mode - signatures/ML were never checked, so no trusted-signed/safe "
                    "counts to report. A file with no hash/YARA hit above wasn't cleared, just not "
                    "concretely flagged by the checks this mode runs.")
    else:
        _safe_print(f"\n[SIGNATURE/ML] {trusted_signed_count} trusted-signed, {clean_count} other clean "
                    "file(s).")
        if model is None:
            _safe_print("[ML SCAN] Skipped - no model loaded (YARA/hash findings above are unaffected).")

    _safe_print("\n[SCAN RESULTS]")
    if not to_review:
        _safe_print("No suspicious or malicious files found.")
        _safe_print("=" * 60)
        return

    for result in to_review:
        _safe_print(f"  [{result['tier']:>10}] ({_detail(result)})  {result['file_path']}")
        if result["downgraded_from_malware"]:
            _safe_print("    (downgraded from 'malware': whitelisted publisher name, but signature chain unverified)")

    _safe_print(f"\n!!! {len(to_review)} FILE(S) FLAGGED FOR REVIEW !!!")
    _safe_print("Review each flagged file below. YARA matches are concrete evidence found in the")
    _safe_print("file itself; the ML model is probabilistic and can be wrong - either way, only")
    _safe_print("confirm files you genuinely believe are malicious.")
    for result in to_review:
        answer = _safe_input(
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
                tier=result["tier"], source="full_drive_scan_cli",
            )
        else:
            _safe_print("  Skipped - not remembered.")
    _safe_print("=" * 60)


def _list_drives():
    drives = []
    for partition in psutil.disk_partitions(all=False):
        drives.append(partition.mountpoint)
    return drives


def main():
    _safe_print("=== DEVADARA - Full Drive Scan ===")

    drives = _list_drives()
    _safe_print(f"[INFO] Drives found: {', '.join(drives) if drives else '(none detected)'}")

    drive_path = _safe_input("Enter the drive or folder to scan (e.g. C:\\): ").strip()
    if not os.path.isdir(drive_path):
        _safe_print(f"[ERROR] '{drive_path}' is not a valid drive or folder.")
        return

    mode_answer = _safe_input(
        "Quick scan (hash + YARA only, faster) or Full scan "
        "(complete pipeline, thorough but can take hours on a large drive)? [Q/F]: "
    ).strip().lower()
    quick = mode_answer != "f"

    known_bad_hashes = get_combined_known_bad_hashes()
    _safe_print(f"[INFO] Loaded {len(known_bad_hashes)} known-bad hash(es) (seed + memory).")

    model, feature_columns, trusted_publishers = None, None, []
    if quick:
        _safe_print("[INFO] Quick mode - not loading the ML model or trusted-publisher list (unused).")
    else:
        trusted_publishers = load_trusted_publishers()
        _safe_print(f"[INFO] Loaded {len(trusted_publishers)} trusted publisher(s).")
        model, feature_columns = load_model_and_features()
        if model is None:
            _safe_print("[INFO] Continuing with hash/YARA/signature-only scanning (no ML model).")

    _safe_print("[INFO] Press Ctrl+C at any time to stop and see results found so far.")
    scan_drive(drive_path, quick, known_bad_hashes, model, feature_columns, trusted_publishers)


if __name__ == "__main__":
    main()
