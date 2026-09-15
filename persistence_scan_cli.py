"""
persistence_scan_cli.py

A simple command-line test tool for the Persistence Check (detecting OTHER
programs' persistence mechanisms - not DEVADARA's own, see
devadara/startup_registration.py for that). Run this from your terminal
like:

    python persistence_scan_cli.py

It enumerates every Registry Run/RunOnce key, Scheduled Task, and
auto-start Service on this machine (see devadara/persistence_scanner.py),
resolves each entry's target executable, and runs it through DEVADARA's
full pipeline (see devadara/scan_engine.py): Hash Check -> YARA Rules
Check -> Digital Signature Check -> ML Model Check.

This is READ-ONLY against the registry, Task Scheduler, and service list -
it never creates, modifies, or removes a persistence entry. For anything
flagged "malware" or "suspicious", you'll be asked whether to remember it
as a confirmed threat and whether to quarantine the file, same as every
other DEVADARA scanner - but quarantining only neutralizes the payload;
the autostart entry itself still exists afterward (now pointing at a
missing file) and needs removing by hand (Task Scheduler / services.msc /
regedit).

On-demand only for now - not yet wired into startup_protect.py's
unattended boot sweep.
"""

import os
import sys
from collections import defaultdict

from devadara.memory import get_combined_known_bad_hashes, remember_threat
from devadara.ml_scanner import load_model_and_features
from devadara.persistence_scanner import evaluate_persistence_entries, list_persistence_entries
from devadara.quarantine import confirm_and_quarantine
from devadara.signature_scanner import load_trusted_publishers


def _safe_print(text=""):
    # A raw registry value / task name / service path can contain a
    # character this console's codepage can't render (confirmed live: a
    # non-cp1252 character inside a real HKLM\...\WOW6432Node\...\Run
    # entry crashes a plain print() with UnicodeEncodeError) - fall back to
    # a lossy re-encode rather than crashing the whole scan over one entry.
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        print(str(text).encode(encoding, errors="replace").decode(encoding))


def _safe_input(prompt):
    # input() writes its prompt to stdout too, so it's exposed to the exact
    # same encoding crash as _safe_print - confirmed live against a real
    # persistence target path (a SmadAV component actually named
    # "SMΔRTP.exe", a stylized "A") that print() alone didn't catch
    # since the crash happens inside input()'s own prompt write, not ours.
    try:
        return input(prompt)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        safe_prompt = prompt.encode(encoding, errors="replace").decode(encoding)
        return input(safe_prompt)


def _location_label(entry):
    label = f"[{entry['source']}] {entry['location']}"
    if entry.get("name"):
        label += f" ({entry['name']})"
    return label


def _detail(result):
    # A "malware"/"suspicious" tier can come from YARA alone, with no ML
    # result at all - see scan_engine.evaluate_file().
    if result["yara"]:
        rule_names = ", ".join(m["rule"] for m in result["yara"])
        return f"YARA: {rule_names}"
    return f"{result['ml']['confidence']:.1%} confidence"


def _note_dangling_entries_after_quarantine():
    _safe_print("  NOTE: the autostart entries above still exist and now point at a missing file.")
    _safe_print("        Remove them by hand (Task Scheduler / services.msc / regedit) as needed.")


def main():
    _safe_print("=== DEVADARA - Persistence Check ===")

    known_bad_hashes = get_combined_known_bad_hashes()
    _safe_print(f"[INFO] Loaded {len(known_bad_hashes)} known-bad hash(es) (seed + memory).")

    trusted_publishers = load_trusted_publishers()
    _safe_print(f"[INFO] Loaded {len(trusted_publishers)} trusted publisher(s).")

    model, feature_columns = load_model_and_features()
    if model is None:
        _safe_print("[INFO] Continuing with hash/YARA/signature-only scanning (no ML model).")

    _safe_print("\n[INFO] Enumerating registry Run/RunOnce keys, Scheduled Tasks, and auto-start Services...")
    entries = list_persistence_entries()

    counts_by_source = defaultdict(int)
    for entry in entries:
        counts_by_source[entry["source"]] += 1
    _safe_print(
        f"[INFO] Found {counts_by_source['registry']} registry entry(ies), "
        f"{counts_by_source['scheduled_task']} scheduled task(s), "
        f"{counts_by_source['service']} auto-start service(s)."
    )

    dangling = [e for e in entries if e["resolved_path"] is None]
    resolvable = [e for e in entries if e["resolved_path"] is not None]

    entries_by_path = defaultdict(list)
    for entry in resolvable:
        entries_by_path[entry["resolved_path"]].append(entry)

    _safe_print(
        f"[INFO] Evaluating {len(entries_by_path)} unique executable(s) referenced by "
        f"{len(resolvable)} entry(ies) - this can take a while if signature checks are needed..."
    )
    evaluate_persistence_entries(entries, known_bad_hashes, model, feature_columns, trusted_publishers)

    known_bad_paths = []
    review_paths = []
    trusted_signed_count = 0
    other_clean_count = 0

    for path, group_entries in entries_by_path.items():
        result = group_entries[0]["scan"]  # shared across the group - see evaluate_persistence_entries
        tier = result["tier"]
        if tier == "known_bad":
            known_bad_paths.append((path, result, group_entries))
        elif tier in ("malware", "suspicious"):
            review_paths.append((path, result, group_entries))
        elif tier == "trusted_signed":
            trusted_signed_count += 1
        else:
            other_clean_count += 1

    _safe_print("\n[HASH SCAN]")
    if not known_bad_paths:
        _safe_print("No known threats found among persistence targets.")
    else:
        _safe_print(f"!!! {len(known_bad_paths)} THREAT(S) FOUND (hash match) !!!")
        for path, result, group_entries in known_bad_paths:
            _safe_print(f"\n  File:   {path}")
            _safe_print(f"  Hash:   {result['hash']}")
            _safe_print(f"  Threat: {result['threat_name']}")
            _safe_print("  Referenced by:")
            for entry in group_entries:
                _safe_print(f"    {_location_label(entry)}")
            quarantined = confirm_and_quarantine(
                path, file_hash=result["hash"], threat_name=result["threat_name"],
                tier="known_bad", source="persistence_scan_cli",
            )
            if quarantined:
                _note_dangling_entries_after_quarantine()

    _safe_print(f"\n[SIGNATURE/ML] {trusted_signed_count} trusted-signed, {other_clean_count} other clean "
                f"executable(s) out of {len(entries_by_path)} unique target(s) evaluated.")

    _safe_print("\n[SCAN RESULTS]")
    if not review_paths:
        _safe_print("No suspicious or malicious persistence targets found.")
    else:
        _safe_print(f"!!! {len(review_paths)} FILE(S) FLAGGED FOR REVIEW !!!")
        _safe_print("Review each flagged file below. YARA matches are concrete evidence found in the")
        _safe_print("file itself; the ML model is probabilistic and can be wrong - either way, only")
        _safe_print("confirm files you genuinely believe are malicious.")
        for path, result, group_entries in review_paths:
            detail = _detail(result)
            _safe_print(f"\n  [{result['tier']:>10}] ({detail})  {path}")
            if result["downgraded_from_malware"]:
                _safe_print("    (downgraded from 'malware': whitelisted publisher name, but signature chain unverified)")
            _safe_print("  Referenced by:")
            for entry in group_entries:
                _safe_print(f"    {_location_label(entry)}")

            answer = _safe_input(
                f"\nMark '{path}' (tier: {result['tier']}, {detail}) as a confirmed threat? [y/N]: "
            ).strip().lower()

            if answer == "y":
                source = "yara" if result["yara"] else "ml_model"
                label = "YARA" if result["yara"] else "ML"
                threat_name = f"{label}-flagged ({result['tier']}): {os.path.basename(path)}"
                remember_threat(result["hash"], threat_name=threat_name, source=source)
                quarantined = confirm_and_quarantine(
                    path, file_hash=result["hash"], threat_name=threat_name,
                    tier=result["tier"], source="persistence_scan_cli",
                )
                if quarantined:
                    _note_dangling_entries_after_quarantine()
            else:
                _safe_print("  Skipped - not remembered.")

    if dangling:
        _safe_print(f"\n[INFO] {len(dangling)} entry(ies) point at a target that no longer exists on "
                     "disk (not scanned - nothing to scan).")

    _safe_print("=" * 60)


if __name__ == "__main__":
    main()
