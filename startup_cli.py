"""
startup_cli.py

Manage DEVADARA's Windows startup protection (see devadara/startup_protect.py
and devadara/startup_registration.py). Run from your terminal like:

    python startup_cli.py enable        # start DEVADARA automatically at logon
    python startup_cli.py disable       # stop starting automatically
    python startup_cli.py status        # show whether it's currently enabled
    python startup_cli.py review-log    # review findings logged while unattended

"review-log" is where startup protection's findings come back to you: since
nothing gets auto-confirmed as a threat while running unattended (see
devadara/startup_protect.py for why), this walks each logged finding and
asks - same manual-confirmation rule as every other DEVADARA tool - whether
to remember it as a confirmed threat, then separately whether to quarantine
the file (see devadara/quarantine.py and quarantine_cli.py) before removing
it from the log.
"""

import argparse
import os

from devadara.memory import remember_threat
from devadara.quarantine import confirm_and_quarantine
from devadara.scan_log import read_findings, remove_findings
from devadara.startup_registration import (
    add_to_startup,
    get_registered_command,
    is_in_startup,
    remove_from_startup,
)


def cmd_enable():
    command = add_to_startup()
    print("[INFO] DEVADARA will now start automatically when you log in to Windows.")
    print(f"  Registered command: {command}")
    print("  (Visible and removable any time via Task Manager -> Startup Apps.)")


def cmd_disable():
    removed = remove_from_startup()
    if removed:
        print("[INFO] DEVADARA removed from Windows startup.")
    else:
        print("[INFO] DEVADARA wasn't registered for startup - nothing to do.")


def cmd_status():
    if is_in_startup():
        print("[STATUS] Enabled - DEVADARA starts automatically at logon.")
        print(f"  Command: {get_registered_command()}")
    else:
        print("[STATUS] Disabled - DEVADARA does not start automatically.")


def _describe(entry):
    tier = entry["tier"]
    details = entry["details"]

    if tier == "behavior_alert":
        print(f"  Ransomware-like activity in: {entry['file_path']}")
        print(f"  {details['event_count']} events in {details['window_seconds']}s")
        if details.get("suspect_processes"):
            print("  Suspect process(es): " + ", ".join(details["suspect_processes"]))
        else:
            print("  No suspect process identified.")
        return

    print(f"  File:   {entry['file_path']}")
    print(f"  Hash:   {entry['hash']}")
    print(f"  Tier:   {tier}")
    if details.get("threat_name"):
        print(f"  Threat: {details['threat_name']}")
    if details.get("confidence") is not None:
        print(f"  ML confidence: {details['confidence']:.1%}")
    if details.get("publisher"):
        print(f"  Publisher: {details['publisher']}")
    if details.get("downgraded_from_malware"):
        print("  (downgraded from 'malware': whitelisted publisher name, but signature chain unverified)")


def cmd_review_log():
    findings = read_findings()
    if not findings:
        print("[INFO] Scan log is empty - nothing to review.")
        return

    print(f"[INFO] {len(findings)} finding(s) in the log.")
    resolved_ids = []

    for entry in findings:
        print()
        print("=" * 60)
        print(f"[{entry['timestamp']}] source: {entry['source']}")
        _describe(entry)

        if entry["tier"] == "behavior_alert":
            answer = input("Acknowledge and remove from log? [y/N]: ").strip().lower()
            if answer == "y":
                resolved_ids.append(entry["id"])
            continue

        if entry["tier"] == "known_bad":
            answer = input("Acknowledge and remove from log? [y/N]: ").strip().lower()
            if answer == "y":
                confirm_and_quarantine(
                    entry["file_path"], file_hash=entry["hash"],
                    threat_name=entry["details"].get("threat_name"),
                    tier="known_bad", source="startup_cli",
                )
                resolved_ids.append(entry["id"])
            continue

        # "malware" / "suspicious" - the only tiers with a single file+hash
        # worth possibly remembering as a confirmed threat.
        answer = input(
            f"Mark as a confirmed threat (tier: {entry['tier']})? [y/N]: "
        ).strip().lower()
        if answer == "y":
            remember_threat(
                entry["hash"],
                threat_name=f"ML-flagged ({entry['tier']}): {os.path.basename(entry['file_path'])}",
                source="ml_model",
            )
            confirm_and_quarantine(
                entry["file_path"], file_hash=entry["hash"],
                threat_name=f"ML-flagged ({entry['tier']})", tier=entry["tier"], source="startup_cli",
            )
            resolved_ids.append(entry["id"])
        else:
            dismiss = input("  Dismiss without confirming (remove from log anyway)? [y/N]: ").strip().lower()
            if dismiss == "y":
                resolved_ids.append(entry["id"])
            else:
                print("  Left in the log for later.")

    remove_findings(set(resolved_ids))
    print()
    print(f"[INFO] {len(resolved_ids)} finding(s) resolved and removed from the log.")


def main():
    parser = argparse.ArgumentParser(description="Manage DEVADARA's Windows startup protection.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("enable", help="Start DEVADARA automatically at Windows logon.")
    subparsers.add_parser("disable", help="Stop DEVADARA from starting automatically.")
    subparsers.add_parser("status", help="Show whether startup protection is currently enabled.")
    subparsers.add_parser("review-log", help="Review findings recorded while running unattended.")

    args = parser.parse_args()

    {
        "enable": cmd_enable,
        "disable": cmd_disable,
        "status": cmd_status,
        "review-log": cmd_review_log,
    }[args.command]()


if __name__ == "__main__":
    main()
