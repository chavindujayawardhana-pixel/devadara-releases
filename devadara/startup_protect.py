"""
startup_protect.py

CLI-ONLY / MANUAL (via startup_protect_cli.py). Windows no longer launches
this at logon - startup_registration.py now registers the GUI
(gui_app.py --autostart), which does the same job: a startup sweep of
Downloads, the Downloads/USB/behavior watchers, tray notifications instead
of PowerShell toasts, and the same data/scan_log.jsonl entries (the
result -> entry mapping lives in scan_log.record_scan_result() /
record_behavior_alert(), shared by both). The description below is how
this module itself still works when run by hand.

Originally the unattended entry point Windows launched at logon. Every other DEVADARA
tool so far is interactive - it asks which folder to scan, or asks "mark
this as a confirmed threat? [y/N]" for every flagged file. None of that
works when nothing runs until you log in and nobody is there to answer a
prompt, so this module wires the same underlying pieces together
differently:

1. On startup, sweep ~/Downloads once with the full Hash -> Signature ->
   ML pipeline (devadara/scan_engine.py), to catch anything that arrived
   while the PC was off.
2. Then start the same three background watchers the interactive CLIs use
   (Downloads folder, USB drives, ransomware-like behavior on Downloads),
   so protection stays active for the rest of the session.
3. Anything worth your attention - a hash match, an ML "malware"/
   "suspicious" verdict, or a behavior-monitor alert - gets appended to
   data/scan_log.jsonl (see devadara/scan_log.py) instead of prompting,
   AND raises a Windows toast (see devadara/notifier.py) so you actually
   learn about it instead of only finding out if you happen to check the
   log yourself. Nothing is ever auto-confirmed as a threat; review the
   log later with `python startup_cli.py review-log`.

   Findings from a folder sweep (boot_sweep, usb_watch) are summarized
   into ONE toast per sweep rather than one per file - a sweep can flag
   several files in under a second, and per-file toasts at that rate
   would spam you (and Windows itself may start suppressing them). A
   single new download or a behavior-monitor alert is its own event, so
   those get an individual toast each.

Run `python startup_protect_cli.py` (the thin top-level launcher next to
scan_cli.py etc.) to test this with a visible console. In production it's
launched the same way but via pythonw.exe (see startup_registration.py),
so nothing is printed to a visible window - the log file is the record of
what happened.
"""

import os
import time

from devadara import self_integrity
from devadara.behavior_monitor import start_monitoring
from devadara.downloads_monitor import start_monitoring_downloads
from devadara.memory import get_combined_known_bad_hashes
from devadara.ml_scanner import load_model_and_features
from devadara.notifier import notify
from devadara.scan_engine import evaluate_file
from devadara.scan_log import record_behavior_alert, record_scan_result
from devadara.signature_scanner import load_trusted_publishers
from devadara.usb_monitor import start_usb_monitoring

DOWNLOADS_FOLDER = os.path.join(os.path.expanduser("~"), "Downloads")

def _log_if_notable(result, source, notify_immediately=False):
    """
    Log the result to data/scan_log.jsonl if its tier is worth reviewing.
    Returns the tier if it was logged, None otherwise (used by
    sweep_folder to tally a batch summary).

    notify_immediately: fire a toast right now for this single finding.
    Only appropriate for one-file-at-a-time callers (a single new
    download) - sweep_folder always passes False and summarizes instead,
    see module docstring for why.
    """
    # DEVADARA's own genuine files are never logged or notified (their
    # tier is untouched); a changed or unlisted file is logged as usual.
    if self_integrity.is_verified_self_file(result.get("file_path"), result.get("hash")):
        return None
    if record_scan_result(result, source) is None:
        return None

    if notify_immediately:
        confidence = (result.get("ml") or {}).get("confidence")
        detail = f" ({confidence:.0%} confidence)" if confidence is not None else ""
        notify(
            "DEVADARA - Suspicious file detected",
            f"{os.path.basename(result['file_path'])} - {result['tier']}{detail}. "
            "Run 'python startup_cli.py review-log' to review.",
        )

    return result["tier"]


def sweep_folder(folder_path, known_bad_hashes, model, feature_columns, trusted_publishers, source):
    """
    Walk folder_path, logging every notable finding (never notifying per
    file - see module docstring). Returns a {tier: count} dict so the
    caller can send one summary toast for the whole sweep.
    """
    files_checked = 0
    tier_counts = {}
    for current_folder, _subfolders, file_names in os.walk(folder_path):
        for file_name in file_names:
            full_path = os.path.join(current_folder, file_name)
            result = evaluate_file(full_path, known_bad_hashes, model, feature_columns, trusted_publishers)
            files_checked += 1
            tier = _log_if_notable(result, source)
            if tier is not None:
                tier_counts[tier] = tier_counts.get(tier, 0) + 1
    print(f"[INFO] Swept {files_checked} file(s) in '{folder_path}'.")
    return tier_counts


def _notify_sweep_summary(location_label, tier_counts):
    total = sum(tier_counts.values())
    if total == 0:
        return
    breakdown = ", ".join(f"{count} {tier}" for tier, count in sorted(tier_counts.items()))
    notify(
        f"DEVADARA - {total} item(s) flagged",
        f"In {location_label}: {breakdown}. Run 'python startup_cli.py review-log' to review.",
    )


def _on_behavior_alert(alert_info):
    record_behavior_alert(alert_info)
    print(f"[ALERT] Ransomware-like activity in '{alert_info['folder']}' - logged for review.")
    notify(
        "DEVADARA - Ransomware-like activity detected",
        f"Unusual burst of file changes in '{alert_info['folder']}'. "
        "Run 'python startup_cli.py review-log' to review.",
    )


def main():
    print("=== DEVADARA - Startup Protection ===")

    known_bad_hashes = get_combined_known_bad_hashes()
    trusted_publishers = load_trusted_publishers()
    model, feature_columns = load_model_and_features()
    if model is None:
        print("[INFO] Continuing with hash+signature-only scanning (no ML model).")

    if os.path.isdir(DOWNLOADS_FOLDER):
        print(f"[INFO] Sweeping '{DOWNLOADS_FOLDER}'...")
        tier_counts = sweep_folder(DOWNLOADS_FOLDER, known_bad_hashes, model, feature_columns, trusted_publishers, "boot_sweep")
        _notify_sweep_summary("Downloads (startup scan)", tier_counts)

    def on_new_download(file_path):
        result = evaluate_file(file_path, known_bad_hashes, model, feature_columns, trusted_publishers)
        _log_if_notable(result, "downloads_watch", notify_immediately=True)

    def on_drive_connected(drive_path):
        tier_counts = sweep_folder(drive_path, known_bad_hashes, model, feature_columns, trusted_publishers, "usb_watch")
        _notify_sweep_summary(f"removable drive '{drive_path}'", tier_counts)

    observers = []
    if os.path.isdir(DOWNLOADS_FOLDER):
        observers.append(start_monitoring_downloads(DOWNLOADS_FOLDER, on_new_download))
        observers.append(start_monitoring(DOWNLOADS_FOLDER, _on_behavior_alert))
    usb_monitor = start_usb_monitoring(on_drive_connected)

    print("[INFO] Startup protection active (Downloads watch, USB watch, behavior monitor).")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping startup protection...")
        for observer in observers:
            observer.stop()
        for observer in observers:
            observer.join()
        usb_monitor.stop()
        usb_monitor.join()
        print("[INFO] Stopped.")


if __name__ == "__main__":
    main()
