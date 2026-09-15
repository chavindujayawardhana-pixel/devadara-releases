"""
monitor_cli.py

A simple command-line test tool for Step 4 (real-time behavior monitoring).
Run this from your terminal like:

    python monitor_cli.py

It will ask you for a folder to watch, then run in the background looking
for ransomware-like bursts of file activity. When one is detected, it
prints what it found and which process(es) look responsible, and asks you
- individually, per process - whether to suspend it. A suspended process
is paused (not killed), giving you a chance to review it before choosing
to kill it, resume it, or just leave it suspended. Nothing is ever
suspended, killed, or resumed without your explicit input.

Press Ctrl+C to stop monitoring.
"""

import os
import time

from devadara.behavior_monitor import (
    kill_process,
    resume_process,
    start_monitoring,
    suspend_process,
)


def on_alert(alert_info):
    print()
    print("=" * 60)
    print("!!! SUSPICIOUS ACTIVITY DETECTED (ransomware-like pattern) !!!")
    print(f"  Folder:       {alert_info['folder']}")
    print(f"  Events seen:  {alert_info['event_count']} in the last {alert_info['window_seconds']}s")
    print("  Sample affected files:")
    for file_path in alert_info["sample_files"]:
        print(f"    - {file_path}")

    suspects = alert_info["suspect_processes"]
    print()
    if not suspects:
        print("  No suspect process could be identified (it may have already")
        print("  finished, or requires Administrator rights to inspect).")
        print("  You may want to check Task Manager manually.")
    else:
        print(f"  {len(suspects)} suspect process(es) had files open in this folder:")
        for suspect in suspects:
            print(f"    - PID {suspect['pid']}: {suspect['name']}")

        print()
        print("  Review carefully - process identification is a best-effort")
        print("  heuristic, not a certainty.")
        for suspect in suspects:
            pid, name = suspect["pid"], suspect["name"]
            answer = input(
                f"\nSuspend process PID {pid} ({name})? [y/N]: "
            ).strip().lower()
            if answer != "y":
                print("  Left running - not suspended.")
                continue

            if not suspend_process(pid):
                continue

            print(f"  Process {pid} ({name}) is suspended (paused, not killed).")
            print("  Take a moment to review it (e.g. in Task Manager) before deciding.")
            decision = input(
                f"  [K]ill it, [R]esume it, or press Enter to leave it suspended: "
            ).strip().lower()
            if decision == "k":
                if kill_process(pid):
                    print(f"  Process {pid} killed.")
            elif decision == "r":
                if resume_process(pid):
                    print(f"  Process {pid} resumed.")
            else:
                print(f"  Left process {pid} suspended - resume or kill it later via Task Manager.")
    print("=" * 60)


def main():
    print("=== DEVADARA - Real-Time Behavior Monitor (Step 4) ===")

    folder_to_watch = input("Enter the full path of a folder to monitor: ").strip()

    if not os.path.isdir(folder_to_watch):
        print(f"[ERROR] '{folder_to_watch}' is not a valid folder.")
        return

    observer = start_monitoring(folder_to_watch, on_alert)
    print(f"[INFO] Watching '{folder_to_watch}' for ransomware-like activity...")
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
