"""
simulate_ransomware.py

SAFE TEST TOOL - this is NOT real ransomware and never touches anything
outside a folder it creates itself.

It creates a batch of harmless dummy text files, then rapidly rewrites
their contents and renames them with a ".locked" extension - mimicking the
FILE ACTIVITY PATTERN ransomware produces (fast, bulk changes across many
files) without doing anything actually malicious. This exists purely to
test devadara/behavior_monitor.py's detection logic.

Usage (manual testing, two terminals):
    Terminal 1: python monitor_cli.py            (watch the same folder)
    Terminal 2: python tests/simulate_ransomware.py
"""

import os
import sys
import time


def create_test_folder(folder_path, num_files=30):
    """Create folder_path with num_files harmless dummy text files."""
    os.makedirs(folder_path, exist_ok=True)
    for i in range(num_files):
        file_path = os.path.join(folder_path, f"file_{i}.txt")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("This is harmless test content.")


def simulate_encryption_burst(folder_path):
    """
    Rapidly rewrite and rename every file in folder_path, one after another
    with no delay - this is the "burst" that should trip the behavior
    monitor's threshold.
    """
    for name in os.listdir(folder_path):
        old_path = os.path.join(folder_path, name)
        if not os.path.isfile(old_path) or old_path.endswith(".locked"):
            continue

        with open(old_path, "w", encoding="utf-8") as f:
            f.write("PRETEND-ENCRYPTED-CONTENT")

        new_path = old_path + ".locked"
        os.rename(old_path, new_path)


if __name__ == "__main__":
    target_folder = sys.argv[1] if len(sys.argv) > 1 else "test_files/ransom_sim"

    print(f"[SIM] Creating 30 harmless test files in '{target_folder}'...")
    create_test_folder(target_folder, num_files=30)

    print("[SIM] Waiting 3 seconds (start your monitor now if you haven't)...")
    time.sleep(3)

    print("[SIM] Simulating a fast encryption-like burst...")
    simulate_encryption_burst(target_folder)

    print("[SIM] Done. Check the monitor for an alert.")
