"""
hash_scanner.py

This is the simplest layer of DEVADARA's defenses, similar to how your immune
system recognizes germs it has "seen" before using antibodies.

How it works:
1. We keep a local JSON file (data/known_bad_hashes.json) that maps a
   SHA256 hash -> a description of the threat it belongs to.
2. For every file we scan, we compute its SHA256 hash.
3. If that hash is already in our "known bad" list, we flag the file.

SHA256 is a one-way "fingerprint" function: the same file content always
produces the same hash, and changing even one byte produces a completely
different hash. It's fast and reliable for exact-match detection.
"""

import hashlib
import json
import os


def compute_sha256(file_path):
    """
    Calculate the SHA256 hash of a single file.

    We read the file in small chunks (4096 bytes at a time) instead of
    loading the whole file into memory at once. This means even a huge
    file (like a multi-gigabyte video) won't slow down or crash the scan.

    Returns the hash as a hex string, or None if the file couldn't be read
    (e.g. it's locked by another program, or we don't have permission).
    """
    sha256_hasher = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:  # "rb" = read in binary mode
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break  # we've reached the end of the file
                sha256_hasher.update(chunk)
    except (PermissionError, FileNotFoundError, OSError):
        # Some files can't be read (in use, no permission, broken link, etc).
        # We skip them quietly rather than crashing the whole scan.
        return None

    return sha256_hasher.hexdigest()


def load_known_bad_hashes(json_path):
    """
    Load our local "known bad hashes" database from a JSON file.

    The JSON file looks like:
        { "somehash123...": "Name of the threat", ... }

    Returns a Python dictionary. If the file is missing or broken, we
    return an empty dictionary instead of crashing, so a scan can still run
    (it just won't find anything, which is safer than stopping entirely).
    """
    if not os.path.exists(json_path):
        print(f"[WARNING] Known-bad hash file not found at: {json_path}")
        return {}

    try:
        with open(json_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        print(f"[WARNING] Could not parse JSON in: {json_path}")
        return {}


def scan_folder(folder_path, known_bad_hashes):
    """
    Walk through every file in folder_path (including subfolders),
    hash each one, and check it against known_bad_hashes.

    Returns a list of "findings" - one dictionary per infected file:
        {
            "file_path": "C:\\Users\\...\\bad.exe",
            "hash": "275a021b...",
            "threat_name": "EICAR-Test-File"
        }

    This function does NOT delete or touch any files. It only reports.
    """
    findings = []
    files_scanned = 0

    # os.walk visits the given folder AND every subfolder inside it.
    for current_folder, _subfolders, file_names in os.walk(folder_path):
        for file_name in file_names:
            full_path = os.path.join(current_folder, file_name)

            file_hash = compute_sha256(full_path)
            files_scanned += 1

            if file_hash is None:
                continue  # couldn't read this file, skip it

            if file_hash in known_bad_hashes:
                findings.append({
                    "file_path": full_path,
                    "hash": file_hash,
                    "threat_name": known_bad_hashes[file_hash],
                })

    print(f"[INFO] Scanned {files_scanned} file(s) in '{folder_path}'.")
    return findings
