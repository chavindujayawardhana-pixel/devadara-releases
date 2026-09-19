"""
drive_scanner.py

Walks a directory tree and scans files, returning an outcome dictionary.
Quick mode focuses on executable files. Full mode checks everything.

Per directory, executable-shaped files have their digital signatures
batch-prefetched in one powershell.exe call (see
signature_scanner.check_digital_signatures_batch()) instead of each paying
its own ~1-4s process-launch cost inside evaluate_file() - signature
checking is otherwise the dominant real cost of scanning a folder with many
executables. Batching per directory (not globally across the whole walk)
keeps should_stop() interruption simple - nothing sits buffered across
directory boundaries waiting to be flushed.
"""
import os
from devadara import scan_engine
from devadara.exceptions import is_excepted
from devadara.hidden_file_scanner import is_hidden
from devadara.signature_scanner import check_digital_signatures_batch

def walk_and_scan(root, quick, known_bad_hashes, model, feature_columns, trusted_publishers=None,
                  on_progress=None, should_stop=None, progress_every_n_files=100):
    outcome = {
        "known_bad_findings": [],
        "to_review": [],
        "trusted_signed_count": 0,
        "clean_count": 0,
        "hidden_files": [],
        "files_scanned": 0,
        "interrupted": False
    }

    files_since_progress = 0

    for dirpath, dirnames, filenames in os.walk(root):
        if should_stop and should_stop():
            outcome["interrupted"] = True
            break
            
        # Filter excepted directories
        dirnames[:] = [d for d in dirnames if not is_excepted(os.path.join(dirpath, d))]

        exec_paths = [
            os.path.join(dirpath, filename) for filename in filenames
            if not is_excepted(os.path.join(dirpath, filename))
            and os.path.splitext(filename)[1].lower() in scan_engine.EXECUTABLE_EXTENSIONS
        ]
        sig_by_path = (
            check_digital_signatures_batch(
                exec_paths, trusted_publishers=trusted_publishers, should_stop=should_stop
            )
            if exec_paths else {}
        )

        for filename in filenames:
            if should_stop and should_stop():
                outcome["interrupted"] = True
                break
                
            file_path = os.path.join(dirpath, filename)
            
            if is_excepted(file_path):
                continue

            if is_hidden(file_path):
                outcome["hidden_files"].append(file_path)

            if quick and os.path.splitext(filename)[1].lower() not in scan_engine.EXECUTABLE_EXTENSIONS:
                continue

            result = scan_engine.evaluate_file(
                file_path, known_bad_hashes, model, feature_columns, trusted_publishers,
                precomputed_signature=sig_by_path.get(file_path),
            )
            
            outcome["files_scanned"] += 1
            files_since_progress += 1
            
            tier = result.get("tier")
            if tier == "known_bad":
                outcome["known_bad_findings"].append(result)
            elif tier in ("malware", "suspicious"):
                outcome["to_review"].append(result)
            elif tier == "trusted_signed":
                outcome["trusted_signed_count"] += 1
            else:
                outcome["clean_count"] += 1

            if on_progress and files_since_progress >= progress_every_n_files:
                on_progress(
                    outcome["files_scanned"],
                    len(outcome["known_bad_findings"]),
                    len(outcome["to_review"]),
                    0,
                    file_path,
                    tier,
                    len(outcome["hidden_files"])
                )
                files_since_progress = 0

    if on_progress and files_since_progress > 0:
        on_progress(
            outcome["files_scanned"],
            len(outcome["known_bad_findings"]),
            len(outcome["to_review"]),
            0,
            file_path if 'file_path' in locals() else None,
            tier if 'tier' in locals() else None,
            len(outcome["hidden_files"])
        )

    return outcome
