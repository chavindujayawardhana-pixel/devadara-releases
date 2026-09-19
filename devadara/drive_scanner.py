"""
drive_scanner.py

Walks a directory tree and scans files, returning an outcome dictionary.
Quick mode focuses on executable files. Full mode checks everything.

Executable-shaped files have their digital signatures batch-prefetched
(see signature_scanner.check_digital_signatures_batch()) instead of each
paying its own ~1-4s process-launch cost inside evaluate_file() - signature
checking is otherwise the dominant real cost of scanning a folder with many
executables. Prefetching happens per SLICE of up to _SIGNATURE_SLICE_SIZE
filenames at a time, not per whole directory - a directory can hold
thousands of executables (a real, measured example: C:\\Windows\\System32's
root alone has 4,333), and batching all of them before evaluating or
reporting progress on any single file produced a real, reproduced 44.5s
stretch with zero visible progress. _SIGNATURE_SLICE_SIZE matches
check_digital_signatures_batch()'s own default chunk_size (40) so each
slice's prefetch is at most one PowerShell launch, bounding the worst-case
silent gap to roughly one chunk's time regardless of directory size.
"""
import os
from devadara import scan_engine
from devadara.exceptions import is_excepted
from devadara.hidden_file_scanner import is_hidden
from devadara.signature_scanner import check_digital_signatures_batch

# Matches check_digital_signatures_batch()'s own default chunk_size, passed
# explicitly (not left to coincide) so a slice's prefetch is never more
# than one PowerShell launch even if that default changes independently.
_SIGNATURE_SLICE_SIZE = 40

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

        stop_now = False
        for slice_start in range(0, len(filenames), _SIGNATURE_SLICE_SIZE):
            if should_stop and should_stop():
                stop_now = True
                break

            filename_slice = filenames[slice_start:slice_start + _SIGNATURE_SLICE_SIZE]

            exec_paths = [
                os.path.join(dirpath, filename) for filename in filename_slice
                if not is_excepted(os.path.join(dirpath, filename))
                and os.path.splitext(filename)[1].lower() in scan_engine.EXECUTABLE_EXTENSIONS
            ]
            sig_by_path = (
                check_digital_signatures_batch(
                    exec_paths, trusted_publishers=trusted_publishers, should_stop=should_stop,
                    chunk_size=_SIGNATURE_SLICE_SIZE,
                )
                if exec_paths else {}
            )

            for filename in filename_slice:
                if should_stop and should_stop():
                    stop_now = True
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

            if stop_now:
                break

        if stop_now:
            outcome["interrupted"] = True
            break

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
