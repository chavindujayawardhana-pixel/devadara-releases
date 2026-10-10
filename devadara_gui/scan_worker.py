"""
scan_worker.py

Phase 3b: the background-thread worker that actually runs a scan. No
worker/QThread pattern exists anywhere in the current codebase (the old
"RealTimeScanPopup" this might sound like belonged to the previous,
fully-deleted devadara_gui/ - see CLAUDE.md) - this is the first one, built
by calling straight into the existing devadara/ modules rather than
reimplementing any of them:

  - devadara.drive_scanner.walk_and_scan() - walks a drive/folder, running
    every file through scan_engine.evaluate_file(); already has the
    on_progress/should_stop hooks this needs.
  - devadara.persistence_scanner.list_persistence_entries() - enumerates
    registry Run/RunOnce + Scheduled Tasks + Services entries.
  - devadara.process_scanner.list_suspicious_processes() - the Memory
    Processes sweep.

Persistence/process entries are evaluated here one at a time via
scan_engine.evaluate_file() directly (the same pipeline entry point every
other DEVADARA tool uses) rather than through
persistence_scanner.evaluate_persistence_entries()/
process_scanner.evaluate_suspicious_processes() - those two batch-evaluate
with no progress/stop hook of their own, which would make this phase both
silently unresponsive to Stop and give no live progress for however long a
handful of signature checks (1-4s each, see signature_scanner.py) take.
Same caching-per-unique-path behavior those functions already have, just
with progress/stop added between entries.

Never writes to data/scan_log.jsonl - that log is specifically
startup_protect.py's unattended-sweep record (see its own docstring, and
devadara_gui/dashboard_page.py's stat cards, which read it scoped to
unattended findings only). Findings from an interactive scan stay in
memory on the GUI side for this phase.

IMPORTANT - two devadara/ calls have been confirmed (via minimal, GUI-free
reproductions, isolating each candidate one at a time) to hang indefinitely
when called from a QThread on this machine, and must be called on the MAIN
thread instead:

  - devadara.ml_scanner.load_model_and_features() (joblib.load()) - a
    Windows + joblib/loky multiprocessing-bootstrap interaction. Completes
    in ~3-7s called synchronously; never returns at all from a QThread.
  - devadara.persistence_scanner.list_autostart_services() specifically
    (psutil.win_service_iter()) - confirmed by testing
    list_registry_run_entries() (winreg), list_scheduled_tasks() (schtasks
    subprocess), and list_autostart_services() individually on a QThread:
    only the services one hangs; the other two, and an unrelated PowerShell
    subprocess call (signature_scanner.check_digital_signature()), all
    completed normally. Since list_persistence_entries() bundles all three
    sources together, the whole call has to move, not just the services
    part - it takes ~10s even run normally (services enumeration is
    genuinely slow, not just slow-because-QThread), so this is a real,
    bounded, unavoidable pause, not a workaround for a fake problem.

process_scanner.list_suspicious_processes() (psutil.process_iter(), a
different API) was tested the same way and is safe on a QThread - it still
runs inside ScanWorker.run() below, unchanged.

ScanPage does both of the above on the GUI thread (wait cursor covering
each) before constructing ScanWorker, and passes the results in - see
gather_persistence_entries() below, called from ScanPage._on_scan_clicked().
"""

import os
import time

from PySide6.QtCore import QObject, Signal

from devadara import drive_scanner, persistence_scanner, process_scanner, scan_engine
from devadara.memory import get_combined_known_bad_hashes
from devadara.signature_scanner import check_digital_signatures_batch, load_trusted_publishers
from devadara_gui.process_guard import describe_suspect

THREAT_TIERS = {"known_bad", "malware", "suspicious"}

# Matches check_digital_signatures_batch()'s own default chunk_size and
# drive_scanner.py's own _SIGNATURE_SLICE_SIZE - see _evaluate_entries()'s
# docstring for why prefetching happens in bounded slices, not all at once.
_SIGNATURE_SLICE_SIZE = 40

# Registry Area / Start-Up Area / Services tree items -> persistence_scanner
# entry "source" values. Start-Up Area maps to Scheduled Tasks - the
# closest available concept; devadara/ has no separate "Startup folder
# shortcuts" enumerator.
_SYSTEM_AREA_SOURCE_MAP = {
    "registry": "registry",
    "startup": "scheduled_task",
    "services": "service",
}


def gather_persistence_entries(system_area_flags):
    """MUST be called from the main/GUI thread - see module docstring.
    Returns the resolved (registry/scheduled-task/service) entries matching
    whichever of Registry Area/Start-Up Area/Services are checked, or []
    if none are (list_persistence_entries() is skipped entirely then, not
    just filtered afterward, since it's the slow, must-be-on-the-main-
    thread call)."""
    wanted_sources = {
        _SYSTEM_AREA_SOURCE_MAP[key]
        for key, enabled in system_area_flags.items()
        if enabled and key in _SYSTEM_AREA_SOURCE_MAP
    }
    if not wanted_sources:
        return []
    all_entries = persistence_scanner.list_persistence_entries()
    return [e for e in all_entries if e["source"] in wanted_sources]


def format_elapsed(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m {secs}s"


class ScanWorker(QObject):
    """Runs entirely on a background thread (see ScanPage._on_scan_clicked
    for the moveToThread() wiring). Every signal here is safe to connect
    directly to GUI slots - Qt auto-queues a signal emitted from one thread
    to a receiver that lives on another."""

    progress = Signal(str, int)                # current_label, checked
    stats = Signal(int, int, int)              # checked, threats, hidden
    log_line = Signal(str)
    # Every flagged scan_engine result (THREAT_TIERS), one per file, sent
    # once just before finished - including from a stopped scan, since
    # whatever it found before stopping is still real. Used to log
    # auto-scan findings and raise the hidden-window tray notification.
    findings = Signal(list)
    # Everything the Results page shows for this scan, sent once just before
    # finished (kept in memory only - see results_store.py):
    #   {"flagged": [scan results], "hidden": [paths],
    #    "startup": [persistence entries whose target was flagged, each with
    #                its "scan" result], "processes": [suspicious processes,
    #                each with exe/create_time snapshotted for process_guard,
    #                its "reasons" and the "scan" of its .exe]}
    results = Signal(dict)
    finished = Signal(bool, int, int, int, float)  # stopped_early, checked, threats, hidden, elapsed_seconds

    def __init__(self, targets, system_area_flags, quick, model, feature_columns,
                 persistence_entries, parent=None):
        """targets: list of folder/drive paths to walk. system_area_flags:
        {"registry": bool, "startup": bool, "services": bool,
        "memory_processes": bool} - only "memory_processes" is still acted
        on here (process_scanner is safe on a QThread); the other three are
        already baked into persistence_entries. quick: passed straight to
        drive_scanner.walk_and_scan() (executable-files-only, when True).
        model/feature_columns/persistence_entries: already loaded on the
        main thread by the caller - see module docstring for why."""
        super().__init__(parent)
        self._targets = list(targets)
        self._system_area_flags = dict(system_area_flags)
        self._quick = quick
        self._model = model
        self._feature_columns = feature_columns
        self._persistence_entries = list(persistence_entries)
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def _should_stop(self):
        return self._stop_requested

    def run(self):
        start_time = time.time()
        model, feature_columns = self._model, self._feature_columns
        persistence_entries = self._persistence_entries

        known_bad_hashes = get_combined_known_bad_hashes()
        trusted_publishers = load_trusted_publishers()
        self._flagged = []

        suspicious_processes = []
        if self._system_area_flags.get("memory_processes"):
            suspicious_processes = process_scanner.list_suspicious_processes()
            # Identity snapshot now (path + start time), so a later Suspend/
            # Kill from the Results page can refuse a reused PID.
            for proc in suspicious_processes:
                snapshot = describe_suspect(proc)
                proc["create_time"] = snapshot["create_time"]
                proc["exe"] = proc.get("exe") or snapshot["exe"]
        hidden_files = []

        checked = 0
        threats = 0
        hidden = 0
        stopped = self._should_stop()

        for target in self._targets:
            if stopped:
                break

            base_checked, base_threats, base_hidden = checked, threats, hidden

            def on_progress(files_scanned, known_bad_count, review_count, _unused,
                             file_path, _tier, hidden_count,
                             _bc=base_checked, _bt=base_threats, _bh=base_hidden):
                c = _bc + files_scanned
                t = _bt + known_bad_count + review_count
                h = _bh + hidden_count
                self.progress.emit(file_path or "", c)
                self.stats.emit(c, t, h)
                if file_path:
                    self.log_line.emit(file_path)

            outcome = drive_scanner.walk_and_scan(
                target, self._quick, known_bad_hashes, model, feature_columns, trusted_publishers,
                on_progress=on_progress, should_stop=self._should_stop, progress_every_n_files=5,
            )
            checked += outcome["files_scanned"]
            self._flagged.extend(outcome["known_bad_findings"] + outcome["to_review"])
            threats += len(outcome["known_bad_findings"]) + len(outcome["to_review"])
            hidden += len(outcome["hidden_files"])
            hidden_files.extend(outcome["hidden_files"])
            if outcome["interrupted"]:
                stopped = True

        if not stopped:
            checked, threats, hidden, stopped = self._evaluate_entries(
                persistence_entries,
                get_path=lambda e: e.get("resolved_path"),
                get_label=lambda e: e.get("location") or e.get("name") or "persistence entry",
                known_bad_hashes=known_bad_hashes, model=model, feature_columns=feature_columns,
                trusted_publishers=trusted_publishers, checked=checked, threats=threats, hidden=hidden,
            )

        if not stopped:
            checked, threats, hidden, stopped = self._evaluate_entries(
                suspicious_processes,
                get_path=lambda e: e.get("exe") if e.get("exe") and os.path.isfile(e["exe"]) else None,
                get_label=lambda e: f"PID {e['pid']} ({e['name']})",
                known_bad_hashes=known_bad_hashes, model=model, feature_columns=feature_columns,
                trusted_publishers=trusted_publishers, checked=checked, threats=threats, hidden=hidden,
            )

        elapsed = time.time() - start_time
        unique = {}
        for result in self._flagged:
            unique.setdefault(result["file_path"], result)
        self.findings.emit(list(unique.values()))
        self.results.emit({
            "flagged": list(unique.values()),
            "hidden": hidden_files,
            "startup": [e for e in persistence_entries
                        if e.get("scan") and e["scan"]["tier"] in THREAT_TIERS],
            "processes": [p for p in suspicious_processes if "scan" in p],
        })
        self.finished.emit(stopped, checked, threats, hidden, elapsed)

    def _evaluate_entries(self, entries, get_path, get_label, known_bad_hashes, model,
                           feature_columns, trusted_publishers, checked, threats, hidden):
        """Evaluate each entry via scan_engine.evaluate_file() directly (see
        module docstring for why, over the batch evaluate_* helpers), one
        unique path per cache hit, with a progress/stop check between each
        entry. Returns the updated (checked, threats, hidden, stopped).

        Signature checks for executable-shaped entries are batch-prefetched
        per SLICE of up to _SIGNATURE_SLICE_SIZE entries at a time (not for
        every entry up front) - prefetching everything before evaluating
        any entry produced a real, measured multi-second stretch with zero
        progress on this session's own 488-persistence-entry test (worse on
        a machine with more entries), the same class of stall confirmed and
        fixed the same way in drive_scanner.walk_and_scan(). A path already
        resolved in an earlier slice is never re-fetched."""
        cache = {}
        sig_by_path = {}
        stopped = False
        for slice_start in range(0, len(entries), _SIGNATURE_SLICE_SIZE):
            if self._should_stop():
                stopped = True
                break

            entry_slice = entries[slice_start:slice_start + _SIGNATURE_SLICE_SIZE]

            new_exec_paths = sorted({
                path for path in (get_path(e) for e in entry_slice)
                if path and path not in sig_by_path
                and os.path.splitext(path)[1].lower() in scan_engine.EXECUTABLE_EXTENSIONS
            })
            if new_exec_paths:
                sig_by_path.update(check_digital_signatures_batch(
                    new_exec_paths, trusted_publishers=trusted_publishers,
                    should_stop=self._should_stop, chunk_size=_SIGNATURE_SLICE_SIZE,
                ))

            for entry in entry_slice:
                if self._should_stop():
                    stopped = True
                    break

                path = get_path(entry)
                label = get_label(entry)
                if path:
                    if path not in cache:
                        cache[path] = scan_engine.evaluate_file(
                            path, known_bad_hashes, model, feature_columns,
                            trusted_publishers=trusted_publishers,
                            precomputed_signature=sig_by_path.get(path),
                        )
                    result = cache[path]
                    entry["scan"] = result
                    checked += 1
                    if result["tier"] in THREAT_TIERS:
                        threats += 1
                        self._flagged.append(result)
                else:
                    entry["scan"] = None

                self.progress.emit(label, checked)
                self.stats.emit(checked, threats, hidden)
                self.log_line.emit(label)

            if stopped:
                break

        return checked, threats, hidden, stopped
