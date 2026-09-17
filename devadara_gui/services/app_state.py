"""
app_state.py

The one place the GUI talks to DEVADARA's real backend (Section 29 of the
design spec: "Connect the GUI to the real backend... Keep GUI code separate
from malware detection implementation."). Every page reaches the actual
devadara/ engines only through this object - nothing here re-implements
detection logic, it only orchestrates modules that were already verified
working (hash/YARA/signature/ML scan_engine pipeline, behavior monitor,
usb/downloads monitors, quarantine, persistence/process scanners, startup
registration, notifier, memory, exceptions).

AppState is a QObject so pages can connect to its signals and react to
state changes (a monitor starting/stopping, a new finding, a toast) without
polling.
"""

import ctypes
import os

from PySide6.QtCore import QObject, Signal

from devadara import scan_log
from devadara.behavior_monitor import kill_process, resume_process, start_monitoring, suspend_process
from devadara.downloads_monitor import start_monitoring_downloads
from devadara.drive_scanner import walk_and_scan
from devadara.exceptions import add_exception, load_exceptions, remove_exception
from devadara.hash_scanner import compute_sha256
from devadara.memory import forget_threat, get_combined_known_bad_hashes, remember_threat
from devadara.ml_scanner import load_model_and_features
from devadara.notifier import notify
from devadara.persistence_scanner import evaluate_persistence_entries, list_persistence_entries
from devadara.process_scanner import evaluate_suspicious_processes, list_suspicious_processes
from devadara.quarantine import (
    delete_permanently as quarantine_delete_permanently,
    list_quarantined,
    quarantine_file,
    restore_file,
)
from devadara.scan_engine import evaluate_file
from devadara.signature_scanner import load_trusted_publishers
from devadara.startup_registration import add_to_startup, is_in_startup, remove_from_startup
from devadara.usb_monitor import list_removable_drives, start_usb_monitoring

from devadara_gui.services import activity_log
from devadara_gui.services.config_store import ConfigStore
from devadara_gui.services.realtime_scan import RealtimeScanRequest

DOWNLOADS_FOLDER = os.path.join(os.path.expanduser("~"), "Downloads")
DESKTOP_FOLDER = os.path.join(os.path.expanduser("~"), "Desktop")
DOCUMENTS_FOLDER = os.path.join(os.path.expanduser("~"), "Documents")
TEMP_FOLDER = os.environ.get("TEMP") or os.environ.get("TMP") or r"C:\Windows\Temp"

OPEN_FINDING_TIERS = {"known_bad", "malware", "suspicious"}


def _fixed_drive_roots():
    import psutil
    roots = []
    for partition in psutil.disk_partitions(all=False):
        opts = partition.opts.split(",")
        if "fixed" in opts:
            roots.append(partition.mountpoint)
    return roots


def _volume_label(root):
    # ctypes, not pywin32 - this project has no pywin32 dependency, and
    # GetVolumeInformationW is a plain kernel32 export any CPython build
    # on Windows can call directly.
    buf = ctypes.create_unicode_buffer(261)
    try:
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root), buf, ctypes.sizeof(buf), None, None, None, None, 0
        )
    except OSError:
        return None
    return buf.value if ok and buf.value else None


def _drive_display_label(root):
    letter = root.rstrip("\\/")
    label = _volume_label(root)
    if not label:
        system_drive = os.environ.get("SystemDrive", "C:")
        label = "Local Disk" if letter.upper() == system_drive.upper() else "New Volume"
    return f"{label} ({letter})"


class AppState(QObject):
    protection_changed = Signal()
    findings_changed = Signal()
    quarantine_changed = Signal()
    activity_changed = Signal()
    toast_requested = Signal(str, str)
    realtime_scan_requested = Signal(object)  # RealtimeScanRequest - see services/realtime_scan.py

    def __init__(self):
        super().__init__()
        self.config = ConfigStore()

        self.known_bad_hashes = get_combined_known_bad_hashes()
        self.trusted_publishers = load_trusted_publishers()
        self.model, self.feature_columns = load_model_and_features()

        self._behavior_observer = None
        self._downloads_observer = None
        self._usb_monitor = None

        self._apply_monitor_state_from_config()

    # ------------------------------------------------------------------
    # Cache refresh
    # ------------------------------------------------------------------
    def refresh_known_bad_hashes(self):
        self.known_bad_hashes = get_combined_known_bad_hashes()

    # ------------------------------------------------------------------
    # Real-time protection / module toggles
    # ------------------------------------------------------------------
    def _apply_monitor_state_from_config(self):
        master_on = self.config.get("realtime_protection_enabled", True)
        if master_on and self.config.get("behavior_monitoring_enabled", True):
            self._start_behavior_monitor()
        if master_on and self.config.get("downloads_autoscan_enabled", True):
            self._start_downloads_monitor()
        if master_on and self.config.get("usb_autoscan_enabled", True):
            self._start_usb_monitor()

    def is_realtime_protection_enabled(self):
        return bool(self.config.get("realtime_protection_enabled", True))

    def is_module_enabled(self, key):
        return bool(self.config.get(f"{key}_enabled", True))

    def is_module_active(self, key):
        """Whether the monitor is actually running right now."""
        return {
            "behavior_monitoring": self._behavior_observer is not None,
            "downloads_autoscan": self._downloads_observer is not None,
            "usb_autoscan": self._usb_monitor is not None,
        }.get(key, False)

    def set_realtime_protection(self, enabled):
        self.config.set("realtime_protection_enabled", enabled)
        if enabled:
            self._apply_monitor_state_from_config()
        else:
            self._stop_behavior_monitor()
            self._stop_downloads_monitor()
            self._stop_usb_monitor()
        if self.config.get("notify_protection_status", True):
            if enabled:
                self.toast_requested.emit("Protection turned on", "Real-time protection is now active.")
            else:
                self.toast_requested.emit(
                    "Real-time protection turned off",
                    "Your PC is not actively monitored.",
                )
        activity_log.add_event(
            "protection_changed",
            "Real-time protection enabled" if enabled else "Real-time protection disabled",
        )
        self.activity_changed.emit()
        self.protection_changed.emit()

    def set_module_enabled(self, key, enabled):
        self.config.set(f"{key}_enabled", enabled)
        if self.is_realtime_protection_enabled():
            if enabled:
                {"behavior_monitoring": self._start_behavior_monitor,
                 "downloads_autoscan": self._start_downloads_monitor,
                 "usb_autoscan": self._start_usb_monitor}[key]()
            else:
                {"behavior_monitoring": self._stop_behavior_monitor,
                 "downloads_autoscan": self._stop_downloads_monitor,
                 "usb_autoscan": self._stop_usb_monitor}[key]()
        self.protection_changed.emit()

    def _start_behavior_monitor(self):
        if self._behavior_observer is not None or not os.path.isdir(DOWNLOADS_FOLDER):
            return
        self._behavior_observer = start_monitoring(DOWNLOADS_FOLDER, self._on_behavior_alert)

    def _stop_behavior_monitor(self):
        if self._behavior_observer is None:
            return
        self._behavior_observer.stop()
        self._behavior_observer.join()
        self._behavior_observer = None

    def _start_downloads_monitor(self):
        if self._downloads_observer is not None or not os.path.isdir(DOWNLOADS_FOLDER):
            return
        self._downloads_observer = start_monitoring_downloads(DOWNLOADS_FOLDER, self._on_new_download)

    def _stop_downloads_monitor(self):
        if self._downloads_observer is None:
            return
        self._downloads_observer.stop()
        self._downloads_observer.join()
        self._downloads_observer = None

    def _start_usb_monitor(self):
        if self._usb_monitor is not None:
            return
        self._usb_monitor = start_usb_monitoring(self._on_drive_connected)

    def _stop_usb_monitor(self):
        if self._usb_monitor is None:
            return
        self._usb_monitor.stop()
        self._usb_monitor.join()
        self._usb_monitor = None

    def shutdown(self):
        self._stop_behavior_monitor()
        self._stop_downloads_monitor()
        self._stop_usb_monitor()

    # -- monitor callbacks (fire on background threads - only touch
    #    thread-safe things here: scan_log/activity_log/quarantine are all
    #    plain file I/O with atomic writes; Qt signal emission across
    #    threads is safe via Qt's queued-connection default) -------------
    def _on_new_download(self, file_path):
        # Surfaced live through RealTimeScanPopup (see
        # devadara_gui/services/realtime_scan.py) instead of a toast now -
        # the popup shows real progress and lets the user Stop/Review, which
        # a toast never could. The actual scan is still the exact same
        # scan_engine.evaluate_file() pipeline, just wrapped as a job for a
        # StoppableWorker so it can report progress and be cancelled.
        def job(should_stop, report_progress):
            return evaluate_file(
                file_path, self.known_bad_hashes, self.model, self.feature_columns, self.trusted_publishers,
                should_stop=should_stop, report_progress=report_progress,
            )

        def on_result(result):
            self._log_scan_findings([result], "downloads_watch")
            self.findings_changed.emit()
            return {
                "is_threat": result.get("tier") in OPEN_FINDING_TIERS,
                "cancelled": result.get("cancelled", False),
            }

        self.realtime_scan_requested.emit(RealtimeScanRequest(
            kind="downloads",
            target_label=os.path.join("Downloads", os.path.basename(file_path)),
            job=job,
            on_result=on_result,
            review_target=file_path,
        ))

    def _on_drive_connected(self, drive_path):
        # Same real devadara.drive_scanner.walk_and_scan pipeline the Scan
        # page's manual USB Scan uses (self.usb_scan_job already builds the
        # exact right job/precount/progress-cadence for it) - only the
        # progress shape is adapted here, to the flat {"percent", "detail"}
        # shape RealTimeScanPopup expects from any real-time job.
        inner_job = self.usb_scan_job(drive_path)

        def job(should_stop, report_progress):
            def adapt_progress(info):
                total = info.get("total_files")
                scanned = info.get("files_scanned", 0)
                percent = int(scanned / total * 100) if total else 0
                # Deliberately NOT forwarding info["current_path"] as
                # "detail" here: the popup's target line is meant to stay a
                # stable "USB Drive (E:)" identifier throughout the scan
                # (see the module's UI spec), not flicker through dozens of
                # individual file names per second as the drive walk visits
                # them - only the percentage/progress bar should move.
                report_progress({"percent": percent})

            return inner_job(should_stop, adapt_progress)

        def on_result(outcome):
            findings = outcome["known_bad_findings"] + outcome["to_review"]
            self._log_scan_findings(findings, "usb_watch")
            activity_log.add_event("usb_scan_completed", f"USB drive scanned: {drive_path}",
                                    f"{outcome['files_scanned']} file(s) scanned")
            self.findings_changed.emit()
            self.activity_changed.emit()
            return {
                "is_threat": bool(findings),
                "cancelled": outcome.get("interrupted", False),
            }

        self.realtime_scan_requested.emit(RealtimeScanRequest(
            kind="usb",
            target_label=f"USB Drive ({drive_path})",
            job=job,
            on_result=on_result,
            review_target=None,
        ))

    def _on_behavior_alert(self, alert_info):
        suspects = [f"PID {s['pid']} ({s['name']})" for s in alert_info["suspect_processes"]]
        scan_log.append_finding(
            source="behavior_alert",
            tier="behavior_alert",
            file_path=alert_info["folder"],
            event_count=alert_info["event_count"],
            window_seconds=alert_info["window_seconds"],
            sample_files=alert_info["sample_files"],
            suspect_processes=suspects,
        )
        activity_log.add_event(
            "behavior_alert",
            "Ransomware-like activity detected",
            f"Unusual burst of file changes in '{alert_info['folder']}'.",
        )
        if self.config.get("notify_threat_detected", True):
            self.toast_requested.emit(
                "Ransomware-like activity detected",
                f"Unusual burst of file changes in '{alert_info['folder']}'.",
            )
        self.activity_changed.emit()

    # ------------------------------------------------------------------
    # Windows startup
    # ------------------------------------------------------------------
    def is_startup_enabled(self):
        return is_in_startup()

    def set_startup_enabled(self, enabled):
        if enabled:
            add_to_startup()
        else:
            remove_from_startup()
        activity_log.add_event(
            "protection_changed",
            "Windows startup launch enabled" if enabled else "Windows startup launch disabled",
        )
        self.activity_changed.emit()
        self.protection_changed.emit()

    # ------------------------------------------------------------------
    # Findings (scan_log-backed "Detected Threats")
    # ------------------------------------------------------------------
    def _log_scan_findings(self, results, source):
        for result in results:
            if result["tier"] not in OPEN_FINDING_TIERS:
                continue
            ml = result.get("ml") or {}
            signature = result.get("signature") or {}
            scan_log.append_finding(
                source=source,
                tier=result["tier"],
                file_path=result["file_path"],
                file_hash=result.get("hash"),
                threat_name=result.get("threat_name"),
                confidence=ml.get("confidence"),
                publisher=signature.get("publisher"),
                yara=[m["rule"] for m in result.get("yara") or []],
                downgraded_from_malware=result.get("downgraded_from_malware", False),
            )

    def list_detected_threats(self):
        findings = [f for f in scan_log.read_findings() if f.get("tier") in OPEN_FINDING_TIERS]
        findings.sort(key=lambda f: f.get("timestamp", ""), reverse=True)
        return findings

    def threats_detected_count(self):
        return len(self.list_detected_threats())

    def _threat_label(self, finding):
        details = finding.get("details") or {}
        return details.get("threat_name") or os.path.basename(finding.get("file_path") or "unknown")

    def quarantine_finding(self, finding_id):
        finding = next((f for f in scan_log.read_findings() if f["id"] == finding_id), None)
        if finding is None:
            return False
        file_path = finding.get("file_path")
        if finding["tier"] != "known_bad" and file_path and finding.get("hash"):
            remember_threat(finding["hash"], self._threat_label(finding), source="user_confirmed")
            self.refresh_known_bad_hashes()
        entry_id = None
        if file_path and os.path.exists(file_path):
            entry_id = quarantine_file(
                file_path, file_hash=finding.get("hash"), threat_name=self._threat_label(finding),
                tier=finding["tier"], source="gui",
            )
        scan_log.remove_findings([finding_id])
        activity_log.add_event("threat_quarantined", f"Quarantined {os.path.basename(file_path or '')}")
        if self.config.get("notify_threat_detected", True):
            self.toast_requested.emit("Threat quarantined", os.path.basename(file_path or ""))
        self.findings_changed.emit()
        self.quarantine_changed.emit()
        self.activity_changed.emit()
        return entry_id is not None

    def delete_finding(self, finding_id):
        finding = next((f for f in scan_log.read_findings() if f["id"] == finding_id), None)
        if finding is None:
            return False
        file_path = finding.get("file_path")
        if finding["tier"] != "known_bad" and file_path and finding.get("hash"):
            remember_threat(finding["hash"], self._threat_label(finding), source="user_confirmed")
            self.refresh_known_bad_hashes()
        deleted = False
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
                deleted = True
            except OSError:
                deleted = False
        scan_log.remove_findings([finding_id])
        activity_log.add_event("threat_deleted", f"Deleted {os.path.basename(file_path or '')}")
        self.findings_changed.emit()
        self.activity_changed.emit()
        return deleted

    def ignore_finding(self, finding_id):
        finding = next((f for f in scan_log.read_findings() if f["id"] == finding_id), None)
        if finding is None:
            return False
        file_path = finding.get("file_path")
        if file_path:
            add_exception(file_path)
        scan_log.remove_findings([finding_id])
        activity_log.add_event("threat_ignored", f"Added exception for {os.path.basename(file_path or '')}")
        self.findings_changed.emit()
        self.activity_changed.emit()
        return True

    # ------------------------------------------------------------------
    # Quarantine
    # ------------------------------------------------------------------
    def list_quarantine(self):
        entries = list_quarantined()
        entries.sort(key=lambda e: e.get("quarantined_at", ""), reverse=True)
        return entries

    def restore_quarantine(self, entry_id):
        ok = restore_file(entry_id)
        if ok:
            activity_log.add_event("threat_restored", "Restored a quarantined file")
            self.activity_changed.emit()
            self.quarantine_changed.emit()
        return ok

    def delete_quarantine_permanently(self, entry_id):
        ok = quarantine_delete_permanently(entry_id)
        if ok:
            activity_log.add_event("threat_deleted", "Permanently deleted a quarantined file")
            self.activity_changed.emit()
            self.quarantine_changed.emit()
        return ok

    # ------------------------------------------------------------------
    # Exceptions
    # ------------------------------------------------------------------
    def list_exceptions(self):
        return load_exceptions()

    def add_exception_path(self, path):
        add_exception(path)

    def remove_exception_path(self, path):
        return remove_exception(path)

    # ------------------------------------------------------------------
    # Scans - each returns a plain function suitable for StoppableWorker:
    # func(should_stop, report_progress) -> outcome dict
    # ------------------------------------------------------------------
    def list_fixed_drive_items(self):
        """
        Computer Drive's tree children (devadara_gui/pages/scan_tree.py) -
        every real fixed drive on this machine, never hardcoded. id is
        stable-ish for one process lifetime (sorted by mountpoint), which
        is all the tree widget needs it for.
        """
        roots = sorted(_fixed_drive_roots())
        return [
            {"id": f"drive_{i}", "path": root, "label": _drive_display_label(root)}
            for i, root in enumerate(roots)
        ]

    def _multi_root_scan_job(self, roots, quick, progress_every_n_files, precount):
        """
        Walks several root paths back-to-back as one logical scan, with
        cumulative (not per-root-reset) progress numbers and elapsed time -
        each root individually still goes through the real,
        already-verified devadara.drive_scanner.walk_and_scan pipeline.

        precount: do a fast file-count pass first so the Scan page can show
        a real percentage instead of an indeterminate bar. Only worth it
        for bounded locations (Quick/Downloads/USB scans), never Full Scan.
        """
        def job(should_stop, report_progress):
            import time
            start_time = time.time()

            total_files = None
            if precount:
                total_files = 0
                for root in roots:
                    for _folder, _subfolders, file_names in os.walk(root):
                        total_files += len(file_names)
                        if should_stop():
                            break
                    if should_stop():
                        break
                report_progress({
                    "files_scanned": 0, "known_bad_count": 0, "flagged_count": 0,
                    "elapsed_seconds": time.time() - start_time, "current_path": None,
                    "current_tier": None, "hidden_count": 0, "total_files": total_files,
                })

            offsets = {"files": 0, "known": 0, "flagged": 0, "hidden": 0}

            def make_on_progress():
                def on_progress(files_scanned, known_count, flagged_count, _elapsed, current_path,
                                 current_tier, hidden_count):
                    report_progress({
                        "files_scanned": offsets["files"] + files_scanned,
                        "known_bad_count": offsets["known"] + known_count,
                        "flagged_count": offsets["flagged"] + flagged_count,
                        "elapsed_seconds": time.time() - start_time,
                        "current_path": current_path,
                        "current_tier": current_tier,
                        "hidden_count": offsets["hidden"] + hidden_count,
                        "total_files": total_files,
                    })
                return on_progress

            outcomes = []
            for root in roots:
                if should_stop():
                    break
                outcome = walk_and_scan(
                    root, quick, self.known_bad_hashes, self.model, self.feature_columns, self.trusted_publishers,
                    on_progress=make_on_progress(), should_stop=should_stop,
                    progress_every_n_files=progress_every_n_files,
                )
                outcomes.append(outcome)
                offsets["files"] += outcome["files_scanned"]
                offsets["known"] += len(outcome["known_bad_findings"])
                offsets["flagged"] += len(outcome["to_review"])
                offsets["hidden"] += len(outcome["hidden_files"])

            combined = _merge_outcomes(outcomes) if outcomes else _empty_outcome()
            combined["elapsed_seconds"] = time.time() - start_time
            return combined

        return job

    def usb_scan_job(self, drive_path):
        return self._multi_root_scan_job([drive_path], quick=False, progress_every_n_files=20, precount=True)

    def connected_removable_drives(self):
        return sorted(list_removable_drives())

    # ------------------------------------------------------------------
    # Scan page's checkbox tree -> one combined scan job (Section: Scan
    # page redesign around assets/scan_page_reference.html). Computer
    # Drive/Common Locations/USB Drive all go through the same real
    # devadara.drive_scanner.walk_and_scan pipeline as before; System Area
    # and Deep Inspection run the exact same backend calls the removed
    # Persistence Check / Process Scan / Memory Scan tools used
    # (list_persistence_entries/evaluate_persistence_entries,
    # list_suspicious_processes/evaluate_suspicious_processes) - only
    # inlined here instead of behind their own job-wrapper methods, since
    # this is now their only caller.
    # ------------------------------------------------------------------
    def common_location_paths(self):
        """id -> real folder path, for the tree's Common Locations children."""
        return {
            "dl": DOWNLOADS_FOLDER, "desktop": DESKTOP_FOLDER,
            "docs": DOCUMENTS_FOLDER, "temp": TEMP_FOLDER,
        }

    def custom_scan_job(self, drive_paths, location_paths, system_area, deep_inspection, usb_path):
        """
        drive_paths: [str, ...] - Computer Drive children checked (hash+YARA
            only, same as the old Full Scan's per-drive pipeline - see
            drive_scanner.py's module docstring on Quick vs Full mode).
        location_paths: [str, ...] - Common Locations children checked (full
            hash+YARA+signature+ML pipeline, same as the old Quick Scan).
        system_area: bool - any System Area group/child checked.
        deep_inspection: bool - any Deep Inspection group/child checked.
        usb_path: str or None - a connected drive to scan if USB Drive is
            checked, else None (nothing to scan - the Scan page is
            responsible for not calling this with a phantom USB phase).

        Returns a job(should_stop, report_progress) -> outcome dict, shaped
        like _multi_root_scan_job's outcome plus two extra keys:
        "persistence_entries" and "process_entries" (each [] when that
        phase didn't run).

        report_progress payloads always carry {"phase", "phase_index",
        "phase_count", "elapsed_seconds", "files_scanned", "known_bad_count",
        "flagged_count", "hidden_count", "current_path", "current_tier"} -
        known_bad_count/flagged_count/hidden_count are running totals across
        every phase (file scans AND System Area/Deep Inspection findings
        folded in as they're found, not just at that phase's end), current_
        path/current_tier are the single most-recently-checked item's own
        identity/result (a file's path, or a persistence entry's name/
        location) and scan_engine tier - a live per-item activity log can
        read these two directly, on every kind of payload. Each payload
        also carries one of:
          - files phase:    "kind": "files", "total_files"
          - system area:    "kind": "entries", "checked", "total"
          - deep inspection: "kind": "indeterminate"
        """
        def job(should_stop, report_progress):
            import time
            start_time = time.time()

            combined = _empty_outcome()
            combined["persistence_entries"] = []
            combined["process_entries"] = []
            running = {"files": 0, "known": 0, "flagged": 0, "hidden": 0}

            file_phases = []
            if drive_paths:
                file_phases.append(("Computer Drive", drive_paths, True, 500, False))
            if location_paths:
                file_phases.append(("Common Locations", location_paths, False, 20, True))
            if usb_path:
                file_phases.append(("USB Drive", [usb_path], False, 20, True))

            phase_count = len(file_phases) + (1 if system_area else 0) + (1 if deep_inspection else 0)
            phase_index = 0

            def base_payload(phase_label):
                return {
                    "phase": phase_label, "phase_index": phase_index, "phase_count": phase_count,
                    "elapsed_seconds": time.time() - start_time,
                    "files_scanned": running["files"], "known_bad_count": running["known"],
                    "flagged_count": running["flagged"], "hidden_count": running["hidden"],
                    "current_path": None, "current_tier": None,
                }

            def _percent(local_done, local_total):
                if not local_total:
                    return None
                return max(0, min(100, int(local_done / local_total * 100)))

            for phase_label, roots, quick, progress_every_n_files, precount in file_phases:
                if should_stop():
                    break
                phase_index += 1
                phase_local = {"files": 0}

                total_files = None
                if precount:
                    total_files = 0
                    for root in roots:
                        for _folder, _subfolders, file_names in os.walk(root):
                            total_files += len(file_names)
                            if should_stop():
                                break
                        if should_stop():
                            break
                payload = base_payload(phase_label)
                payload.update({
                    "kind": "files", "total_files": total_files,
                    "percent": _percent(0, total_files),
                })
                report_progress(payload)

                def on_progress(files_scanned, known_count, flagged_count, _elapsed, current_path,
                                 current_tier, hidden_count,
                                 _label=phase_label, _total=total_files, _phase_local=phase_local):
                    payload = base_payload(_label)
                    payload.update({
                        "kind": "files", "current_path": current_path, "current_tier": current_tier,
                        "total_files": _total,
                        "percent": _percent(_phase_local["files"] + files_scanned, _total),
                        "files_scanned": running["files"] + files_scanned,
                        "known_bad_count": running["known"] + known_count,
                        "flagged_count": running["flagged"] + flagged_count,
                        "hidden_count": running["hidden"] + hidden_count,
                    })
                    report_progress(payload)

                for root in roots:
                    if should_stop():
                        break
                    outcome = walk_and_scan(
                        root, quick, self.known_bad_hashes, self.model, self.feature_columns,
                        self.trusted_publishers, on_progress=on_progress, should_stop=should_stop,
                        progress_every_n_files=progress_every_n_files,
                    )
                    combined["known_bad_findings"].extend(outcome["known_bad_findings"])
                    combined["to_review"].extend(outcome["to_review"])
                    combined["trusted_signed_count"] += outcome["trusted_signed_count"]
                    combined["clean_count"] += outcome["clean_count"]
                    combined["hidden_files"].extend(outcome["hidden_files"])
                    combined["files_scanned"] += outcome["files_scanned"]
                    combined["interrupted"] = combined["interrupted"] or outcome["interrupted"]
                    running["files"] += outcome["files_scanned"]
                    running["known"] += len(outcome["known_bad_findings"])
                    running["flagged"] += len(outcome["to_review"])
                    running["hidden"] += len(outcome["hidden_files"])
                    phase_local["files"] += outcome["files_scanned"]

            if system_area and not should_stop():
                phase_index += 1
                entries = list_persistence_entries()
                total = len(entries)

                def on_persistence_progress(checked, checked_total, entry=None, _label="System Area"):
                    entry_label = (entry.get("name") or entry.get("location")) if entry else None
                    scan = entry.get("scan") if entry else None
                    tier = scan.get("tier") if scan else None
                    # Fold this entry's own tier into the same running
                    # known/flagged tallies the file-scan phases use, so
                    # "Threats detected"/"Suspicious items" (and Fix All's
                    # count) reflect System Area findings live, not just
                    # once the whole phase finishes.
                    if tier == "known_bad":
                        running["known"] += 1
                    elif tier in ("malware", "suspicious"):
                        running["flagged"] += 1
                    payload = base_payload(_label)
                    payload.update({
                        "kind": "entries", "checked": checked, "total": checked_total,
                        "percent": _percent(checked, checked_total),
                        "current_path": entry_label,
                        "current_tier": tier,
                    })
                    report_progress(payload)

                on_persistence_progress(0, total)
                evaluate_persistence_entries(
                    entries, self.known_bad_hashes, self.model, self.feature_columns,
                    trusted_publishers=self.trusted_publishers, should_stop=should_stop,
                    report_progress=on_persistence_progress,
                )
                combined["persistence_entries"] = entries

            if deep_inspection and not should_stop():
                phase_index += 1
                payload = base_payload("Deep Inspection")
                payload["kind"] = "indeterminate"
                report_progress(payload)

                entries = list_suspicious_processes()
                evaluate_suspicious_processes(
                    entries, self.known_bad_hashes, self.model, self.feature_columns,
                    trusted_publishers=self.trusted_publishers, should_stop=should_stop,
                )
                combined["process_entries"] = entries
                # No per-process progress callback exists (see
                # process_scanner.py's own module docstring - this sweep is
                # fast enough not to need one) - fold the whole phase's
                # tally into the running counts in one shot instead, so
                # "Threats detected"/"Suspicious items" still reflect it
                # before the job returns.
                for proc_entry in entries:
                    proc_scan = proc_entry.get("scan")
                    proc_tier = proc_scan.get("tier") if proc_scan else None
                    if proc_tier == "known_bad":
                        running["known"] += 1
                    elif proc_tier in ("malware", "suspicious"):
                        running["flagged"] += 1
                if entries:
                    payload = base_payload("Deep Inspection")
                    payload["kind"] = "indeterminate"
                    report_progress(payload)

            combined["elapsed_seconds"] = time.time() - start_time
            return combined

        return job

    def finalize_scan(self, mode_label, outcome):
        findings = outcome["known_bad_findings"] + outcome["to_review"]
        self._log_scan_findings(findings, "gui_scan")
        threats = len(outcome["known_bad_findings"])
        suspicious = len(outcome["to_review"])
        # System Area / Deep Inspection phases (see custom_scan_job) don't
        # produce scan_log-shaped findings - they're not files on disk, and
        # (matching the old Persistence Check / Process Scan tools' own
        # read-only-display, no-quarantine-flow contract) aren't logged as
        # open threats here either. Their suspicious/threat counts still
        # belong in this run's summary, so they're tallied in separately.
        for entry in outcome.get("persistence_entries", []) + outcome.get("process_entries", []):
            scan = entry.get("scan")
            if scan is None:
                continue
            if scan.get("tier") == "known_bad":
                threats += 1
            elif scan.get("tier") in ("malware", "suspicious"):
                suspicious += 1
        summary = f"{threats} threat(s), {suspicious} suspicious item(s)" if (threats or suspicious) else "No threats found"
        self.config.set_many(
            last_scan_at=_now_iso(),
            last_scan_summary=f"{mode_label}: {summary}",
        )
        activity_log.add_event("scan_completed", f"{mode_label} completed", summary)
        if self.config.get("notify_scan_completed", True):
            self.toast_requested.emit(f"{mode_label} completed", summary)
        self.findings_changed.emit()
        self.activity_changed.emit()

    def last_scan_at(self):
        return self.config.get("last_scan_at")

    def suspend_pid(self, pid):
        ok = suspend_process(pid)
        if ok:
            activity_log.add_event("process_suspended", f"Suspended process {pid}")
            self.activity_changed.emit()
        return ok

    def resume_pid(self, pid):
        ok = resume_process(pid)
        if ok:
            activity_log.add_event("process_resumed", f"Resumed process {pid}")
            self.activity_changed.emit()
        return ok

    def kill_pid(self, pid):
        ok = kill_process(pid)
        if ok:
            activity_log.add_event("process_terminated", f"Terminated process {pid}")
            self.activity_changed.emit()
        return ok


def _empty_outcome():
    return {
        "known_bad_findings": [], "trusted_signed_count": 0, "clean_count": 0,
        "to_review": [], "hidden_files": [], "files_scanned": 0,
        "elapsed_seconds": 0.0, "interrupted": False,
    }


def _merge_outcomes(outcomes):
    merged = _empty_outcome()
    for outcome in outcomes:
        merged["known_bad_findings"].extend(outcome["known_bad_findings"])
        merged["trusted_signed_count"] += outcome["trusted_signed_count"]
        merged["clean_count"] += outcome["clean_count"]
        merged["to_review"].extend(outcome["to_review"])
        merged["hidden_files"].extend(outcome["hidden_files"])
        merged["files_scanned"] += outcome["files_scanned"]
        merged["elapsed_seconds"] += outcome["elapsed_seconds"]
        merged["interrupted"] = merged["interrupted"] or outcome["interrupted"]
    return merged


def _now_iso():
    from datetime import datetime
    return datetime.now().isoformat(timespec="seconds")
