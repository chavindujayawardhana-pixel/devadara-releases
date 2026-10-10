"""
results_store.py

What the Results page shows from the LAST MANUAL SCAN - kept in memory
only (owner decision: nothing new is saved to disk; results go stale
quickly anyway, and a rescan rebuilds them). Filled from
ScanWorker.results via ScanPage.manual_scan_results; auto-scans don't
replace it (their findings are in data/scan_log.jsonl, which the Results
page reads directly, as it does the quarantine index).

Rows are removed here once an action on the Results page has dealt with
them (quarantined, ignored, unhidden ...), so the page never offers the
same action twice on something that's already handled.
"""

import os
from datetime import datetime

from PySide6.QtCore import QObject, Signal


def _same_path(a, b):
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


class ResultsStore(QObject):
    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanned_at = None
        self.flagged = []
        self.hidden = []
        self.startup = []
        self.processes = []

    def set_last_scan(self, results):
        self.scanned_at = datetime.now()
        self.flagged = list(results.get("flagged", []))
        self.hidden = list(results.get("hidden", []))
        self.startup = list(results.get("startup", []))
        self.processes = list(results.get("processes", []))
        self.changed.emit()

    def remove_flagged(self, file_path):
        self.flagged = [r for r in self.flagged if not _same_path(r["file_path"], file_path)]
        self.changed.emit()

    def remove_hidden(self, path):
        self.hidden = [p for p in self.hidden if not _same_path(p, path)]
        self.changed.emit()
