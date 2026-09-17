"""
workers.py

Every DEVADARA scan (Quick/Full/Downloads/USB/Persistence/Process/Memory)
runs on a QThread here, never on the UI thread (Section 32 of the design
spec: "The application must remain responsive... Do not perform long-running
operations directly on the main Qt UI thread"). Each worker exposes plain
Qt signals (progress/finished/error) so pages only ever touch widgets from
slot callbacks on the main thread - never from inside run().
"""

import threading
import traceback

from PySide6.QtCore import QThread, Signal


class CallableWorker(QThread):
    """
    Runs any zero-argument callable on a background thread. func should
    return a plain value (a dict, a list, ...) - emitted via `finished`.
    An exception is caught and emitted via `failed` instead of crashing the
    app; core backend calls already avoid raising for expected failure
    modes, so this is a last-resort safety net, not something callers
    should rely on for control flow.
    """

    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, func, parent=None):
        super().__init__(parent)
        self._func = func

    def run(self):
        try:
            result = self._func()
        except Exception:
            self.failed.emit(traceback.format_exc())
            return
        self.finished_ok.emit(result)


class StoppableWorker(QThread):
    """
    Same shape as CallableWorker, but hands the target function a
    should_stop() callable wired to a threading.Event - every long scan in
    devadara/ (drive_scanner.walk_and_scan, persistence_scanner.
    evaluate_persistence_entries, process_scanner.evaluate_suspicious_processes)
    already accepts this exact signature, so a page's Cancel button can stop
    a real scan mid-run rather than just hiding the progress UI while work
    keeps running underneath it.
    """

    progress = Signal(object)
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, func, parent=None):
        """func(should_stop, report_progress) -> result"""
        super().__init__(parent)
        self._func = func
        self._stop_event = threading.Event()

    def request_stop(self):
        self._stop_event.set()

    def _should_stop(self):
        return self._stop_event.is_set()

    def run(self):
        try:
            result = self._func(self._should_stop, self.progress.emit)
        except Exception:
            self.failed.emit(traceback.format_exc())
            return
        self.finished_ok.emit(result)
