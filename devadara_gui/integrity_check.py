"""
integrity_check.py

Runs devadara.self_integrity.check_install() - DEVADARA comparing its own
program files with its signed manifest - off the GUI thread, once shortly
after startup (MainWindow.start_background_init) and again whenever the
Dashboard's "Check now" is clicked.

It only hashes files (hashlib), so it's safe on a QThread here - unlike
loading the ML model or persistence_scanner.list_persistence_entries(),
which hang on a QThread on this machine (see scan_worker.py). The check
only reads: it never deletes, moves or quarantines anything, and
check_install() never raises - an ERROR result is shown instead.
"""

from datetime import datetime

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import QApplication

from devadara import self_integrity

# Waited for on quit, so the app never exits with the thread still running.
SHUTDOWN_WAIT_MS = 10_000


class _CheckWorker(QObject):
    done = Signal(dict)

    def run(self):
        try:
            result = self_integrity.check_install()
        except Exception as exc:  # check_install() never raises; belt and braces
            result = {"status": self_integrity.ERROR, "message": f"the check couldn't run: {exc}",
                      "checked": 0, "changed": [], "missing": [], "extra": [], "unreadable": [],
                      "checked_at": datetime.now().isoformat(timespec="seconds")}
        self.done.emit(result)


class IntegrityChecker(QObject):
    """One check at a time. started/finished are emitted on the GUI thread."""

    started = Signal()
    finished = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread = None
        self._worker = None
        self.last_result = None
        app = QApplication.instance()
        if app is not None:
            app.aboutToQuit.connect(self.shutdown)

    def is_running(self):
        return self._thread is not None

    def start(self):
        """Start a check unless one is already running. Returns True if started."""
        if self._thread is not None:
            return False
        self._thread = QThread(self)
        self._worker = _CheckWorker()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.done.connect(self._on_done)
        self._worker.done.connect(self._thread.quit)
        self._worker.done.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()
        self.started.emit()
        return True

    def _on_done(self, result):
        self._thread = None
        self._worker = None
        self.last_result = result
        self.finished.emit(result)

    def shutdown(self):
        """App quitting: let a running check finish (it only reads files)."""
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(SHUTDOWN_WAIT_MS)
