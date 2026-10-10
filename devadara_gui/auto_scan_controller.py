"""
auto_scan_controller.py

Wraps devadara.downloads_monitor/devadara.usb_monitor's background
watchers for GUI use. Neither backend module has ever been imported by
devadara_gui/ before this - they're plain callback-based watchers whose
callbacks fire on their OWN background thread (watchdog's internal
observer thread, or the USB poller's own threading.Thread), never on the
Qt/GUI thread. This QObject is constructed on the GUI thread and never
moved to another one, so any signal emitted here - even though .emit() is
physically called from one of those background threads - is automatically
queued and delivered on the GUI thread by Qt (resolved by the *receiver's*
thread affinity, not the emitting thread), the same mechanism
ScanWorker's signals already rely on (see scan_worker.py's own module
docstring).

Loads the ML model once (load_model_and_features() is confirmed to hang
if ever called from a QThread - this class only ever runs on the GUI
thread, so that's not a risk here, but it's still a real ~3-7s blocking
call, hence load_model() is deferred until just after the main window
has been shown and painted - see MainWindow.start_background_init()). known_bad_hashes/trusted_publishers are NOT cached
here: ScanWorker.run() already reloads those fresh every scan (a cheap
local JSON load, unlike the model), so there's nothing to deduplicate.
"""

import os

from PySide6.QtCore import QObject, Signal

from devadara.downloads_monitor import start_monitoring_downloads
from devadara.ml_scanner import load_model_and_features
from devadara.usb_monitor import start_usb_monitoring

from devadara_gui.config_store import ConfigStore

DOWNLOADS_FOLDER = os.path.join(os.path.expanduser("~"), "Downloads")


class AutoScanController(QObject):
    downloads_file_detected = Signal(str)
    usb_drive_detected = Signal(str)
    # True while at least one watcher is actually running. First emitted
    # at the end of load_model() (the sidebar shows "STARTING..." until
    # then, never "ACTIVE"), then on every watcher start/stop.
    realtime_state_changed = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.config_store = ConfigStore()
        self.model = None
        self.feature_columns = None
        self._downloads_observer = None
        self._usb_monitor = None

    def load_model(self):
        """Must run on the GUI thread - see module docstring. Starts
        whichever watcher(s) are enabled per persisted config once the
        model is ready, so a detection can never race an unloaded model."""
        if self.model is not None:
            return
        self.model, self.feature_columns = load_model_and_features()
        self._apply_startup_config()
        self._emit_realtime_state()

    def _apply_startup_config(self):
        if self.config_store.get("downloads_autoscan_enabled", True):
            self.start_downloads_watch()
        if self.config_store.get("usb_autoscan_enabled", True):
            self.start_usb_watch()

    def is_realtime_active(self):
        return self._downloads_observer is not None or self._usb_monitor is not None

    def _emit_realtime_state(self):
        self.realtime_state_changed.emit(self.is_realtime_active())

    def start_downloads_watch(self):
        if self._downloads_observer is not None:
            return
        if not os.path.isdir(DOWNLOADS_FOLDER):
            print(f"[WARNING] Downloads folder not found, skipping auto-scan watch: {DOWNLOADS_FOLDER}")
            return
        self._downloads_observer = start_monitoring_downloads(DOWNLOADS_FOLDER, self._handle_new_download)
        self._emit_realtime_state()

    def stop_downloads_watch(self):
        if self._downloads_observer is None:
            return
        observer, self._downloads_observer = self._downloads_observer, None
        observer.stop()
        observer.join()
        self._emit_realtime_state()

    def start_usb_watch(self):
        if self._usb_monitor is not None:
            return
        self._usb_monitor = start_usb_monitoring(self._handle_drive_connected)
        self._emit_realtime_state()

    def stop_usb_watch(self):
        if self._usb_monitor is None:
            return
        monitor, self._usb_monitor = self._usb_monitor, None
        monitor.stop()
        monitor.join()
        self._emit_realtime_state()

    # ─── watcher callbacks - fire on a background thread, do minimal work ───

    def _handle_new_download(self, file_path):
        try:
            self.downloads_file_detected.emit(file_path)
        except Exception:
            pass

    def _handle_drive_connected(self, drive_path):
        try:
            self.usb_drive_detected.emit(drive_path)
        except Exception:
            pass
