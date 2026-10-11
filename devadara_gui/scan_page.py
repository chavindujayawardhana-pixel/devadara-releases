"""
scan_page.py

Phase 3a: the Scan page's mode radios and checkbox tree - selection UI and
its logic only. No backend scan connection yet (Phase 3b); the Scan button
is a no-op for this phase.

Drive detection: devadara.usb_monitor.list_removable_drives() is a real,
already-used backend function - imported and called directly for USB
drives, including for live hot-plug polling (see _poll_usb_drives below).
No existing devadara/ function returns fixed-only drives (drive_scanner.py
only walks a given root; full_drive_scan_cli.py's _list_drives() is a
private CLI helper mixing fixed+removable) - list_fixed_drives() below is
new, but read-only and backend-untouched, using the same psutil approach
list_removable_drives() already does with the opposite opts filter.
"""

import os
from collections import deque, namedtuple

import psutil
from PySide6.QtCore import QSize, QThread, QTimer, Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QAbstractItemView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from devadara import scan_log
from devadara.ml_scanner import load_model_and_features
from devadara.usb_monitor import list_removable_drives

from devadara_gui import scan_history, theme
from devadara_gui.auto_scan_controller import DOWNLOADS_FOLDER
from devadara_gui.components import (
    Button, Card, ElidedLabel, PageHeader, RadioItem, StatCard, StatusCircle, TreeRow,
)
from devadara_gui.mini_form_popup import MiniFormPopup
from devadara_gui.results_page import reason_text
from devadara_gui.scan_worker import ScanWorker, format_elapsed, gather_persistence_entries

FIXED_PREFIX = "fixed:"
USB_PREFIX = "usb:"

MODES = ["Quick Scan", "Full Scan", "Scan Downloads", "Scan USB"]

# One scan request, manual or auto-triggered - built by _resolve_scan_plan()
# (manual) or _on_downloads_file_detected()/_on_usb_drive_detected() (auto),
# and either started immediately or queued by _enqueue_or_start() if a scan
# is already running. is_auto/auto_label drive which UI path _start_scan()/
# _on_scan_finished() take - see their own docstrings. log_source, when set
# ("downloads_watch"/"usb_watch"/"boot_sweep"), writes the request's
# findings to data/scan_log.jsonl; manual scans leave it None and aren't
# logged (the Dashboard's stat cards count unattended findings only).
# scan_kind, when set, is what scan_history records once the scan FINISHES
# (see _record_scan_history): the manual mode, "Custom scan", or "Startup
# scan"; per-file Downloads/USB auto-scans leave it None.
_ScanRequest = namedtuple("_ScanRequest", [
    "targets", "system_area_flags", "quick", "model", "feature_columns",
    "persistence_entries", "is_auto", "auto_label", "log_source", "scan_kind",
], defaults=(None, None))

# The sign-in startup sweep of Downloads (see ScanPage.start_boot_sweep).
# Full mode, like startup_protect.py's original boot sweep: Quick would
# skip every non-executable, so YARA would never see a malicious script,
# document or ransom note.
BOOT_SWEEP_QUICK = False

# A reactive single-file/single-drive auto-scan trigger has nothing to do
# with registry/services/startup/process state - only the file or drive
# itself is being checked.
_NO_SYSTEM_AREA_FLAGS = {"registry": False, "startup": False, "services": False, "memory_processes": False}

SYSTEM_AREA_CHILD_KEYS = ["memory_processes", "services", "registry", "startup"]
SYSTEM_AREA_LABELS = {
    "memory_processes": "Memory Processes",
    "services": "Services",
    "registry": "Registry Area",
    "startup": "Start-Up Area",
}

USB_POLL_INTERVAL_MS = 500


def list_fixed_drives():
    """Real fixed drive mountpoints (e.g. ["C:\\", "D:\\"]), sorted. See
    module docstring for why this is new (no reusable devadara/ function)
    but backend-untouched (same psutil.disk_partitions() approach
    list_removable_drives() already uses)."""
    drives = []
    for partition in psutil.disk_partitions(all=False):
        if "fixed" in partition.opts.split(","):
            drives.append(partition.mountpoint)
    return sorted(drives)


def _drive_label(mountpoint, is_usb):
    letter = mountpoint.rstrip("\\")
    if is_usb:
        return f"USB Drive ({letter})"
    if letter.upper() == "C:":
        return f"Local Disk ({letter})"
    return f"Drive ({letter})"


class ScanPage(QWidget):
    # True when a scan starts from idle; False only once the last one ends
    # with nothing left queued - a queued follow-up scan emits nothing, so
    # listeners (the orbit-animated sidebar logo and tray icon) never
    # flicker between back-to-back scans. Covers manual and auto-triggered
    # scans alike, and stopped ones (ScanWorker always emits finished).
    scan_active_changed = Signal(bool)
    # (auto_label, findings) - an auto-triggered scan (Downloads/USB/boot
    # sweep) finished with at least one flagged file; MainWindow turns it
    # into a tray notification when the window is hidden.
    auto_scan_flagged = Signal(str, list)
    # A finished scan was recorded in scan_history (last scan / last full
    # scan) - MainWindow refreshes the Dashboard and sidebar.
    scan_recorded = Signal()
    # ScanWorker.results of a finished MANUAL scan (stopped ones too) - the
    # Results page's in-memory "last scan" (see results_store.py).
    manual_scan_results = Signal(dict)
    # (scan_kind, checked, threats, flagged_announced) - a scan with a
    # scan_kind (manual or the startup sweep, never a per-file Downloads/USB
    # auto-scan) FINISHED (not stopped). flagged_announced: auto_scan_flagged
    # already went out for it. MainWindow turns it into the "scan finished"
    # tray message (Settings › Notifications).
    scan_completed = Signal(str, int, int, bool)

    def __init__(self, navigate=None, main_window=None, controller=None, parent=None):
        """navigate: callable(index) - switches both the content stack and
        the sidebar's active nav item (see MainWindow.navigate_to), used by
        the Fix All buttons to reach the Results page.
        main_window: the app's MainWindow - hidden/restored around the
        Mini-Form popup when the user minimizes/opens Details on an active
        scan (see _on_minimize_requested/_on_details_requested).
        controller: the app's AutoScanController - its
        downloads_file_detected/usb_drive_detected signals feed
        _on_downloads_file_detected/_on_usb_drive_detected, which enqueue
        or start an auto-triggered scan the same way a manual Start click
        does (see _enqueue_or_start/_start_scan)."""
        super().__init__(parent)
        self._navigate = navigate
        self._main_window = main_window
        self._controller = controller

        self._rows = {}  # key -> TreeRow
        self._system_area_keys = set()
        self._current_mode = MODES[0]
        self._fixed_drives = []
        self._usb_drives = []
        self._known_usb = set()
        self._system_area_row = None
        self._thread = None
        self._worker = None
        self._current_request = None
        self._pending_queue = deque()
        self._scan_active = False  # see scan_active_changed
        self._current_findings = []
        self._current_results = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 60)
        layout.setSpacing(20)

        layout.addWidget(PageHeader("Scan", "// select scan mode or configure targets"))

        self._inner_stack = QStackedWidget()

        config_view = QWidget()
        config_layout = QVBoxLayout(config_view)
        config_layout.setContentsMargins(0, 0, 0, 0)
        config_layout.setSpacing(20)

        config_card = Card(title="Scan Configuration", badge="[READY]")

        hint = QLabel("// pick a mode, or check/uncheck items yourself for a custom scan")
        hint.setObjectName("pageSub")
        hint.setFont(theme.letter_spaced_font(size=8, spacing=0.5))
        config_card.content_layout.addWidget(hint)

        config_card.content_layout.addLayout(self._build_radio_row())
        config_card.content_layout.addLayout(self._build_scan_content())

        config_layout.addWidget(config_card)
        config_layout.addStretch(1)

        self._progress_view = ScanProgressView()
        self._progress_view.fix_all_requested.connect(self._on_fix_all_requested)
        self._progress_view.close_requested.connect(lambda: self._inner_stack.setCurrentIndex(0))
        self._progress_view.stop_confirmed.connect(self._on_stop_confirmed)
        self._progress_view.minimize_requested.connect(self._on_minimize_requested)

        self._mini_popup = MiniFormPopup(self._main_window)
        self._mini_popup.details_requested.connect(self._on_details_requested)
        self._mini_popup.stop_requested.connect(self._on_popup_stop_requested)

        if self._controller is not None:
            self._controller.downloads_file_detected.connect(self._on_downloads_file_detected)
            self._controller.usb_drive_detected.connect(self._on_usb_drive_detected)

        self._inner_stack.addWidget(config_view)      # index 0
        self._inner_stack.addWidget(self._progress_view)  # index 1

        layout.addWidget(self._inner_stack)

        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_usb_drives)

        self._radio_buttons[MODES[0]].setChecked(True)
        self._apply_mode(MODES[0])

    # ─── construction ───

    def _build_radio_row(self):
        row = QHBoxLayout()
        row.setSpacing(10)

        self._radio_group = QButtonGroup(self)
        self._radio_group.setExclusive(True)
        self._radio_buttons = {}
        for index, mode in enumerate(MODES):
            button = RadioItem(mode)
            self._radio_group.addButton(button, index)
            row.addWidget(button)
            self._radio_buttons[mode] = button
        row.addStretch(1)

        self._radio_group.idClicked.connect(lambda index: self._apply_mode(MODES[index]))
        return row

    def _build_scan_content(self):
        row = QHBoxLayout()
        row.setSpacing(16)

        tree_container = QFrame()
        tree_container.setObjectName("treeContainer")
        tree_container.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._tree_layout = QVBoxLayout(tree_container)
        self._tree_layout.setContentsMargins(8, 8, 8, 8)
        self._tree_layout.setSpacing(2)
        self._build_tree()
        row.addWidget(tree_container, 1)

        right_col = QVBoxLayout()
        right_col.setSpacing(10)

        self._scan_button = Button("Start", variant="primary")
        self._scan_button.setMinimumSize(140, 54)
        self._scan_button.clicked.connect(self._on_scan_clicked)
        right_col.addWidget(self._scan_button)

        self._usb_warning_label = QLabel("Not USB connected")
        self._usb_warning_label.setObjectName("usbNotConnected")
        self._usb_warning_label.setFont(theme.letter_spaced_font(size=8, spacing=0.5))
        self._usb_warning_label.setWordWrap(True)
        self._usb_warning_label.setMaximumWidth(140)
        self._usb_warning_label.hide()
        right_col.addWidget(self._usb_warning_label)

        right_col.addStretch(1)
        row.addLayout(right_col)
        return row

    def _build_tree(self):
        self._fixed_drives = list_fixed_drives()
        self._usb_drives = sorted(list_removable_drives())
        self._known_usb = set(self._usb_drives)

        computer_drive_row = TreeRow("Computer Drive", is_group=True, icon="\U0001F4BE")
        self._tree_layout.addWidget(computer_drive_row)
        self._register_row("computer_drive", computer_drive_row)
        computer_drive_row.collapse_toggled.connect(
            lambda expanded: self._set_children_visible(self._computer_drive_child_keys(), expanded)
        )

        for mountpoint in self._fixed_drives:
            row = TreeRow(_drive_label(mountpoint, is_usb=False), indent=True)
            self._tree_layout.addWidget(row)
            self._register_row(f"{FIXED_PREFIX}{mountpoint}", row)

        for mountpoint in self._usb_drives:
            row = TreeRow(_drive_label(mountpoint, is_usb=True), indent=True)
            self._tree_layout.addWidget(row)
            self._register_row(f"{USB_PREFIX}{mountpoint}", row)

        self._system_area_row = TreeRow("System Area", is_group=True, icon="\u2699\ufe0f")
        self._tree_layout.addWidget(self._system_area_row)
        self._register_row("system_area", self._system_area_row, is_system_area=True)
        self._system_area_row.collapse_toggled.connect(
            lambda expanded: self._set_children_visible(SYSTEM_AREA_CHILD_KEYS, expanded)
        )

        for key in SYSTEM_AREA_CHILD_KEYS:
            row = TreeRow(SYSTEM_AREA_LABELS[key], indent=True)
            self._tree_layout.addWidget(row)
            self._register_row(key, row, is_system_area=True)

    def _register_row(self, key, row, is_system_area=False):
        self._rows[key] = row
        row.toggled.connect(lambda requested, k=key: self._on_row_toggled(k, requested))
        if is_system_area:
            self._system_area_keys.add(key)

    def _computer_drive_child_keys(self):
        return [k for k in self._rows if k.startswith(FIXED_PREFIX) or k.startswith(USB_PREFIX)]

    def _set_children_visible(self, keys, visible):
        for key in keys:
            row = self._rows.get(key)
            if row is not None:
                row.setVisible(visible)

    # ─── checking / mode logic ───

    def _on_row_toggled(self, key, requested_checked):
        """A checkbox was clicked - requested_checked is the state the user
        is asking for, not yet applied (see components.TreeCheckbox)."""
        if key in self._system_area_keys and not requested_checked:
            if not self._confirm_skip_system_area():
                return  # "Keep Checked" (or dialog dismissed) - no change
        self._set_checked(key, requested_checked)

    def _set_checked(self, key, value):
        row = self._rows.get(key)
        if row is None:
            return
        row.setChecked(value)
        if key == "computer_drive":
            for child_key in self._computer_drive_child_keys():
                self._rows[child_key].setChecked(value)
        elif key == "system_area":
            for child_key in SYSTEM_AREA_CHILD_KEYS:
                self._rows[child_key].setChecked(value)

    def _confirm_skip_system_area(self):
        box = QMessageBox(self)
        box.setWindowTitle("Skip System Area check?")
        box.setText(
            "System Area protection catches malware hiding in startup, "
            "registry, and background processes. We recommend keeping "
            "this on."
        )
        keep_button = box.addButton("Keep Checked", QMessageBox.ButtonRole.RejectRole)
        skip_button = box.addButton("Skip Anyway", QMessageBox.ButtonRole.DestructiveRole)
        box.setDefaultButton(keep_button)
        box.exec()
        return box.clickedButton() is skip_button

    def _mode_checked_keys(self, mode):
        """Exactly which tree keys should be checked for a given mode -
        System Area is always fully checked, every mode (the protection
        rule applies the same regardless of which mode is active)."""
        checked = set(SYSTEM_AREA_CHILD_KEYS) | {"system_area"}

        if mode == "Quick Scan":
            for mountpoint in self._fixed_drives:
                if mountpoint.upper().startswith("C:"):
                    checked.add(f"{FIXED_PREFIX}{mountpoint}")
        elif mode == "Full Scan":
            checked.add("computer_drive")
            checked.update(f"{FIXED_PREFIX}{m}" for m in self._fixed_drives)
            checked.update(f"{USB_PREFIX}{m}" for m in self._usb_drives)
        elif mode == "Scan Downloads":
            pass  # Downloads is a direct backend path in Phase 3b, not a tree item
        elif mode == "Scan USB":
            checked.update(f"{USB_PREFIX}{m}" for m in self._usb_drives)

        return checked

    def _apply_mode(self, mode):
        """Re-applies mode's full default checked-state, overwriting any
        manual customization - a silent, direct setter that never shows
        the System Area dialog (that's only for user-initiated unchecks,
        never a mode switch resetting state)."""
        self._current_mode = mode
        checked_keys = self._mode_checked_keys(mode)
        for key, row in self._rows.items():
            row.setChecked(key in checked_keys)
        self._update_usb_gate()

    def select_mode(self, mode_name):
        """Programmatically select a mode (e.g. from Dashboard's Quick Scan/
        Full Scan Quick Actions) - checks the matching radio button and
        applies its auto-check behavior, same as a real click would (radio
        buttons don't emit idClicked on a programmatic setChecked())."""
        button = self._radio_buttons.get(mode_name)
        if button is None:
            return
        button.setChecked(True)
        self._apply_mode(mode_name)

    def _update_usb_gate(self):
        no_usb = self._current_mode == "Scan USB" and not self._usb_drives
        self._usb_warning_label.setVisible(no_usb)
        self._scan_button.setEnabled(not no_usb)

    def _manual_scan_kind(self):
        """The current mode's name if its default selection is unchanged,
        otherwise "Custom scan" - so only an untouched Full Scan counts as
        a full scan."""
        checked = {key for key, row in self._rows.items() if row.isChecked()}
        if checked == self._mode_checked_keys(self._current_mode):
            return self._current_mode
        return "Custom scan"

    def _on_scan_clicked(self):
        targets, system_area_flags, quick = self._resolve_scan_plan()
        scan_kind = self._manual_scan_kind()
        already_running = self._thread is not None

        # Only touch the progress view/popup's "starting" state if nothing
        # is currently running - if an auto-scan's popup is live right now,
        # a manual click must not reset it out from under that scan; the
        # click's own request just gets queued instead (see
        # _enqueue_or_start), and this same prelude runs later, from
        # _start_scan, once it's this request's turn.
        if not already_running:
            self._inner_stack.setCurrentIndex(1)
            self._progress_view.reset_for_new_scan()
            self._mini_popup.reset()
            # Force an immediate repaint before the blocking calls below
            # start - otherwise Qt wouldn't actually draw this transition
            # until control returns to the event loop, so the screen would
            # appear to still be showing the old config view (looking
            # frozen) for the whole duration of those calls instead of
            # showing "initializing...".
            QApplication.processEvents()

        # Two devadara/ calls are confirmed (see scan_worker.py's module
        # docstring - each isolated and reproduced individually, not
        # guessed) to hang indefinitely if called from ScanWorker's QThread
        # on this machine, and must happen here on the GUI thread instead:
        # loading the ML model, and gathering persistence entries (registry/
        # scheduled-task/service - specifically the service enumeration
        # part). Both are genuinely slow even run correctly (model ~3-7s,
        # persistence ~10s for services alone) - real, bounded pauses, not
        # symptoms of a bug - so each gets its own visible status line
        # (with an explicit repaint) plus a wait cursor, rather than leaving
        # the screen looking static/stuck for however long they take. These
        # loads happen even when a scan is already running and this request
        # will just be queued - manual clicks always reload fresh (unlike
        # auto-triggers, which reuse the controller's cached model), and
        # that's unaffected by queueing.
        #
        # The USB hot-plug poll timer is also stopped for this whole
        # window - confirmed via another reproduction that it firing during
        # the model load reliably hangs that too (a psutil.disk_partitions()
        # / joblib interaction), so it's not restarted until both of these
        # slow calls are done.
        was_polling = self._poll_timer.isActive()
        self._poll_timer.stop()

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            if quick:
                model, feature_columns = None, None
            else:
                if not already_running:
                    self._progress_view.update_progress("loading detection engine...", 0)
                    QApplication.processEvents()
                model, feature_columns = load_model_and_features()

            needs_persistence = any(
                system_area_flags.get(key) for key in ("registry", "startup", "services")
            )
            if needs_persistence and not already_running:
                self._progress_view.update_progress("checking startup entries and services...", 0)
                QApplication.processEvents()
            persistence_entries = gather_persistence_entries(system_area_flags)
        finally:
            QApplication.restoreOverrideCursor()

        if was_polling:
            self._poll_timer.start(USB_POLL_INTERVAL_MS)

        request = _ScanRequest(
            targets, system_area_flags, quick, model, feature_columns, persistence_entries,
            is_auto=False, auto_label=None, scan_kind=scan_kind,
        )
        if already_running:
            self._pending_queue.append(request)
        else:
            self._start_scan(request)

    def _on_downloads_file_detected(self, file_path):
        if self._controller is None or self._controller.model is None:
            return
        self._enqueue_or_start(_ScanRequest(
            [file_path], _NO_SYSTEM_AREA_FLAGS, False,
            self._controller.model, self._controller.feature_columns, [],
            is_auto=True, auto_label=f"Downloads: {os.path.basename(file_path)}",
            log_source="downloads_watch",
        ))

    def _on_usb_drive_detected(self, drive_path):
        if self._controller is None or self._controller.model is None:
            return
        self._enqueue_or_start(_ScanRequest(
            [drive_path], _NO_SYSTEM_AREA_FLAGS, False,
            self._controller.model, self._controller.feature_columns, [],
            is_auto=True, auto_label=f"USB drive: {drive_path}",
            log_source="usb_watch",
        ))

    def start_boot_sweep(self):
        """The sign-in startup sweep (gui_app.py --autostart only, via
        MainWindow.schedule_boot_sweep): one Downloads scan through the same
        queue/popup/Stop path as any auto-scan, catching whatever arrived
        while the PC was off. Skipped if the model isn't loaded yet or
        there's no Downloads folder."""
        if self._controller is None or self._controller.model is None:
            return
        if not os.path.isdir(DOWNLOADS_FOLDER):
            return
        self._enqueue_or_start(_ScanRequest(
            [DOWNLOADS_FOLDER], _NO_SYSTEM_AREA_FLAGS, BOOT_SWEEP_QUICK,
            self._controller.model, self._controller.feature_columns, [],
            is_auto=True, auto_label="Startup scan: Downloads",
            log_source="boot_sweep", scan_kind="Startup scan",
        ))

    def _enqueue_or_start(self, request):
        if self._thread is None:
            self._start_scan(request)
        else:
            self._pending_queue.append(request)

    def _start_scan(self, request):
        """Builds and starts the ScanWorker/QThread for one request - shared
        by manual Start clicks and auto-triggered detections (see
        _on_scan_clicked/_enqueue_or_start). is_auto picks which UI comes
        up: the full progress screen for a manual scan, vs. just the
        Mini-Form popup (auto-shown, main window untouched) for an
        auto-triggered one."""
        self._current_request = request
        self._current_findings = []
        self._current_results = None
        if not self._scan_active:
            self._scan_active = True
            self.scan_active_changed.emit(True)

        if request.is_auto:
            self._mini_popup.reset()
            self._mini_popup.update_progress(request.auto_label, 0)
            self._mini_popup.show_positioned()
        else:
            self._inner_stack.setCurrentIndex(1)
            self._progress_view.reset_for_new_scan()
            self._mini_popup.reset()

        self._thread = QThread(self)
        self._worker = ScanWorker(
            request.targets, request.system_area_flags, request.quick,
            request.model, request.feature_columns, request.persistence_entries,
        )
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        if not request.is_auto:
            self._worker.progress.connect(self._progress_view.update_progress)
            self._worker.stats.connect(self._progress_view.update_stats)
            self._worker.log_line.connect(self._progress_view.append_log)
        # Same real signals, also connected to the Mini-Form popup so it
        # mirrors this scan live - no log_line, the popup has no log panel
        # (see mini_form_popup.py).
        self._worker.progress.connect(self._mini_popup.update_progress)
        self._worker.stats.connect(self._mini_popup.update_stats)
        self._worker.findings.connect(self._on_findings)
        self._worker.results.connect(self._on_results)
        self._worker.finished.connect(self._on_scan_finished)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()

    def _resolve_scan_plan(self):
        """Reads Phase 3a's checked tree state + current mode (read-only -
        none of that logic is touched) and resolves it into what the
        worker actually needs: folder/drive paths, which System Area
        checks to run, and whether to use the faster executable-only
        pipeline."""
        targets = []
        for key, row in self._rows.items():
            if not row.isChecked():
                continue
            if key.startswith(FIXED_PREFIX):
                targets.append(key[len(FIXED_PREFIX):])
            elif key.startswith(USB_PREFIX):
                targets.append(key[len(USB_PREFIX):])

        if self._current_mode == "Scan Downloads":
            downloads = os.path.join(os.path.expanduser("~"), "Downloads")
            if os.path.isdir(downloads):
                targets.append(downloads)

        system_area_flags = {
            key: self._rows[key].isChecked() for key in SYSTEM_AREA_CHILD_KEYS
        }

        quick = self._current_mode == "Quick Scan"
        return targets, system_area_flags, quick

    def _on_findings(self, findings):
        # Emitted by the worker just before finished - see ScanWorker.findings.
        self._current_findings = findings

    def _on_results(self, results):
        # Emitted by the worker just before finished - see ScanWorker.results.
        self._current_results = results

    def _record_findings(self, request, findings):
        """Log an unattended request's findings and announce them - never
        acts on them (no quarantine/delete; that stays a human decision)."""
        if request is None or not findings:
            return
        if request.log_source:
            for result in findings:
                scan_log.record_scan_result(result, request.log_source)
        if request.is_auto:
            self.auto_scan_flagged.emit(request.auto_label, findings)

    def _record_scan_history(self, request, stopped):
        """A finished (never a stopped) scan with a scan_kind -> the last
        scan / last full scan shown on the Dashboard and sidebar."""
        if stopped or request is None or not request.scan_kind or self._controller is None:
            return
        scan_history.record_finished_scan(self._controller.config_store, request.scan_kind)
        self.scan_recorded.emit()

    def _on_scan_finished(self, stopped, checked, threats, hidden, elapsed):
        request = self._current_request
        flagged_announced = bool(request is not None and request.is_auto and self._current_findings)
        self._record_findings(request, self._current_findings)
        self._record_scan_history(request, stopped)
        if not stopped and request is not None and request.scan_kind:
            self.scan_completed.emit(request.scan_kind, checked, threats, flagged_announced)
        self._current_findings = []
        known_good_self = (self._current_results or {}).get("known_good_self", [])
        if (self._current_request is not None and not self._current_request.is_auto
                and self._current_results is not None):
            self.manual_scan_results.emit(self._current_results)
        self._current_results = None
        is_auto = self._current_request is not None and self._current_request.is_auto
        if is_auto:
            self._mini_popup.show_auto_scan_result(stopped, checked, threats, hidden, elapsed)
        else:
            if stopped:
                self._inner_stack.setCurrentIndex(0)
            else:
                self._progress_view.show_finished(checked, threats, hidden, elapsed, known_good_self)
            # Mirrors the same finish onto the popup too, in case the user
            # had minimized this manual scan - unchanged behavior from
            # before request queueing existed.
            self._mini_popup.show_finished(stopped, checked, threats, hidden, elapsed)

        self._worker = None
        self._thread = None
        self._current_request = None
        if self._pending_queue:
            self._start_scan(self._pending_queue.popleft())
        else:
            self._scan_active = False
            self.scan_active_changed.emit(False)

    def _on_stop_confirmed(self):
        if self._worker is not None:
            self._worker.stop()

    def is_scan_running(self):
        """Used by MainWindow.closeEvent to decide whether to warn before
        closing to tray - a running scan (self._thread not yet cleared by
        _on_scan_finished) counts, regardless of whether it's manual or
        auto-triggered."""
        return self._thread is not None

    def force_stop_running_scan(self):
        """Used by MainWindow.closeEvent/_exit_app - the user already
        confirmed via that dialog, so this skips confirm_stop_dialog
        (unlike _on_stop_confirmed's normal callers) and also drops
        anything still queued, since closing means nothing should keep
        running in the background afterward."""
        self._pending_queue.clear()
        if self._worker is not None:
            self._worker.stop()

    def _on_fix_all_requested(self):
        if self._navigate is not None:
            self._navigate(3)  # Results page - see main_window.NAV_ITEMS

    def _on_minimize_requested(self):
        # Popup shown BEFORE the main window hides, so there's never a
        # moment with zero visible top-level windows (Qt's default
        # quitOnLastWindowClosed behavior is tied to a real close event,
        # not a bare .hide(), but avoiding the gap entirely sidesteps
        # needing to rely on that distinction at all).
        self._mini_popup.show_positioned()
        if self._main_window is not None:
            self._main_window.hide()

    def _on_details_requested(self):
        self._mini_popup.hide()
        if self._main_window is not None:
            self._main_window.show()
            self._main_window.raise_()
            self._main_window.activateWindow()

    def _on_popup_stop_requested(self):
        # Stop, specifically from the popup, closes the popup and restores
        # the main window immediately - unlike a scan finishing on its own
        # while minimized (show_finished/show_auto_scan_result, still
        # frozen-until-Details>>/auto-fade as before), the user just took
        # an explicit action here and there's nothing left for the popup
        # to usefully keep showing.
        if confirm_stop_dialog(self._mini_popup):
            self._mini_popup.set_stop_enabled(False)
            self._on_stop_confirmed()
            self._on_details_requested()

    # ─── live USB hot-plug detection ───

    def showEvent(self, event):
        super().showEvent(event)
        self._poll_usb_drives()  # catch anything that changed while hidden
        self._poll_timer.start(USB_POLL_INTERVAL_MS)

    def hideEvent(self, event):
        super().hideEvent(event)
        self._poll_timer.stop()

    def _poll_usb_drives(self):
        current = list_removable_drives()
        added = current - self._known_usb
        removed = self._known_usb - current
        if not added and not removed:
            return
        self._known_usb = current

        for mountpoint in sorted(removed):
            row = self._rows.pop(f"{USB_PREFIX}{mountpoint}", None)
            if row is not None:
                self._tree_layout.removeWidget(row)
                row.deleteLater()
            if mountpoint in self._usb_drives:
                self._usb_drives.remove(mountpoint)

        for mountpoint in sorted(added):
            self._usb_drives.append(mountpoint)
            row = TreeRow(_drive_label(mountpoint, is_usb=True), indent=True)
            insert_index = self._tree_layout.indexOf(self._system_area_row)
            self._tree_layout.insertWidget(insert_index, row)
            self._register_row(f"{USB_PREFIX}{mountpoint}", row)

        # re-apply the current mode's rule so a newly-added/removed drive is
        # correctly (un)checked under Full Scan/Scan USB, and the "Not USB
        # connected" gate re-evaluates immediately.
        self._apply_mode(self._current_mode)


class ScanCompleteCard(QWidget):
    """The scan-complete panel matching the reference image
    (assets/scan_complete_cards.png) - a centered ~520px corner-bracket
    card whose accent color, icon, title, and button all switch between a
    threats-found (red) and clean (neon) state."""

    fix_all_clicked = Signal()
    close_clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        self._card = Card()
        self._card.setFixedWidth(520)

        inner = QVBoxLayout()
        inner.setContentsMargins(20, 30, 20, 30)
        inner.setSpacing(14)
        inner.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        self._icon = StatusCircle()
        inner.addWidget(self._icon, 0, Qt.AlignmentFlag.AlignHCenter)

        self._label = QLabel("// SCAN COMPLETE")
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._label.setFont(theme.letter_spaced_font(size=8, bold=True, spacing=2))
        self._label.setStyleSheet(f"color: {theme.TEXT_MUTE};")
        inner.addWidget(self._label, 0, Qt.AlignmentFlag.AlignHCenter)

        self._title = QLabel()
        self._title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._title.setFont(theme.letter_spaced_font(size=18, black=True, spacing=2))
        inner.addWidget(self._title, 0, Qt.AlignmentFlag.AlignHCenter)

        self._subtitle = QLabel()
        self._subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._subtitle.setFont(theme.letter_spaced_font(size=9, spacing=0.3))
        self._subtitle.setStyleSheet(f"color: {theme.TEXT_DIM};")
        inner.addWidget(self._subtitle, 0, Qt.AlignmentFlag.AlignHCenter)

        self._button = Button("Fix All", variant="primary")
        self._button.clicked.connect(self._on_button_clicked)
        inner.addWidget(self._button)

        self._card.content_layout.addLayout(inner)
        outer.addWidget(self._card)

        self._threats = 0

    def _on_button_clicked(self):
        if self._threats > 0:
            self.fix_all_clicked.emit()
        else:
            self.close_clicked.emit()

    def show_result(self, threats, files_checked, elapsed_seconds, known_good_self=()):
        """known_good_self: scan results of DEVADARA's own genuine files a
        layer flagged (ScanWorker.results) - not counted as threats, but
        named in the subtitle so they never silently disappear."""
        self._threats = threats
        if threats > 0:
            accent = theme.DANGER
            self._card.set_accent(accent)
            self._icon.set_variant("danger")
            plural = "" if threats == 1 else "S"
            self._title.setText(f"{threats} THREAT{plural} FOUND")
            self._subtitle.setText(
                f"{files_checked:,} files scanned · completed in {format_elapsed(elapsed_seconds)}"
            )
            self._button.setText("FIX ALL")
            self._button.set_variant("primary")
        else:
            accent = theme.NEON
            self._card.set_accent(accent)
            self._icon.set_variant("success")
            self._title.setText("NO THREATS FOUND")
            self._subtitle.setText(f"{files_checked:,} files scanned · your computer is clean")
            self._button.setText("CLOSE")
            self._button.set_variant("secondary")

        self._title.setStyleSheet(f"color: {accent};")
        self._title.setGraphicsEffect(theme.glow_effect(accent, blur=16))

        # What the scan said about DEVADARA's own files stays visible here.
        if known_good_self:
            n = len(known_good_self)
            self._subtitle.setText(self._subtitle.text() + f"\n{n} DEVADARA file{'' if n == 1 else 's'} "
                                   "verified (Known Good) · hover for details")
            lines = []
            for result in known_good_self:
                reason = reason_text(result)
                lines.append(f"{result['file_path']} — scan said: {result.get('tier')}"
                             + (f" ({reason})" if reason else ""))
            self._subtitle.setToolTip("\n".join(lines))
        else:
            self._subtitle.setToolTip("")


def confirm_stop_dialog(parent):
    """Same "Stop scan in progress?" QMessageBox used by both
    ScanProgressView's own Stop button and MiniFormPopup's Stop button
    (via ScanPage._on_popup_stop_requested) - extracted to a module-level
    function so the popup doesn't duplicate this dialog's copy/behavior."""
    box = QMessageBox(parent)
    box.setWindowTitle("Stop scan in progress?")
    box.setText(
        "Stopping now cancels the scan before it finishes. Files "
        "already checked are unaffected."
    )
    keep_button = box.addButton("Keep Scanning", QMessageBox.ButtonRole.RejectRole)
    stop_button = box.addButton("Stop Scan", QMessageBox.ButtonRole.DestructiveRole)
    box.setDefaultButton(keep_button)

    # Centered on the screen, not left to Qt's default of centering over
    # `parent` - when parent is the Mini-Form popup (a small window
    # anchored to the bottom-right corner), that default tucks this dialog
    # into the same corner instead of the middle of the desktop.
    screen = (parent.screen() if parent is not None else None) or QApplication.primaryScreen()
    if screen is not None:
        geo = screen.availableGeometry()
        box.adjustSize()
        box.move(
            geo.center().x() - box.width() // 2,
            geo.center().y() - box.height() // 2,
        )

    box.exec()
    return box.clickedButton() is stop_button


class ScanProgressView(QWidget):
    """The scan-in-progress screen: current-target path + live Files-Checked
    count + indeterminate progress bar, the 3 live stats (reusing StatCard
    exactly as Dashboard does), the Log/Mini-Form/Stop button row, a
    togglable log panel, and the ScanCompleteCard shown in place of all of
    the above once finished - its own Fix All/Close button is the only one
    visible in that state, matching the reference image
    (assets/scan_complete_cards.png), which shows no progress bar/stats/
    buttons alongside the complete card.

    No pre-count/percent: the real scan reports batched updates (one per
    handful of files, or one per persistence/process entry - see
    scan_worker.py), which would look like large jumps if drawn directly.
    Two GUI-thread-only QTimers fake a smooth, fast-feeling update cadence
    on top of those real batches without touching any devadara.* call or
    changing the real scan's own batching cadence:
      - _checked_timer eases the displayed Files-Checked count toward the
        latest real value instead of snapping to it.
      - _path_cycle_timer cycles the current-path line through a small
        rolling buffer of recently-seen REAL paths, faster than they
        actually arrive - never fabricated text, just replayed quicker."""

    _CHECKED_TICK_MS = 40
    _PATH_CYCLE_MS = 150
    _RECENT_PATHS_MAXLEN = 8
    _LOG_MAX_LINES = 2000

    fix_all_requested = Signal()
    close_requested = Signal()
    stop_confirmed = Signal()
    minimize_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        title = QLabel("// SCANNING YOUR PC")
        title.setFont(theme.letter_spaced_font(size=13, black=True, spacing=2))
        title.setStyleSheet(f"color: {theme.NEON};")
        title.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=14))
        layout.addWidget(title)

        self._progress_section = QWidget()
        section_layout = QVBoxLayout(self._progress_section)
        section_layout.setContentsMargins(0, 0, 0, 0)
        section_layout.setSpacing(16)

        target_card = Card(title="Current Target", badge="[RUNNING]")

        # One line, middle-elided, fixed height - a long path must never
        # make the progress bar/stats below jump (full path in the tooltip).
        self._path_label = ElidedLabel()
        self._path_label.setFont(theme.letter_spaced_font(size=9, spacing=0.3))
        self._path_label.setStyleSheet(
            f"color: {theme.CYAN}; border-left: 2px solid {theme.CYAN}; padding-left: 8px;"
        )
        target_card.content_layout.addWidget(self._path_label)

        progress_row = QHBoxLayout()
        progress_row.setSpacing(14)

        # Occupies the same slot the "0%"/"100%" label used to - now shows
        # the live (eased) Files-Checked count instead, in the same color.
        self._checked_label = QLabel("0")
        self._checked_label.setFont(theme.letter_spaced_font(size=14, black=True, spacing=1))
        self._checked_label.setStyleSheet(f"color: {theme.NEON};")
        self._checked_label.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=10))
        self._checked_label.setMinimumWidth(70)
        progress_row.addWidget(self._checked_label)

        self._progress_bar = QProgressBar()
        self._progress_bar.setObjectName("scanProgressBar")
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setFixedHeight(8)
        # Always indeterminate (marquee) - there's no known total any more
        # since the pre-count phase was removed; this range is set once and
        # never changed for the life of the widget.
        self._progress_bar.setRange(0, 0)
        progress_row.addWidget(self._progress_bar, 1)

        target_card.content_layout.addLayout(progress_row)
        section_layout.addWidget(target_card)

        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self._files_stat = StatCard("Files Checked", "0")
        self._threats_stat = StatCard("Threats", "0", variant="danger")
        self._hidden_stat = StatCard("Hidden", "0", variant="warn")
        stats_row.addWidget(self._files_stat)
        stats_row.addWidget(self._threats_stat)
        stats_row.addWidget(self._hidden_stat)
        section_layout.addLayout(stats_row)

        # Recent files, one line each, middle-elided (full path on hover);
        # never wraps and never scrolls sideways.
        self._log_panel = QListWidget()
        self._log_panel.setObjectName("scanLogPanel")
        self._log_panel.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self._log_panel.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._log_panel.setWordWrap(False)
        self._log_panel.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self._log_panel.setUniformItemSizes(True)
        self._log_panel.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._log_panel.setFixedHeight(140)
        self._log_panel.setFont(theme.letter_spaced_font(size=8, spacing=0.2))
        self._log_panel.hide()
        section_layout.addWidget(self._log_panel)

        buttons_row = QHBoxLayout()
        buttons_row.setSpacing(10)

        self._log_button = Button("Log", variant="secondary")
        self._log_button.clicked.connect(self._toggle_log)
        buttons_row.addWidget(self._log_button)

        self._mini_form_button = Button("Minimize", variant="secondary")
        self._mini_form_button.clicked.connect(self.minimize_requested.emit)
        buttons_row.addWidget(self._mini_form_button)

        self._stop_button = Button("Stop", variant="secondary")
        self._stop_button.clicked.connect(self._on_stop_clicked)
        buttons_row.addWidget(self._stop_button)

        section_layout.addLayout(buttons_row)
        layout.addWidget(self._progress_section)

        self._complete_card = ScanCompleteCard()
        self._complete_card.fix_all_clicked.connect(self.fix_all_requested.emit)
        self._complete_card.close_clicked.connect(self._on_close_clicked)
        self._complete_card.hide()
        layout.addWidget(self._complete_card, 0, Qt.AlignmentFlag.AlignHCenter)

        layout.addStretch(1)

        # Smoothing state - pure GUI-thread timers, no devadara.* calls (see
        # class docstring).
        self._target_checked = 0
        self._displayed_checked = 0
        self._checked_timer = QTimer(self)
        self._checked_timer.setInterval(self._CHECKED_TICK_MS)
        self._checked_timer.timeout.connect(self._tick_checked)

        self._recent_paths = deque(maxlen=self._RECENT_PATHS_MAXLEN)
        self._path_cycle_index = 0
        self._path_cycle_timer = QTimer(self)
        self._path_cycle_timer.setInterval(self._PATH_CYCLE_MS)
        self._path_cycle_timer.timeout.connect(self._cycle_path)

    def _tick_checked(self):
        gap = self._target_checked - self._displayed_checked
        if gap <= 0:
            return
        self._displayed_checked += max(1, -(-gap // 8))  # ceil(gap / 8)
        if self._displayed_checked > self._target_checked:
            self._displayed_checked = self._target_checked
        self._set_checked_display(self._displayed_checked)

    def _set_checked_display(self, value):
        text = f"{value:,}"
        self._checked_label.setText(text)
        self._files_stat.set_value(text)

    def _cycle_path(self):
        if not self._recent_paths:
            return
        self._path_cycle_index = (self._path_cycle_index + 1) % len(self._recent_paths)
        self._path_label.setText(f"> {self._recent_paths[self._path_cycle_index]}")

    def _toggle_log(self):
        self._log_panel.setVisible(not self._log_panel.isVisible())

    def _on_stop_clicked(self):
        if self._confirm_stop():
            self._stop_button.setEnabled(False)
            self._checked_timer.stop()
            self._path_cycle_timer.stop()
            self.stop_confirmed.emit()

    def _on_close_clicked(self):
        self.close_requested.emit()

    def _confirm_stop(self):
        return confirm_stop_dialog(self)

    def reset_for_new_scan(self):
        self._progress_section.show()
        self._complete_card.hide()
        self._log_panel.clear()
        self._log_panel.hide()
        self._path_label.setText("// initializing scan engine...")
        self._target_checked = 0
        self._displayed_checked = 0
        self._set_checked_display(0)
        self._threats_stat.set_value(0, variant="danger")
        self._hidden_stat.set_value(0, variant="warn")
        self._recent_paths.clear()
        self._path_cycle_index = 0
        self._stop_button.setEnabled(True)
        self._checked_timer.start()
        self._path_cycle_timer.start()

    def update_progress(self, label, checked):
        self._target_checked = checked
        if label and (not self._recent_paths or self._recent_paths[-1] != label):
            self._recent_paths.append(label)
            self._path_cycle_index = len(self._recent_paths) - 1
            self._path_label.setText(f"> {label}")

    def update_stats(self, checked, threats, hidden):
        self._threats_stat.set_value(threats, variant="danger")
        self._hidden_stat.set_value(hidden, variant="warn")

    def append_log(self, line):
        if line:
            item = QListWidgetItem(line)
            item.setToolTip(line)
            # One text line per entry, like the old plain-text log - the
            # native style would otherwise pad each row.
            item.setSizeHint(QSize(0, self._log_panel.fontMetrics().lineSpacing()))
            self._log_panel.addItem(item)
            while self._log_panel.count() > self._LOG_MAX_LINES:
                self._log_panel.takeItem(0)
            self._log_panel.scrollToBottom()

    def show_finished(self, checked, threats, hidden, elapsed, known_good_self=()):
        self._checked_timer.stop()
        self._path_cycle_timer.stop()
        self._target_checked = checked
        self._displayed_checked = checked
        self._set_checked_display(checked)
        self._path_label.setText("> scan complete.")
        self.update_stats(checked, threats, hidden)

        self._progress_section.hide()
        self._complete_card.show_result(threats, checked, elapsed, known_good_self)
        self._complete_card.show()
