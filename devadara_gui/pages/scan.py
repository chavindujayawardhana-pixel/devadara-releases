"""
scan.py

The Scan page (Section 4): a mode-radio row + checkbox tree for selection
(assets/scan_page_reference.html, confirmed with the user - see
devadara_gui/pages/scan_tree.py for the widget that reproduces it), then
scanning (full takeover, live progress - assets/scan_progress_reference.html,
also confirmed: Full/Mini/Log states + a Stop confirmation) -> completed.
The tree replaces the four separate mode cards this page used to show, and
also replaces the Tools tab entirely: System Area and Deep Inspection are
this same tree's groups, running the exact backend calls the removed
Persistence Check / Process Scan / Memory Scan tools used (see
AppState.custom_scan_job()).

Every scan still runs on a background QThread via
devadara_gui.services.workers.StoppableWorker, wrapping the real
devadara_gui.services.app_state scan jobs - the UI thread never blocks.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from devadara_gui import theme
from devadara_gui.components import (
    Card,
    body_secondary,
    key_value_list,
    make_label,
    page_title,
    section_title,
)
from devadara_gui.dialogs import ConfirmationDialog
from devadara_gui.pages.scan_tree import (
    DEEP_INSPECTION_IDS,
    MODE_LABELS,
    SYSTEM_AREA_IDS,
    ScanModeRow,
    ScanTreeWidget,
    build_tree_spec,
)
from devadara_gui.results_views import PersistenceResultsView, ProcessResultsView
from devadara_gui.scan_mini_popup import ScanMiniPopup
from devadara_gui.services.workers import StoppableWorker

_FLAGGED_TIERS = {"malware", "suspicious", "known_bad"}
_LOG_MAX_ENTRIES = 400
_FULL_VIEW_WIDTH = 600


def _format_elapsed(seconds):
    seconds = int(seconds)
    minutes, secs = divmod(seconds, 60)
    return f"{minutes:02d}:{secs:02d}"


def _elide_left(text, max_len=64):
    if text is None:
        return "-"
    if len(text) <= max_len:
        return text
    return "..." + text[-(max_len - 3):]


def _tier_result_word(tier):
    return "flagged" if tier in _FLAGGED_TIERS else "clean"


class ScanPage(theme.PageCanvas):
    navigate_requested = Signal(str)

    def __init__(self, app_state, parent=None):
        super().__init__(parent)
        self.app_state = app_state
        self.setObjectName("pageRoot")
        self._worker = None
        self._current_mode = None
        self._minimized = False
        self._log_rows = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(theme.PAGE_PADDING, theme.PAGE_PADDING, theme.PAGE_PADDING, theme.PAGE_PADDING)
        outer.setSpacing(theme.CARD_GAP)
        outer.addWidget(page_title("Scan"))

        self.stack = QStackedWidget()
        outer.addWidget(self.stack)

        self.selection_widget = self._build_selection_widget()
        self.scanning_widget = self._build_scanning_widget()
        self.completed_widget = self._build_completed_widget()

        self.stack.addWidget(self.selection_widget)
        self.stack.addWidget(self.scanning_widget)
        self.stack.addWidget(self.completed_widget)
        self.stack.setCurrentWidget(self.selection_widget)

        self.mini_popup = ScanMiniPopup()
        self.mini_popup.detail_clicked.connect(self._on_mini_detail_clicked)
        self.mini_popup.stop_clicked.connect(self._confirm_and_stop)

    # ------------------------------------------------------------------
    def _build_selection_widget(self):
        widget = QWidget()
        outer = QVBoxLayout(widget)
        outer.setSpacing(theme.CARD_GAP)

        card = Card(object_name="card", padding=20)
        card.addWidget(body_secondary(
            "Pick a mode, or check/uncheck items yourself for a custom scan.", wrap=True,
        ))

        self.mode_row = ScanModeRow()
        card.addWidget(self.mode_row)

        drive_items = self.app_state.list_fixed_drive_items()
        tree_spec = build_tree_spec(drive_items)
        self.tree = ScanTreeWidget(tree_spec)
        self.mode_row.mode_selected.connect(self.tree.apply_mode)
        self.tree.selection_changed.connect(self._refresh_scan_button_state)

        content_row = QHBoxLayout()
        content_row.setSpacing(20)
        content_row.addWidget(self.tree, 1)

        button_col = QVBoxLayout()
        button_col.setSpacing(10)
        button_col.setAlignment(Qt.AlignTop)

        self.scan_button = QPushButton("Scan")
        self.scan_button.setObjectName("primaryButton")
        self.scan_button.setCursor(Qt.PointingHandCursor)
        self.scan_button.setFixedWidth(150)
        self.scan_button.setMinimumHeight(56)
        theme.apply_glow(self.scan_button, theme.PRIMARY_SCAN_GLOW, blur=18)
        self.scan_button.clicked.connect(self._on_scan_clicked)
        button_col.addWidget(self.scan_button)

        self.usb_note = make_label("", "metadataDisabled")
        self.usb_note.setWordWrap(True)
        self.usb_note.setAlignment(Qt.AlignHCenter)
        self.usb_note.setFixedWidth(150)
        button_col.addWidget(self.usb_note)

        content_row.addLayout(button_col)
        card.addLayout(content_row)

        outer.addWidget(card)
        outer.addStretch()

        self._refresh_scan_button_state()
        return widget

    def _refresh_scan_button_state(self):
        checked = set(self.tree.checked_ids())
        drives = self.app_state.connected_removable_drives()
        usb_checked = "usb" in checked
        self.usb_note.setText("No USB drive connected" if (usb_checked and not drives) else "")
        only_usb_checked = checked == {"usb"}
        disabled = (not checked) or (only_usb_checked and not drives)
        self.scan_button.setEnabled(not disabled)

    def showEvent(self, event):
        super().showEvent(event)
        self._refresh_scan_button_state()
        # The user navigated back to Scan (sidebar, or Fix All) while
        # minimized - treat that exactly like clicking "Detail >>"/the mini
        # popup's close button, so the app never ends up with both the
        # full screen AND the mini popup implying two different states.
        if self._minimized:
            self._on_mini_detail_clicked()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "persistence_view"):
            self.persistence_view.reposition(self.size())
        if hasattr(self, "process_view"):
            self.process_view.reposition(self.size())

    def closeEvent(self, event):
        self.mini_popup.close()
        super().closeEvent(event)

    @staticmethod
    def _centered(inner_widget):
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(inner_widget)
        row.addStretch()
        outer = QVBoxLayout()
        outer.addStretch()
        outer.addLayout(row)
        outer.addStretch()
        return outer

    @staticmethod
    def _result_row(label_text):
        row = QWidget()
        row.setObjectName("transparentPanel")
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.addWidget(make_label(label_text, "metadataText"))
        layout.addStretch()
        value_label = make_label("0", "bodyText")
        value_label.setStyleSheet(f"font-size: 12px; font-weight: 600; color: {theme.TEXT_PRIMARY};")
        layout.addWidget(value_label)
        return row, value_label

    # ------------------------------------------------------------------
    def _build_scanning_widget(self):
        widget = QWidget()
        outer = QVBoxLayout(widget)
        outer.setContentsMargins(0, 0, 0, 0)

        self.scan_view_stack = QStackedWidget()
        outer.addWidget(self.scan_view_stack)

        self.full_view = self._build_full_view()
        self.log_view = self._build_log_view()
        self.scan_view_stack.addWidget(self.full_view)
        self.scan_view_stack.addWidget(self.log_view)
        self.scan_view_stack.setCurrentWidget(self.full_view)

        return widget

    def _build_full_view(self):
        container = QWidget()
        container.setFixedWidth(_FULL_VIEW_WIDTH)
        inner = QVBoxLayout(container)
        inner.setSpacing(14)

        header_row = QHBoxLayout()
        title = make_label("Scanning your PC", "sectionTitle")
        title.setStyleSheet(f"font-size: 18px; font-weight: 600; color: {theme.TEXT_PRIMARY};")
        header_row.addWidget(title)
        header_row.addStretch()
        self.minimize_button = QPushButton("— Minimize")
        self.minimize_button.setObjectName("secondaryButton")
        self.minimize_button.setCursor(Qt.PointingHandCursor)
        self.minimize_button.clicked.connect(self._on_minimize_clicked)
        header_row.addWidget(self.minimize_button)
        inner.addLayout(header_row)

        # -- Current Location card -----------------------------------------
        location_card = Card()
        location_card.addWidget(make_label("CURRENT LOCATION", "eyebrowLabel"))
        self.location_label = make_label("-", "metadataText")
        self.location_label.setStyleSheet(
            f"font-family: Consolas, monospace; font-size: 12px; color: {theme.TEXT_SECONDARY};"
        )
        self.location_label.setWordWrap(False)
        location_card.addWidget(self.location_label)

        percent_row = QHBoxLayout()
        percent_row.setSpacing(12)
        self.percentage_label = make_label("", "displayText")
        self.percentage_label.setStyleSheet(f"font-size: 22px; font-weight: 700; color: {theme.TEXT_PRIMARY};")
        self.percentage_label.setFixedWidth(70)
        percent_row.addWidget(self.percentage_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setTextVisible(False)
        percent_row.addWidget(self.progress_bar, 1)
        location_card.addLayout(percent_row)

        self.status_text_label = make_label("Scanning files and folders...", "metadataText")
        location_card.addWidget(self.status_text_label)
        inner.addWidget(location_card)

        # -- Scan Result card -------------------------------------------------
        result_card = Card()
        result_card.addWidget(make_label("SCAN RESULT", "eyebrowLabel"))
        files_row, self.scanning_files_value = self._result_row("Files checked")
        threats_row, self.scanning_threats_value = self._result_row("Threats detected")
        suspicious_row, self.scanning_suspicious_value = self._result_row("Suspicious items")
        hidden_row, self.scanning_hidden_value = self._result_row("Hidden files")
        for row in (files_row, threats_row, suspicious_row, hidden_row):
            result_card.addWidget(row)
        inner.addWidget(result_card)

        # -- Fix All (never auto-fixes anything - navigates to Threats for
        # the user to review/act on manually; hidden while nothing's found) -
        self.fix_all_button = QPushButton("Fix All")
        self.fix_all_button.setObjectName("primaryButton")
        self.fix_all_button.setCursor(Qt.PointingHandCursor)
        theme.apply_glow(self.fix_all_button, theme.ACCENT_GREEN, blur=18, alpha=130)
        self.fix_all_button.clicked.connect(self._on_fix_all_clicked)
        self.fix_all_button.hide()
        inner.addWidget(self.fix_all_button)

        # -- View Log / Stop Scan ------------------------------------------
        actions_row = QHBoxLayout()
        actions_row.setSpacing(10)
        self.view_log_button = QPushButton("View Log")
        self.view_log_button.setObjectName("secondaryButton")
        self.view_log_button.setCursor(Qt.PointingHandCursor)
        self.view_log_button.clicked.connect(self._on_view_log_clicked)
        actions_row.addWidget(self.view_log_button)
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setObjectName("secondaryButton")
        self.stop_button.setCursor(Qt.PointingHandCursor)
        self.stop_button.clicked.connect(self._confirm_and_stop)
        actions_row.addWidget(self.stop_button)
        inner.addLayout(actions_row)

        widget = QWidget()
        widget.setLayout(self._centered(container))
        return widget

    def _build_log_view(self):
        container = QWidget()
        container.setFixedWidth(_FULL_VIEW_WIDTH)
        inner = QVBoxLayout(container)
        inner.setSpacing(14)

        header_row = QHBoxLayout()
        title = make_label("Scan Activity Log", "sectionTitle")
        title.setStyleSheet(f"font-size: 16px; font-weight: 600; color: {theme.TEXT_PRIMARY};")
        header_row.addWidget(title)
        header_row.addStretch()
        back_btn = QPushButton("← Back")
        back_btn.setObjectName("secondaryButton")
        back_btn.setCursor(Qt.PointingHandCursor)
        back_btn.clicked.connect(self._on_log_back_clicked)
        header_row.addWidget(back_btn)
        inner.addLayout(header_row)

        log_card = Card()
        self.log_scroll = QScrollArea()
        self.log_scroll.setWidgetResizable(True)
        self.log_scroll.setFixedHeight(240)
        self.log_body = QWidget()
        self.log_body.setObjectName("transparentPanel")
        self.log_body_layout = QVBoxLayout(self.log_body)
        self.log_body_layout.setContentsMargins(0, 0, 0, 0)
        self.log_body_layout.setSpacing(2)
        self.log_body_layout.addStretch()
        self.log_scroll.setWidget(self.log_body)
        log_card.addWidget(self.log_scroll)

        self.log_live_label = make_label("⋯ live updating as scan continues", "metadataDisabled")
        log_card.addWidget(self.log_live_label)
        inner.addWidget(log_card)

        widget = QWidget()
        widget.setLayout(self._centered(container))
        return widget

    def _clear_log(self):
        for label in self._log_rows:
            label.deleteLater()
        self._log_rows = []
        self.log_live_label.show()

    def _append_log_entry(self, path, tier):
        if not path:
            return
        name = path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        word = _tier_result_word(tier)
        flagged = word == "flagged"
        color = theme.TEXT_PRIMARY if flagged else theme.TEXT_SECONDARY
        weight = "700" if flagged else "400"
        label = make_label(f"✓ Checked: {name} — {word}", "bodyText")
        label.setStyleSheet(
            f"font-family: Consolas, monospace; font-size: 11px; color: {color}; font-weight: {weight};"
        )
        label.setToolTip(path)
        # Insert before the trailing stretch, which stays last.
        self.log_body_layout.insertWidget(self.log_body_layout.count() - 1, label)
        self._log_rows.append(label)
        if len(self._log_rows) > _LOG_MAX_ENTRIES:
            oldest = self._log_rows.pop(0)
            self.log_body_layout.removeWidget(oldest)
            oldest.deleteLater()
        self.log_scroll.verticalScrollBar().setValue(self.log_scroll.verticalScrollBar().maximum())

    # ------------------------------------------------------------------
    def _build_completed_widget(self):
        widget = QWidget()
        outer = QVBoxLayout(widget)
        outer.setSpacing(theme.CARD_GAP)

        title = make_label("Scan completed", "sectionTitle")
        title.setStyleSheet(f"font-size: 20px; font-weight: 600; color: {theme.TEXT_PRIMARY};")
        outer.addWidget(title, alignment=Qt.AlignHCenter)

        self.completed_card = Card()
        self.completed_card.setFixedWidth(480)
        outer.addWidget(self.completed_card, alignment=Qt.AlignHCenter)

        button_row = QHBoxLayout()
        self.done_button = QPushButton("Done")
        self.done_button.setObjectName("primaryButton")
        self.done_button.setCursor(Qt.PointingHandCursor)
        self.done_button.clicked.connect(self._go_to_selection)
        theme.apply_glow(self.done_button, theme.ACCENT_GREEN, blur=20, alpha=130)
        button_row.addWidget(self.done_button)

        self.review_button = QPushButton("Done")
        self.review_button.setObjectName("textButton")
        self.review_button.setCursor(Qt.PointingHandCursor)
        self.review_button.clicked.connect(self._go_to_selection)
        button_row.addWidget(self.review_button)
        outer.addLayout(button_row)

        # System Area / Deep Inspection results (only shown when that phase
        # ran and produced entries) - reuses the exact rendering the removed
        # Persistence Check / Process Scan tools used (results_views.py),
        # rather than rebuilding it for this page.
        self.persistence_section_title = section_title("System Area Results")
        self.persistence_section_title.hide()
        outer.addWidget(self.persistence_section_title)
        self.persistence_view = PersistenceResultsView()
        self.persistence_view.hide()
        outer.addWidget(self.persistence_view)

        self.process_section_title = section_title("Deep Inspection Results")
        self.process_section_title.hide()
        outer.addWidget(self.process_section_title)
        self.process_view = ProcessResultsView(self.app_state)
        self.process_view.hide()
        outer.addWidget(self.process_view, 1)

        return widget

    def _go_to_selection(self):
        self.stack.setCurrentWidget(self.selection_widget)
        self._refresh_scan_button_state()

    # ------------------------------------------------------------------
    def start_scan(self, mode):
        """Entry point for Dashboard's four quick-action cards - applies
        that mode's default tree selection, then runs it immediately."""
        if self._worker is not None:
            return
        self.mode_row.set_active_mode(mode)
        self.tree.apply_mode(mode)
        self._refresh_scan_button_state()
        if not self.scan_button.isEnabled():
            return
        self._run_selected_scan()

    def _on_scan_clicked(self):
        self._run_selected_scan()

    def _build_job_from_tree(self):
        checked = set(self.tree.checked_ids())
        drive_items = self.app_state.list_fixed_drive_items()
        drive_paths = [d["path"] for d in drive_items if d["id"] in checked]

        location_map = self.app_state.common_location_paths()
        location_paths = [path for item_id, path in location_map.items() if item_id in checked]

        system_area = bool(checked & set(SYSTEM_AREA_IDS)) or "sys" in checked
        deep_inspection = bool(checked & set(DEEP_INSPECTION_IDS)) or "tools" in checked

        usb_path = None
        if "usb" in checked:
            drives = self.app_state.connected_removable_drives()
            if drives:
                usb_path = drives[0]

        return self.app_state.custom_scan_job(drive_paths, location_paths, system_area, deep_inspection, usb_path)

    def _run_selected_scan(self):
        if self._worker is not None:
            return
        job = self._build_job_from_tree()

        self._current_mode = self.mode_row.current_mode
        self._minimized = False
        self.mini_popup.hide()
        self.scan_view_stack.setCurrentWidget(self.full_view)
        self._clear_log()

        self.location_label.setText("-")
        self.status_text_label.setText("Scanning files and folders...")
        self.percentage_label.setText("")
        self.progress_bar.setRange(0, 0)
        self.scanning_files_value.setText("0")
        self.scanning_threats_value.setText("0")
        self.scanning_suspicious_value.setText("0")
        self.scanning_hidden_value.setText("0")
        self.fix_all_button.hide()
        self.stop_button.setEnabled(True)
        self.stack.setCurrentWidget(self.scanning_widget)

        self._worker = StoppableWorker(job)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished_ok.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _confirm_and_stop(self):
        if self._worker is None:
            return
        if ConfirmationDialog.confirm(
            self, "Stop this scan?",
            "The scan is still in progress. Stopping now will leave the remaining files "
            "unchecked, and any threats not yet found will stay on your system.",
            confirm_label="Stop Scan", destructive=True, cancel_label="Keep Scanning",
        ):
            self.stop_button.setEnabled(False)
            self.mini_popup.set_stop_enabled(False)
            self._worker.request_stop()

    # ------------------------------------------------------------------
    def _on_minimize_clicked(self):
        self._minimized = True
        # Switch the main window's content away from this takeover screen
        # BEFORE showing the mini popup (not after) - navigate_requested is
        # a direct/synchronous connection to MainWindow.navigate_to(), so
        # by the time this line returns the Dashboard is already the
        # QStackedWidget's current widget and this page is hidden. Doing
        # it first (rather than showing the popup, then switching) means
        # there's no window where the popup's own entrance animation is
        # competing with a same-frame page switch for the compositor's
        # attention - confirmed necessary: a real live screenshot caught
        # this screen still showing behind the popup when the popup was
        # shown first.
        self.navigate_requested.emit("dashboard")
        QApplication.processEvents()
        self.mini_popup.show_popup(MODE_LABELS.get(self._current_mode, "Scan"))
        self.mini_popup.set_stop_enabled(True)

    def _on_mini_detail_clicked(self):
        self._minimized = False
        self.mini_popup.hide()
        self.scan_view_stack.setCurrentWidget(self.full_view)
        self.navigate_requested.emit("scan")

    def _on_view_log_clicked(self):
        self.scan_view_stack.setCurrentWidget(self.log_view)

    def _on_log_back_clicked(self):
        self.scan_view_stack.setCurrentWidget(self.full_view)

    def _on_fix_all_clicked(self):
        # Never auto-fixes/deletes anything - purely a shortcut to the
        # Threats page's own manual quarantine/delete/ignore actions. The
        # scan itself (self._worker) keeps running in the background
        # exactly as before; navigating away doesn't touch it.
        self.navigate_requested.emit("threats")

    # ------------------------------------------------------------------
    def _status_text_for(self, info):
        phase = info.get("phase", "")
        phase_index = info.get("phase_index", 1)
        phase_count = info.get("phase_count", 1)
        prefix = f"Step {phase_index} of {phase_count}: {phase} — " if phase_count > 1 else ""
        kind = info.get("kind")
        if kind == "entries":
            return f"{prefix}Checking persistence entries ({info['checked']} / {info['total']})..."
        if kind == "indeterminate":
            return f"{prefix}Scanning running processes for suspicious indicators..."
        return f"{prefix}Scanning files and folders..."

    def _update_fix_all(self, fixable_count):
        if fixable_count > 0:
            plural = "s" if fixable_count != 1 else ""
            self.fix_all_button.setText(f"Fix All — Review {fixable_count} Item{plural}")
            self.fix_all_button.show()
        else:
            self.fix_all_button.hide()

    def _on_progress(self, info):
        files_scanned = info.get("files_scanned", 0)
        known = info.get("known_bad_count", 0)
        flagged = info.get("flagged_count", 0)
        hidden = info.get("hidden_count", 0)
        percent = info.get("percent")
        current_path = info.get("current_path")
        current_tier = info.get("current_tier")

        self.scanning_files_value.setText(f"{files_scanned:,}")
        self.scanning_threats_value.setText(str(known))
        self.scanning_suspicious_value.setText(str(flagged))
        self.scanning_hidden_value.setText(str(hidden))

        location_text = _elide_left(current_path) if current_path else "-"
        self.location_label.setText(location_text)
        self.status_text_label.setText(self._status_text_for(info))

        if percent is not None:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(percent)
            self.percentage_label.setText(f"{percent}%")
        else:
            self.progress_bar.setRange(0, 0)
            self.percentage_label.setText("")

        self._update_fix_all(known + flagged)
        self._append_log_entry(current_path, current_tier)

        if self._minimized:
            self.mini_popup.set_path(location_text)
            self.mini_popup.set_progress(percent)
            self.mini_popup.set_counts(known + flagged, hidden)

    def _on_finished(self, outcome):
        mode = self._current_mode
        self._worker = None
        self._minimized = False
        self.mini_popup.hide()
        self.app_state.finalize_scan(MODE_LABELS.get(mode, "Scan"), outcome)
        self._show_completed(outcome)

    def _on_failed(self, _error_text):
        self._worker = None
        self._minimized = False
        self.mini_popup.hide()
        self._go_to_selection()

    def _show_completed(self, outcome):
        while self.completed_card.layout_.count():
            item = self.completed_card.layout_.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        threats = len(outcome["known_bad_findings"])
        suspicious = len(outcome["to_review"])
        for entry in outcome.get("persistence_entries", []) + outcome.get("process_entries", []):
            scan = entry.get("scan")
            if scan is None:
                continue
            if scan.get("tier") == "known_bad":
                threats += 1
            elif scan.get("tier") in ("malware", "suspicious"):
                suspicious += 1

        rows = [
            ("Files scanned", f"{outcome['files_scanned']:,}"),
            ("Threats detected", str(threats)),
            ("Suspicious items", str(suspicious)),
            ("Hidden files", str(len(outcome.get("hidden_files", [])))),
            ("Duration", _format_elapsed(outcome["elapsed_seconds"])),
        ]
        self.completed_card.addWidget(key_value_list(rows))

        if threats or suspicious:
            self.done_button.setText("Review Threats")
            self.done_button.clicked.disconnect()
            self.done_button.clicked.connect(self._review_threats)
            self.review_button.setText("Done")
            self.review_button.show()
        else:
            self.done_button.setText("Done")
            try:
                self.done_button.clicked.disconnect()
            except (RuntimeError, TypeError):
                pass
            self.done_button.clicked.connect(self._go_to_selection)
            self.review_button.hide()

        persistence_entries = outcome.get("persistence_entries", [])
        if persistence_entries:
            self.persistence_view.render(persistence_entries)
            self.persistence_section_title.show()
            self.persistence_view.show()
        else:
            self.persistence_section_title.hide()
            self.persistence_view.hide()

        process_entries = outcome.get("process_entries", [])
        if process_entries:
            self.process_view.render(process_entries)
            self.process_section_title.show()
            self.process_view.show()
        else:
            self.process_section_title.hide()
            self.process_view.hide()

        self.stack.setCurrentWidget(self.completed_widget)

    def _review_threats(self):
        self._go_to_selection()
        self.navigate_requested.emit("threats")
