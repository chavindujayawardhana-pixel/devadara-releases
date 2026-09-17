"""
threats.py

The Threats page (Section 6): Detected Threats (backed by
devadara/scan_log.py via app_state) and Quarantine (backed by
devadara/quarantine.py via app_state) tabs, plus a slide-over Threat
Details panel (Section 6.3).
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from devadara_gui import theme
from devadara_gui.components import (
    Card,
    EmptyState,
    ThreatCard,
    body_secondary,
    format_timestamp,
    key_value_list,
    page_title,
)
from devadara_gui.dialogs import ConfirmationDialog
from devadara_gui.slide_over import SlideOverPanel

_ML_GLOSS = "How confident the local machine-learning model is that this file's structure resembles malware."
_YARA_GLOSS = "Matched a known pattern used by malicious software."
_SIG_GLOSS = "Whether Windows could verify this file was signed by a trusted software publisher."


class ThreatsPage(theme.PageCanvas):
    def __init__(self, app_state, parent=None):
        super().__init__(parent)
        self.app_state = app_state
        self.setObjectName("pageRoot")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(theme.PAGE_PADDING, theme.PAGE_PADDING, theme.PAGE_PADDING, theme.PAGE_PADDING)
        outer.setSpacing(theme.CARD_GAP)
        outer.addWidget(page_title("Threats"))

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs)

        self.detected_scroll = QScrollArea()
        self.detected_scroll.setWidgetResizable(True)
        self.detected_body = QWidget()
        self.detected_layout = QVBoxLayout(self.detected_body)
        self.detected_layout.setSpacing(12)
        self.detected_scroll.setWidget(self.detected_body)
        self.tabs.addTab(self.detected_scroll, "Detected Threats")

        self.quarantine_scroll = QScrollArea()
        self.quarantine_scroll.setWidgetResizable(True)
        self.quarantine_body = QWidget()
        self.quarantine_layout = QVBoxLayout(self.quarantine_body)
        self.quarantine_layout.setSpacing(12)
        self.quarantine_scroll.setWidget(self.quarantine_body)
        self.tabs.addTab(self.quarantine_scroll, "Quarantine")

        self.detail_panel = SlideOverPanel(self)
        self.detail_panel.hide()

        self.app_state.findings_changed.connect(self.refresh_detected)
        self.app_state.quarantine_changed.connect(self.refresh_quarantine)

        self.refresh_detected()
        self.refresh_quarantine()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.detail_panel.isVisible():
            self.detail_panel.reposition(self.size())

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_detected()
        self.refresh_quarantine()

    def open_detected_tab(self):
        self.tabs.setCurrentIndex(0)

    # ------------------------------------------------------------------
    def _clear(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def refresh_detected(self):
        self._clear(self.detected_layout)
        findings = self.app_state.list_detected_threats()

        if not findings:
            empty = EmptyState("No threats detected", "DEVADARA hasn't detected any threats on this PC.")
            empty.setMinimumHeight(300)
            self.detected_layout.addWidget(empty)
            return

        for finding in findings:
            file_path = finding.get("file_path") or "(unknown file)"
            name = file_path.split("\\")[-1] if "\\" in file_path else file_path
            card = ThreatCard(name, file_path, format_timestamp(finding.get("timestamp", "")))
            card.quarantine_clicked.connect(lambda f=finding: self._quarantine(f))
            card.delete_clicked.connect(lambda f=finding: self._delete(f))
            card.ignore_clicked.connect(lambda f=finding: self._ignore(f))
            card.details_clicked.connect(lambda f=finding: self._show_details(f))
            self.detected_layout.addWidget(card)
        self.detected_layout.addStretch()

    def _quarantine(self, finding):
        self.app_state.quarantine_finding(finding["id"])

    def _delete(self, finding):
        name = (finding.get("file_path") or "this file").split("\\")[-1]
        if ConfirmationDialog.confirm(
            self, "Delete this file?",
            f"'{name}' will be permanently deleted from your PC. This cannot be undone.",
            confirm_label="Delete", destructive=True,
        ):
            self.app_state.delete_finding(finding["id"])

    def _ignore(self, finding):
        name = (finding.get("file_path") or "this file").split("\\")[-1]
        if ConfirmationDialog.confirm(
            self, "Ignore this file?",
            f"Add an exception for '{name}'? DEVADARA won't flag it again.",
            confirm_label="Add Exception",
        ):
            self.app_state.ignore_finding(finding["id"])

    def _show_details(self, finding):
        details = finding.get("details") or {}
        file_path = finding.get("file_path") or "(unknown)"
        name = file_path.split("\\")[-1] if "\\" in file_path else file_path

        rows = [("File", name)]
        if finding.get("hash"):
            rows.append(("SHA256", finding["hash"][:20] + "..."))

        tier = finding.get("tier")
        if tier == "known_bad":
            rows.append(("Detection method", "Known-threat hash match"))
        elif details.get("yara"):
            rows.append(("YARA result", "Match: " + ", ".join(details["yara"]), _YARA_GLOSS))
        if details.get("confidence") is not None:
            rows.append(("ML classification", f"{details['confidence']:.0%} confidence", _ML_GLOSS))
        publisher = details.get("publisher")
        rows.append(("Digital signature", publisher if publisher else "Not signed", _SIG_GLOSS))
        rows.append(("File location", file_path))
        rows.append(("Detection time", format_timestamp(finding.get("timestamp", ""))))
        rows.append(("Source", finding.get("source", "")))

        self.detail_panel.set_title(name)
        self.detail_panel.clear_body()
        self.detail_panel.add_widget(key_value_list(rows))

        actions = QHBoxLayout()
        quarantine_btn = QPushButton("Quarantine")
        quarantine_btn.setObjectName("primaryButton")
        quarantine_btn.setCursor(Qt.PointingHandCursor)
        quarantine_btn.clicked.connect(lambda: (self._quarantine(finding), self.detail_panel.hide()))
        theme.apply_glow(quarantine_btn, theme.ACCENT_GREEN, blur=18, alpha=130)
        actions.addWidget(quarantine_btn)
        delete_btn = QPushButton("Delete")
        delete_btn.setObjectName("secondaryButton")
        delete_btn.setCursor(Qt.PointingHandCursor)
        delete_btn.clicked.connect(lambda: (self._delete(finding), self.detail_panel.hide()))
        actions.addWidget(delete_btn)
        actions_widget = QWidget()
        actions_widget.setObjectName("transparentPanel")
        actions_widget.setLayout(actions)
        self.detail_panel.add_widget(actions_widget)

        self.detail_panel.reposition(self.size())
        self.detail_panel.open()

    # ------------------------------------------------------------------
    def refresh_quarantine(self):
        self._clear(self.quarantine_layout)
        entries = self.app_state.list_quarantine()

        if not entries:
            empty = EmptyState("Quarantine is empty", "No files are currently isolated by DEVADARA.")
            empty.setMinimumHeight(300)
            self.quarantine_layout.addWidget(empty)
            return

        note = body_secondary(
            "Items securely isolated by DEVADARA - quarantined files are isolated from the "
            "rest of your system and cannot run normally.",
            wrap=True,
        )
        self.quarantine_layout.addWidget(note)

        for entry in entries:
            card = Card()
            original_path = entry.get("original_path") or ""
            name = original_path.split("\\")[-1] if "\\" in original_path else original_path
            folder = "\\".join(original_path.split("\\")[:-1]) if "\\" in original_path else "-"

            name_label = body_secondary(name)
            name_label.setStyleSheet(f"font-size: 14px; font-weight: 600; color: {theme.TEXT_PRIMARY};")
            card.addWidget(name_label)
            card.addWidget(body_secondary(f"Original location: {folder}"))
            card.addWidget(body_secondary(f"Date: {format_timestamp(entry.get('quarantined_at', ''))}"))

            actions = QHBoxLayout()
            restore_btn = QPushButton("Restore")
            restore_btn.setObjectName("secondaryButton")
            restore_btn.setCursor(Qt.PointingHandCursor)
            restore_btn.clicked.connect(lambda e=entry: self._restore(e))
            actions.addWidget(restore_btn)

            delete_btn = QPushButton("Delete Permanently")
            delete_btn.setObjectName("secondaryButton")
            delete_btn.setCursor(Qt.PointingHandCursor)
            delete_btn.clicked.connect(lambda e=entry: self._delete_quarantined(e))
            actions.addWidget(delete_btn)
            actions.addStretch()
            card.addLayout(actions)

            self.quarantine_layout.addWidget(card)
        self.quarantine_layout.addStretch()

    def _restore(self, entry):
        self.app_state.restore_quarantine(entry["id"])

    def _delete_quarantined(self, entry):
        name = (entry.get("original_path") or "this file").split("\\")[-1]
        if ConfirmationDialog.confirm(
            self, "Delete permanently?",
            f"'{name}' will be permanently erased. This cannot be undone.",
            confirm_label="Delete Permanently", destructive=True,
        ):
            self.app_state.delete_quarantine_permanently(entry["id"])
