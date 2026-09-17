"""
results_views.py

Reusable result-list widgets for the two backend checks that used to be
their own Tools sub-pages (devadara_gui/pages/tools/persistence.py and
process_scan.py, now removed - their functionality lives only in the Scan
page's checkbox tree per the redesign). Extracted here, unchanged in
behavior, so the Scan page's "completed" screen can embed them directly
after a System Area / Deep Inspection phase runs, instead of rebuilding
this rendering from scratch.

PersistenceResultsView: registry/scheduled-task/service entries, grouped
into collapsible sections, suspicious-first, read-only (no delete/disable
action - matches persistence_scanner.py's own read-only module contract).

ProcessResultsView: flagged running processes in a table, with
Suspend/Terminate in each row's overflow menu (same
devadara.behavior_monitor.suspend_process/kill_process backend the old
Process Scan / Memory Scan tools used).
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QMenu,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from devadara_gui import theme
from devadara_gui.components import EmptyState, StatusDot, body_secondary, body_text, key_value_list, make_label
from devadara_gui.dialogs import ConfirmationDialog
from devadara_gui.slide_over import SlideOverPanel

_PERSISTENCE_SECTIONS = [("registry", "Registry"), ("scheduled_task", "Scheduled Tasks"), ("service", "Services")]

_SYSTEM_CRITICAL_NAMES = {
    "svchost.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "smss.exe", "spoolsv.exe", "explorer.exe",
}

PROCESS_COLUMNS = ["Process", "PID", "Path", "Publisher", "Signature", "Status"]


def _is_suspicious_scan(scan):
    return scan is not None and scan.get("tier") in ("malware", "suspicious", "known_bad")


class CollapsibleSection(QWidget):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.toggle_btn = QToolButton()
        self.toggle_btn.setStyleSheet(
            f"QToolButton {{ color: {theme.TEXT_PRIMARY}; font-size: 14px; font-weight: 600; "
            f"background: {theme.GRADIENT_NEUTRAL_CARD}; border: 1px solid {theme.BORDER_DEFAULT}; "
            f"border-radius: {theme.RADIUS_CARD}px; padding: 12px 16px; text-align: left; }}"
        )
        self.toggle_btn.setText(title)
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.setChecked(True)
        self.toggle_btn.setToolButtonStyle(Qt.ToolButtonTextOnly)
        self.toggle_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toggle_btn.clicked.connect(self._on_toggle)
        outer.addWidget(self.toggle_btn)

        self.body = QWidget()
        self.body.setStyleSheet(
            f"background: {theme.GRADIENT_NEUTRAL_CARD}; border: 1px solid {theme.BORDER_DEFAULT}; "
            f"border-top: none; border-bottom-left-radius: {theme.RADIUS_CARD}px; "
            f"border-bottom-right-radius: {theme.RADIUS_CARD}px;"
        )
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(16, 8, 16, 8)
        self.body_layout.setSpacing(0)
        outer.addWidget(self.body)

    def set_count(self, count):
        base = self.toggle_btn.text().split(" (")[0]
        self.toggle_btn.setText(f"{base} ({count})")

    def _on_toggle(self, checked):
        self.body.setVisible(checked)


class PersistenceResultsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        self._body_layout = layout

        self.detail_panel = SlideOverPanel(self)
        self.detail_panel.hide()

    def reposition(self, size):
        if self.detail_panel.isVisible():
            self.detail_panel.reposition(size)

    def clear(self):
        while self._body_layout.count():
            item = self._body_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def render(self, entries):
        self.clear()
        for source_key, title in _PERSISTENCE_SECTIONS:
            group = [e for e in entries if e["source"] == source_key]
            group.sort(key=lambda e: not _is_suspicious_scan(e.get("scan")))
            section = CollapsibleSection(title)
            section.set_count(len(group))

            if not group:
                section.body_layout.addWidget(body_secondary("No entries found."))
            for entry in group:
                section.body_layout.addWidget(self._entry_row(entry))
            self._body_layout.addWidget(section)
        self._body_layout.addStretch()

    def _entry_row(self, entry):
        row = QWidget()
        row.setObjectName("transparentPanel")
        layout = QVBoxLayout(row)
        layout.setContentsMargins(0, 10, 0, 10)
        layout.setSpacing(4)

        name_label = body_text(entry.get("name") or entry.get("location") or "(unnamed)")
        layout.addWidget(name_label)
        layout.addWidget(make_label(f"Location: {entry.get('location', '')}", "metadataText"))

        status_row = QHBoxLayout()
        suspicious = _is_suspicious_scan(entry.get("scan"))
        status_row.addWidget(StatusDot("attention" if suspicious else "inactive"))
        status_row.addWidget(make_label(
            "Suspicious persistence entry detected" if suspicious else "No suspicious indicators",
            "metadataText",
        ))
        status_row.addStretch()
        details_btn = QPushButton("Details >")
        details_btn.setObjectName("textButton")
        details_btn.setCursor(Qt.PointingHandCursor)
        details_btn.clicked.connect(lambda: self._show_details(entry))
        status_row.addWidget(details_btn)
        layout.addLayout(status_row)

        return row

    def _show_details(self, entry):
        scan = entry.get("scan")
        rows = [
            ("Source", entry.get("source", "")),
            ("Location", entry.get("location", "")),
            ("Command", entry.get("command", "")),
            ("Resolved path", entry.get("resolved_path") or "Target not found on disk"),
        ]
        if scan is not None:
            rows.append(("Tier", scan.get("tier", "")))
            if scan.get("threat_name"):
                rows.append(("Threat", scan["threat_name"]))
            if scan.get("ml"):
                rows.append(("ML classification", f"{scan['ml']['confidence']:.0%} confidence"))
            if scan.get("signature"):
                rows.append(("Digital signature", scan["signature"].get("status", "")))

        self.detail_panel.set_title(entry.get("name") or entry.get("location") or "Persistence entry")
        self.detail_panel.clear_body()
        self.detail_panel.add_widget(key_value_list(rows))
        self.detail_panel.reposition(self.size())
        self.detail_panel.open()


class ProcessResultsView(QWidget):
    def __init__(self, app_state, parent=None):
        super().__init__(parent)
        self.app_state = app_state
        self._entries = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.empty_state = EmptyState(
            "No suspicious processes found",
            "Deep Inspection did not flag any running process for review.",
        )
        layout.addWidget(self.empty_state)

        self.table = QTableWidget(0, len(PROCESS_COLUMNS))
        self.table.setHorizontalHeaderLabels(PROCESS_COLUMNS)
        self.table.verticalHeader().hide()
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setShowGrid(False)
        self.table.hide()
        layout.addWidget(self.table)

        self.detail_panel = SlideOverPanel(self)
        self.detail_panel.hide()

    def reposition(self, size):
        if self.detail_panel.isVisible():
            self.detail_panel.reposition(size)

    def clear(self):
        self._entries = []
        self.table.hide()
        self.table.setRowCount(0)
        self.empty_state.show()

    def _tier_status(self, entry):
        scan = entry.get("scan")
        if scan is None:
            return "Unscanned", "inactive"
        if scan.get("tier") in ("malware", "suspicious", "known_bad"):
            return "Suspicious", "attention"
        return "Safe", "active"

    def render(self, entries):
        self._entries = entries
        if not entries:
            self.clear()
            return

        self.empty_state.hide()
        self.table.show()
        self.table.setRowCount(len(entries))

        for row, entry in enumerate(entries):
            scan = entry.get("scan") or {}
            signature = scan.get("signature") or {}
            publisher = signature.get("publisher") or "-"
            sig_status = signature.get("status") or ("-" if scan.get("signature") is None else "Unsigned")
            status_text, status_state = self._tier_status(entry)

            self.table.setItem(row, 0, QTableWidgetItem(entry.get("name", "")))
            self.table.setItem(row, 1, QTableWidgetItem(str(entry.get("pid", ""))))
            self.table.setItem(row, 2, QTableWidgetItem(entry.get("exe") or "-"))
            self.table.setItem(row, 3, QTableWidgetItem(publisher))
            self.table.setItem(row, 4, QTableWidgetItem(sig_status))

            status_cell = QWidget()
            status_cell.setObjectName("transparentPanel")
            status_layout = QHBoxLayout(status_cell)
            status_layout.setContentsMargins(6, 0, 6, 0)
            status_layout.setSpacing(6)
            status_layout.addWidget(StatusDot(status_state))
            status_layout.addWidget(make_label(status_text, "metadataText"))
            more_btn = QPushButton("⋯")
            more_btn.setObjectName("textButton")
            more_btn.setFixedWidth(28)
            more_btn.setCursor(Qt.PointingHandCursor)
            more_btn.clicked.connect(lambda _checked=False, e=entry, b=more_btn: self._open_row_menu(e, b))
            status_layout.addStretch()
            status_layout.addWidget(more_btn)
            self.table.setCellWidget(row, 5, status_cell)

        self.table.resizeRowsToContents()

    def _open_row_menu(self, entry, anchor_button):
        menu = QMenu(self)
        menu.addAction("View Details", lambda: self._show_details(entry))
        menu.addAction("Suspend", lambda: self._suspend(entry))
        menu.addAction("Terminate", lambda: self._terminate(entry))
        menu.exec(anchor_button.mapToGlobal(anchor_button.rect().bottomRight()))

    def _show_details(self, entry):
        scan = entry.get("scan") or {}
        rows = [
            ("Process", entry.get("name", "")),
            ("PID", str(entry.get("pid", ""))),
            ("Path", entry.get("exe") or "-"),
            ("Reasons flagged", "; ".join(entry.get("reasons", []))),
        ]
        if scan.get("tier"):
            rows.append(("Detection tier", scan["tier"]))
        if scan.get("ml"):
            rows.append(("ML classification", f"{scan['ml']['confidence']:.0%} confidence"))
        if scan.get("signature"):
            rows.append(("Digital signature", scan["signature"].get("status", "")))

        self.detail_panel.set_title(entry.get("name", "Process"))
        self.detail_panel.clear_body()
        self.detail_panel.add_widget(key_value_list(rows))
        self.detail_panel.reposition(self.size())
        self.detail_panel.open()

    def _confirm_and_act(self, entry, action_label, backend_call):
        name = entry.get("name", "")
        pid = entry.get("pid")
        exe = entry.get("exe") or ""
        body = f"Are you sure you want to {action_label.lower()} this process?\n\n{name} (PID {pid})\n{exe}"
        if name.lower() in _SYSTEM_CRITICAL_NAMES:
            body += "\n\nThis is a system process. Terminating it may cause instability or a crash."
        if ConfirmationDialog.confirm(self, f"{action_label} process?", body, confirm_label=action_label, destructive=True):
            backend_call(pid)

    def _suspend(self, entry):
        self._confirm_and_act(entry, "Suspend", self.app_state.suspend_pid)

    def _terminate(self, entry):
        self._confirm_and_act(entry, "Terminate", self.app_state.kill_pid)
