"""
results_page.py

The Results page (Phase 5): five tabs - Virus, Startup, Hidden, Quarantine,
Process - each a table with a checkbox per row, a clickable path column,
and action buttons underneath that act on the checked rows (the mockup's
layout, assets/deepseek_html_20260917_f4ed9f.html, with the owner's five
tabs instead of its four).

Data, all local:
  - Virus: the last manual scan's flagged files (ResultsStore, memory only)
    + unattended findings from data/scan_log.jsonl (auto-scans, startup scan)
  - Startup: the last manual scan's startup entries whose target was flagged
  - Hidden: the last manual scan's hidden files
  - Quarantine: devadara.quarantine's index
  - Process: the last manual scan's suspicious processes

OWNER RULE: every action here - including small reversible ones and Open
in Explorer - runs only after dialogs.confirm() returned True. Nothing on
this page ever acts on its own.
"""

import os

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from devadara import quarantine, scan_log
from devadara.hidden_file_scanner import describe_attributes
from devadara_gui import dialogs, theme
from devadara_gui.components import Button, PageHeader
from devadara_gui.file_location import open_in_explorer
from devadara_gui.process_guard import still_same_process

THREAT_TIERS = ("known_bad", "malware", "suspicious")
SOURCE_LABELS = {
    "last_scan": "Last scan",
    "downloads_watch": "Downloads auto-scan",
    "usb_watch": "USB auto-scan",
    "boot_sweep": "Startup scan",
}


def _norm(path):
    return os.path.normcase(os.path.abspath(path)) if path else ""


def _threat_text(result):
    if result.get("threat_name"):
        return result["threat_name"]
    confidence = (result.get("ml") or {}).get("confidence")
    if confidence is None:
        confidence = (result.get("details") or {}).get("confidence")
    return f"ML {confidence:.0%}" if confidence is not None else "—"


class ResultsTab(QWidget):
    """One tab: table + action buttons + a status line. Rows are
    (cells, payload); column 0 is always the checkbox."""

    path_clicked = Signal(str)

    def __init__(self, columns, path_column, parent=None):
        super().__init__(parent)
        self._columns = [""] + list(columns)
        self._path_column = path_column + 1
        self._payloads = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.table = QTableWidget(0, len(self._columns))
        self.table.setObjectName("resultsTable")
        self.table.setHorizontalHeaderLabels([c.upper() for c in self._columns])
        self.table.horizontalHeader().setFont(theme.letter_spaced_font(size=7, bold=True, spacing=2))
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.table.horizontalHeader().setHighlightSections(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(36)
        self.table.setShowGrid(False)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.table.setMouseTracking(True)
        # Columns are always fitted to the width (see _fit_columns).
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(36)
        self.table.cellClicked.connect(self._on_cell_clicked)
        layout.addWidget(self.table, 1)

        self.actions = QHBoxLayout()
        self.actions.setSpacing(10)
        self.actions.addStretch(1)
        layout.addLayout(self.actions)

        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setFont(theme.letter_spaced_font(size=8, spacing=0.3))
        layout.addWidget(self.status)
        self.set_status("")

    def add_action(self, label, handler, primary=False):
        button = Button(label, variant="primary" if primary else "secondary")
        button.clicked.connect(handler)
        self.actions.insertWidget(self.actions.count() - 1, button)
        return button

    def set_status(self, text, color=None):
        self.status.setText(text)
        self.status.setStyleSheet(f"color: {color or theme.TEXT_DIM};")
        self.status.setVisible(bool(text))

    def set_rows(self, rows):
        """rows: list of (cells, payload); len(cells) == len(columns)."""
        self._payloads = [payload for _cells, payload in rows]
        table = self.table
        table.clearSpans()
        table.setRowCount(0)
        if not rows:
            table.setRowCount(1)
            item = QTableWidgetItem("// no items found")
            item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            item.setForeground(QColor(theme.TEXT_MUTE))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            table.setItem(0, 0, item)
            table.setSpan(0, 0, 1, len(self._columns))
            table.setRowHeight(0, 110)
            QTimer.singleShot(0, self._fit_columns)
            return
        table.setRowCount(len(rows))
        for r, (cells, _payload) in enumerate(rows):
            check = QTableWidgetItem()
            check.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
            check.setCheckState(Qt.CheckState.Unchecked)
            table.setItem(r, 0, check)
            for c, text in enumerate(cells, start=1):
                item = QTableWidgetItem(str(text))
                item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                item.setToolTip(str(text))
                if c == self._path_column:
                    item.setForeground(QColor(theme.CYAN))
                    font = QFont(item.font())
                    font.setUnderline(True)
                    item.setFont(font)
                    item.setToolTip(f"{text}\n(click to show in File Explorer)")
                table.setItem(r, c, item)

        QTimer.singleShot(0, self._fit_columns)

    PATH_SHARE = 0.4      # the path column never gets less than this share...
    PATH_MIN = 160        # ...or this many pixels, however narrow the window
    CHECK_WIDTH = 36
    CELL_PADDING = 12     # theme.py: QTableWidget#resultsTable::item padding

    def _fit_columns(self):
        """Other columns at their natural width when the path can still keep
        its floor; otherwise the widest of them are capped (their text
        elides). Nothing ever collapses to zero or scrolls sideways."""
        table, header = self.table, self.table.horizontalHeader()
        avail = table.viewport().width()
        if avail <= 0:
            return
        others = [c for c in range(1, len(self._columns)) if c != self._path_column]
        pad = 2 * self.CELL_PADDING + 8   # the QSS item padding isn't in the size hints
        natural = {c: max(table.sizeHintForColumn(c) + pad, header.sectionSizeHint(c)) for c in others}
        room = avail - self.CHECK_WIDTH
        path_floor = max(int(room * self.PATH_SHARE), self.PATH_MIN)
        # Other columns keep their natural width while the path still gets
        # its floor; the path then takes everything left (eliding in the
        # middle if a long path still doesn't fit).
        if sum(natural.values()) + path_floor > room:
            # Cap only the widest columns (one shared cap), so short ones -
            # names, PIDs, statuses - stay whole and long text elides.
            budget = max(room - path_floor, 60 * len(others))
            cap = max(natural.values())
            while cap > 60 and sum(min(w, cap) for w in natural.values()) > budget:
                cap -= 4
            natural = {c: max(60, min(w, cap)) for c, w in natural.items()}
        header.resizeSection(0, self.CHECK_WIDTH)
        for c, w in natural.items():
            header.resizeSection(c, w)
        header.resizeSection(self._path_column, max(room - sum(natural.values()), self.PATH_MIN))

    # Fitted after the event, once the table itself has its final width - a
    # hidden tab (or one mid-resize) still reports a stale viewport width.
    def resizeEvent(self, event):
        super().resizeEvent(event)
        QTimer.singleShot(0, self._fit_columns)

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(0, self._fit_columns)

    def payloads(self):
        return list(self._payloads)

    def checked_payloads(self):
        out = []
        for r, payload in enumerate(self._payloads):
            item = self.table.item(r, 0)
            if item is not None and item.checkState() == Qt.CheckState.Checked:
                out.append(payload)
        return out

    def set_checked(self, row, checked=True):
        self.table.item(row, 0).setCheckState(
            Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)

    def _on_cell_clicked(self, row, column):
        if column != self._path_column or row >= len(self._payloads):
            return
        item = self.table.item(row, column)
        if item is not None and item.text() and item.text() != "—":
            self.path_clicked.emit(item.text())


class ResultsPage(QWidget):
    TABS = ["Virus", "Startup", "Hidden", "Quarantine", "Process"]

    def __init__(self, store, guard, parent=None):
        super().__init__(parent)
        self._store = store
        self._guard = guard

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(14)
        layout.addWidget(PageHeader("Results", "// findings from last scan — click path to locate"))

        self._scan_info = QLabel()
        self._scan_info.setFont(theme.letter_spaced_font(size=8, spacing=0.5))
        self._scan_info.setStyleSheet(f"color: {theme.TEXT_DIM};")
        layout.addWidget(self._scan_info)

        tab_row = QFrame()
        tab_row.setObjectName("resultsTabRow")
        tab_row.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        tab_layout = QHBoxLayout(tab_row)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(2)
        self._tab_group = QButtonGroup(self)
        self._tab_group.setExclusive(True)
        self._tab_buttons = []
        for index, name in enumerate(self.TABS):
            button = QPushButton(f"[ {name.upper()} ]")
            button.setObjectName("resultsTab")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setFont(theme.letter_spaced_font(size=8, bold=True, spacing=2))
            self._tab_group.addButton(button, index)
            tab_layout.addWidget(button)
            self._tab_buttons.append(button)
        tab_layout.addStretch(1)
        layout.addWidget(tab_row)

        self._stack = QStackedWidget()
        self.tabs = {
            "Virus": ResultsTab(["Threat", "Verdict", "File path", "Found by", "Status"], path_column=2),
            "Startup": ResultsTab(["Entry", "Type", "Target path", "Verdict", "Status"], path_column=2),
            "Hidden": ResultsTab(["Name", "Attributes", "Path", "Status"], path_column=2),
            "Quarantine": ResultsTab(["Original name", "Threat", "Verdict", "Quarantined", "Original path"],
                                     path_column=4),
            "Process": ResultsTab(["Program", "PID", "Path", "Why flagged", "Status"], path_column=2),
        }
        for name in self.TABS:
            tab = self.tabs[name]
            tab.path_clicked.connect(self.open_location)
            self._stack.addWidget(tab)
        layout.addWidget(self._stack, 1)

        self._tab_group.idClicked.connect(self._stack.setCurrentIndex)
        self._tab_buttons[0].setChecked(True)

        store.changed.connect(self.refresh)
        self.refresh()

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh()  # the scan log and quarantine index change on disk

    def show_tab(self, name):
        index = self.TABS.index(name)
        self._tab_buttons[index].setChecked(True)
        self._stack.setCurrentIndex(index)

    # ─── data ───

    def refresh(self):
        if self._store.scanned_at is None:
            self._scan_info.setText("// last manual scan: none yet this session — "
                                    "auto-scan findings and quarantine are shown below")
        else:
            self._scan_info.setText(
                f"// last manual scan: {self._store.scanned_at:%Y-%m-%d %H:%M}")
        counts = {
            "Virus": self._refresh_virus(),
            "Startup": self._refresh_startup(),
            "Hidden": self._refresh_hidden(),
            "Quarantine": self._refresh_quarantine(),
            "Process": self._refresh_process(),
        }
        self._counts = counts
        self._update_tab_labels()

    def _update_tab_labels(self):
        """The mockup's "[ VIRUS ]" labels, plus counts - dropping the
        brackets only when all five don't fit (e.g. at the 900px minimum)."""
        counts = getattr(self, "_counts", {})
        for compact in (False, True):
            for index, name in enumerate(self.TABS):
                n = counts.get(name, 0)
                label = f"{name.upper()} · {n}" if n else name.upper()
                button = self._tab_buttons[index]
                button.setText(label if compact else f"[ {label} ]")
                if button.property("compact") != compact:
                    button.setProperty("compact", compact)  # theme.py: tighter padding
                    button.style().unpolish(button)
                    button.style().polish(button)
            needed = sum(b.sizeHint().width() for b in self._tab_buttons) + 2 * len(self._tab_buttons)
            if needed <= self._stack.width() or self._stack.width() <= 0:
                break

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_tab_labels()

    def virus_items(self):
        """Last-scan flagged files + unattended scan-log findings, one item
        per file (log ids kept so an action can resolve them in the log)."""
        items = {}
        for result in self._store.flagged:
            key = _norm(result["file_path"])
            items[key] = {"file_path": result["file_path"], "hash": result.get("hash"),
                          "tier": result["tier"], "threat": _threat_text(result),
                          "sources": ["last_scan"], "log_ids": [], "from_store": True}
        for entry in scan_log.read_findings():
            if entry.get("tier") not in THREAT_TIERS or not entry.get("file_path"):
                continue
            key = _norm(entry["file_path"])
            item = items.setdefault(key, {
                "file_path": entry["file_path"], "hash": entry.get("hash"), "tier": entry["tier"],
                "threat": _threat_text(entry), "sources": [], "log_ids": [], "from_store": False})
            if entry.get("source") not in item["sources"]:
                item["sources"].append(entry.get("source"))
            item["log_ids"].append(entry["id"])
        return list(items.values())

    def _refresh_virus(self):
        rows = []
        for item in self.virus_items():
            status = "On disk" if os.path.isfile(item["file_path"]) else "File missing"
            sources = ", ".join(SOURCE_LABELS.get(s, s or "?") for s in item["sources"])
            rows.append(([item["threat"], item["tier"], item["file_path"], sources, status], item))
        self.tabs["Virus"].set_rows(rows)
        return len(rows)

    def _quarantined_by_path(self):
        return {_norm(e.get("original_path")): e for e in quarantine.list_quarantined()}

    def _refresh_startup(self):
        quarantined = self._quarantined_by_path()
        rows = []
        for entry in self._store.startup:
            target = entry.get("resolved_path") or ""
            if os.path.exists(target):
                status = "Target present"
            elif _norm(target) in quarantined:
                when = (quarantined[_norm(target)].get("quarantined_at") or "")[:10]
                status = f"TARGET MISSING — quarantined {when}"
            else:
                status = "TARGET MISSING"
            name = entry.get("name") or entry.get("location") or "?"
            tier = (entry.get("scan") or {}).get("tier", "—")
            rows.append(([name, entry.get("source", "?"), target or "—", tier, status], entry))
        self.tabs["Startup"].set_rows(rows)
        return len(rows)

    def _refresh_hidden(self):
        rows = []
        for path in self._store.hidden:
            attrs = describe_attributes(path)
            status = ("Missing" if attrs == "Missing" else
                      "Still hidden" if attrs.startswith("Hidden") else "Visible")
            rows.append(([os.path.basename(path) or path, attrs, path, status], path))
        self.tabs["Hidden"].set_rows(rows)
        return len(rows)

    def _refresh_quarantine(self):
        rows = []
        entries = sorted(quarantine.list_quarantined(), key=lambda e: e.get("quarantined_at") or "",
                         reverse=True)
        for entry in entries:
            original = entry.get("original_path") or ""
            rows.append(([os.path.basename(original) or "?", entry.get("threat_name") or "—",
                          entry.get("tier") or "—", (entry.get("quarantined_at") or "").replace("T", " "),
                          original or "—"], entry))
        self.tabs["Quarantine"].set_rows(rows)
        return len(rows)

    def process_status(self, proc):
        if proc.get("create_time") is None or not still_same_process(proc):
            return "Exited"
        if self._guard.is_suspended(proc):
            return "Suspended by DEVADARA"
        return "Running"

    def _refresh_process(self):
        rows = []
        for proc in self._store.processes:
            rows.append(([proc.get("name") or "?", str(proc["pid"]), proc.get("exe") or "—",
                          "; ".join(proc.get("reasons") or []) or "—", self.process_status(proc)], proc))
        self.tabs["Process"].set_rows(rows)
        return len(rows)

    # ─── actions (every one behind dialogs.confirm) ───

    def open_location(self, path):
        exists = os.path.isfile(path)
        message = ("This opens File Explorer at this file's location and highlights it. "
                   "It does not open or run the file." if exists else
                   "This file is no longer there. File Explorer will open the nearest folder "
                   "that still exists. Nothing is opened or run.")
        if not dialogs.confirm(self, "Open in File Explorer?", message, "Open in Explorer", items=[path]):
            return False
        return open_in_explorer(path)
