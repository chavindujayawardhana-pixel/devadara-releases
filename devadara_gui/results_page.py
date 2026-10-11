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

from PySide6.QtCore import QEvent, QRect, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QStackedWidget,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from devadara import ignore_list, quarantine, scan_log, verdict_labels
from devadara.hash_scanner import compute_sha256
from devadara import hidden_file_scanner
from devadara.hidden_file_scanner import describe_attributes
from devadara_gui import dialogs, theme
from devadara_gui.components import Button, PageHeader
from devadara_gui.file_location import open_in_explorer
from devadara_gui.process_guard import refusal_reason, still_same_process

THREAT_TIERS = ("known_bad", "malware", "suspicious")
SYSTEM_ROOT = os.path.normcase(os.path.abspath(os.environ.get("SystemRoot", r"C:\Windows")))
LARGE_FILE_BYTES = 200 * 1024 * 1024  # quarantine reads the whole file into memory

# Where the user can remove a startup entry themselves - DEVADARA never does.
STARTUP_REMOVAL_HINTS = {
    "registry": "Task Manager → Startup apps (or the registry key above)",
    "scheduled_task": "Task Scheduler (taskschd.msc) → the task above",
    "service": "Services (services.msc) → the service above",
}
PROGRAM_FILES = [os.path.normcase(os.path.abspath(p)) for p in
                 (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")) if p]

SOURCE_LABELS = {
    "last_scan": "Last scan",
    "downloads_watch": "Downloads",
    "usb_watch": "USB",
    "boot_sweep": "Startup scan",
}


def _norm(path):
    return os.path.normcase(os.path.abspath(path)) if path else ""


NOTHING = "—"  # shown only when the data truly holds nothing to show
_PLACEHOLDERS = {None, "", "—", "–", "-"}


def signature_text(result):
    """The digital-signature facts the scan recorded, to help judge a false
    positive (a signed installer that a "suspicious" YARA rule still holds
    at "suspicious"). Display only - it never changes a verdict. None when
    no signature was checked (non-executables never are)."""
    sig = result.get("signature")
    if sig:
        status = sig.get("status")
        # A certificate name containing a comma arrives quoted ('"HITPAW CO.')
        # - stripped for display only; detection still uses the raw value.
        publisher = (sig.get("publisher") or "").strip('" ') or None
        if sig.get("valid_and_trusted"):
            return f"Signed: {publisher}"
        if status == "Valid" and publisher:
            return f"Signed: {publisher} (certificate expired)"
        if status == "NotSigned":
            return "Unsigned"
        if status in ("Error", "Unknown", None):
            return "signature check failed"
        return f"Signature {status}" + (f": {publisher}" if publisher else "")
    # Scan-log entries only record the publisher name, not whether the
    # signature was valid - say exactly that much.
    publisher = (result.get("details") or {}).get("publisher")
    return f"Publisher: {publisher}" if publisher else None


def verdict_cell(result, check_self=True):
    """A table cell for a result's verdict: the plain-words label plus
    the raw tier, coloured with the label's theme token (see
    devadara/verdict_labels.py). Display only - never a verdict change."""
    text, token = verdict_labels.verdict_text(result, check_self)
    return text, getattr(theme, token)


def reason_text(result):
    """Why a scan_engine result (or a scan_log entry, whose extra fields
    sit under "details") was flagged, in plain words, built only from
    fields that exist: the threat name (hash match / high-severity YARA),
    YARA rule names (a "suspicious" YARA match sets no threat name), the
    ML score, and the trusted-publisher-name downgrade. None if the data
    holds none of these - e.g. an auto-scan log entry for a YARA match,
    since the scan log doesn't record rule names."""
    details = result.get("details") or {}
    parts = []
    threat = result.get("threat_name") or details.get("threat_name")
    if threat not in _PLACEHOLDERS:
        parts.append(threat)
    rules = [m["rule"] for m in (result.get("yara") or []) if m.get("rule")]
    if rules and not (threat or "").startswith("YARA:"):
        parts.append("YARA: " + ", ".join(rules))
    ml = result.get("ml") or {}
    # A file the ML model couldn't read (is_pe False) carries a placeholder
    # 0.0, not a real score - never shown as one.
    confidence = ml.get("confidence") if ml.get("is_pe", True) else None
    if confidence is None and not ml:
        confidence = details.get("confidence") or None
    if confidence is not None:
        parts.append(f"ML score {confidence:.0%}")
    signature = signature_text(result)
    if signature:
        parts.append(signature)
    if result.get("downgraded_from_malware") or details.get("downgraded_from_malware"):
        parts.append("publisher name on the trusted list, but its signature isn't verified")
    return "; ".join(parts) or None


CHECK_SIZE = 13  # px - row boxes and the header "select all" box (theme.py indicator rules)


def centered_check_rect(cell):
    """The one place a checkbox's position is decided: CHECK_SIZE square,
    centred horizontally and vertically in the cell - used for every row
    box and for the header box, so they always line up exactly."""
    return QRect(cell.x() + (cell.width() - CHECK_SIZE) // 2,
                 cell.y() + (cell.height() - CHECK_SIZE) // 2, CHECK_SIZE, CHECK_SIZE)


class _CenteredCheckDelegate(QStyledItemDelegate):
    """Column 0: draws the row's check box centred in the cell (Qt's own
    placement depends on the Windows style and top-aligns it in tall rows),
    styled by the same QSS ::indicator rules. A click anywhere in the cell
    toggles it - selection only, no action."""

    def paint(self, painter, option, index):
        cell = QStyleOptionViewItem(option)
        self.initStyleOption(cell, index)
        cell.features &= ~QStyleOptionViewItem.ViewItemFeature.HasCheckIndicator
        style = cell.widget.style() if cell.widget else QStyle()
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, cell, painter, cell.widget)  # hover background
        state = index.data(Qt.ItemDataRole.CheckStateRole)
        if state is None:
            return
        box = QStyleOptionViewItem(option)
        box.rect = centered_check_rect(option.rect)
        box.state &= ~(QStyle.StateFlag.State_On | QStyle.StateFlag.State_Off | QStyle.StateFlag.State_NoChange)
        box.state |= {Qt.CheckState.Checked.value: QStyle.StateFlag.State_On,
                      Qt.CheckState.PartiallyChecked.value: QStyle.StateFlag.State_NoChange}.get(
            Qt.CheckState(state).value, QStyle.StateFlag.State_Off)
        style.drawPrimitive(QStyle.PrimitiveElement.PE_IndicatorItemViewItemCheck, box, painter, cell.widget)

    def editorEvent(self, event, model, option, index):
        if index.data(Qt.ItemDataRole.CheckStateRole) is None:
            return False
        if event.type() in (QEvent.Type.MouseButtonPress, QEvent.Type.MouseButtonDblClick):
            return option.rect.contains(event.position().toPoint())
        if (event.type() == QEvent.Type.MouseButtonRelease and event.button() == Qt.MouseButton.LeftButton
                and option.rect.contains(event.position().toPoint())):
            checked = Qt.CheckState(index.data(Qt.ItemDataRole.CheckStateRole)) == Qt.CheckState.Checked
            model.setData(index, Qt.CheckState.Unchecked if checked else Qt.CheckState.Checked,
                          Qt.ItemDataRole.CheckStateRole)
            return True
        return False


class _MiddleElideDelegate(QStyledItemDelegate):
    """Paths elide in the middle (drive ... file name); every other column
    elides at the end so the start of a reason stays readable."""

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        option.textElideMode = Qt.TextElideMode.ElideMiddle


class ResultsTab(QWidget):
    """One tab: table + action buttons + a status line. Rows are
    (cells, payload); column 0 is always the checkbox."""

    path_clicked = Signal(str)
    # Row ticks changed in bulk (select all) - itemChanged is blocked then.
    checks_changed = Signal()

    def __init__(self, columns, path_column, priority_column=None, parent=None):
        super().__init__(parent)
        self._columns = [""] + list(columns)
        self._path_column = path_column + 1
        # The column that explains WHY (threat / reason) - it shares the
        # width with the path instead of being capped like the rest.
        self._priority_column = priority_column + 1 if priority_column is not None else None
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
        self.table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self._path_delegate = _MiddleElideDelegate(self.table)
        self._check_delegate = _CenteredCheckDelegate(self.table)
        self.table.setItemDelegateForColumn(0, self._check_delegate)
        self.table.setItemDelegateForColumn(self._path_column, self._path_delegate)
        self.table.setMouseTracking(True)
        # Columns are always fitted to the width (see _fit_columns).
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(36)
        self.table.cellClicked.connect(self._on_cell_clicked)
        layout.addWidget(self.table, 1)

        # "Select all" in the checkbox column's header. It ONLY ticks or
        # unticks rows - it is never connected to any action; the action
        # buttons below still warn first, naming the count and the files.
        self.select_all = QCheckBox(header)
        self.select_all.setFixedSize(CHECK_SIZE, CHECK_SIZE)  # exactly the row boxes' size
        self.select_all.setObjectName("resultsSelectAll")
        self.select_all.setTristate(True)  # shows "some ticked"; clicks are handled below
        self.select_all.setToolTip("Tick or untick every row. This only selects - it does not run any action.")
        self.select_all.clicked.connect(self._on_select_all_clicked)
        self.table.itemChanged.connect(self._sync_select_all)
        header.geometriesChanged.connect(self._place_select_all)
        header.sectionResized.connect(self._place_select_all)

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
        """rows: list of (cells, payload); len(cells) == len(columns). A
        cell is text, or (text, colour) for a coloured cell (verdicts)."""
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
            self._sync_select_all()
            QTimer.singleShot(0, self._fit_columns)
            return
        table.setRowCount(len(rows))
        for r, (cells, _payload) in enumerate(rows):
            check = QTableWidgetItem()
            check.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
            check.setCheckState(Qt.CheckState.Unchecked)
            table.setItem(r, 0, check)
            for c, text in enumerate(cells, start=1):
                color = None
                if isinstance(text, tuple):
                    text, color = text
                text = str(text)
                if c == self._priority_column:
                    # One line per part of the reason ("YARA: ..." /
                    # "Signed: ..."), so no part is cut off by the others.
                    text = text.replace(" — ", "\n").replace("; ", "\n")
                item = QTableWidgetItem(text)
                item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                item.setToolTip(text)
                if color:
                    item.setForeground(QColor(color))
                if c == self._path_column:
                    item.setForeground(QColor(theme.CYAN))
                    font = QFont(item.font())
                    font.setUnderline(True)
                    item.setFont(font)
                    item.setToolTip(f"{text}\n(click to show in File Explorer)")
                table.setItem(r, c, item)
        # Rows grow only for multi-line reasons; single-line rows keep 36px.
        line_height = table.fontMetrics().lineSpacing()
        for r in range(len(rows)):
            item = table.item(r, self._priority_column) if self._priority_column else None
            lines = item.text().count("\n") + 1 if item is not None else 1
            table.setRowHeight(r, max(36, lines * line_height + 16))

        self._sync_select_all()
        QTimer.singleShot(0, self._fit_columns)

    PATH_SHARE = 0.25     # the path column never gets less than this share...
    PRIORITY_SHARE = 0.35 # ...and the reason column up to this share
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
            # The reason column keeps up to its share; then only the widest
            # of the rest are capped (one shared cap), so short ones -
            # names, PIDs, statuses - stay whole and long text elides.
            fixed = {}
            prio = self._priority_column
            if prio in natural:
                fixed[prio] = min(natural[prio], max(int(room * self.PRIORITY_SHARE), 120))
            rest = {c: w for c, w in natural.items() if c not in fixed}
            if prio in fixed:
                # Very narrow: the reason column gives back what the other
                # columns need for their 60px minimum.
                fixed[prio] = max(120, min(fixed[prio], room - path_floor - 60 * len(rest)))
            budget = max(room - path_floor - sum(fixed.values()), 60 * len(rest))
            cap = max(rest.values()) if rest else 60
            while cap > 60 and sum(min(w, cap) for w in rest.values()) > budget:
                cap -= 4
            natural = {**{c: max(60, min(w, cap)) for c, w in rest.items()}, **fixed}
        header.resizeSection(0, self.CHECK_WIDTH)
        for c, w in natural.items():
            header.resizeSection(c, w)
        header.resizeSection(self._path_column, max(room - sum(natural.values()), self.PATH_MIN))
        self._place_select_all()

    def _place_select_all(self, *_):
        header = self.table.horizontalHeader()
        cell = QRect(header.sectionViewportPosition(0), 0, header.sectionSize(0), header.height())
        # Same centring rule as the row boxes, in the same column - and the
        # header viewport starts at the same x as the table's viewport.
        self.select_all.move(centered_check_rect(cell).topLeft())

    def _row_check_items(self):
        return [self.table.item(r, 0) for r in range(len(self._payloads))]

    def _on_select_all_clicked(self):
        """Tick every row, or untick every row if all were already ticked.
        Selection only - nothing else happens."""
        items = self._row_check_items()
        target = (Qt.CheckState.Unchecked if items and all(i.checkState() == Qt.CheckState.Checked for i in items)
                  else Qt.CheckState.Checked)
        self.table.blockSignals(True)
        for item in items:
            item.setCheckState(target)
        self.table.blockSignals(False)
        self.table.viewport().update()
        self._sync_select_all()
        self.checks_changed.emit()

    def _sync_select_all(self, *_):
        items = self._row_check_items()
        ticked = sum(1 for i in items if i is not None and i.checkState() == Qt.CheckState.Checked)
        state = (Qt.CheckState.Unchecked if ticked == 0 else
                 Qt.CheckState.Checked if ticked == len(items) else Qt.CheckState.PartiallyChecked)
        self.select_all.blockSignals(True)
        self.select_all.setCheckState(state)
        self.select_all.setEnabled(bool(items))
        self.select_all.blockSignals(False)

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
        if item is not None and item.text() and item.text() != NOTHING:
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
            "Virus": ResultsTab(["Threat", "Verdict", "File path", "Found by", "Status"],
                                path_column=2, priority_column=0),
            "Startup": ResultsTab(["Entry", "Type", "Target path", "Verdict", "Status"],
                                  path_column=2, priority_column=3),
            "Hidden": ResultsTab(["Name", "Attributes", "Path", "Status"], path_column=2, priority_column=1),
            "Quarantine": ResultsTab(["Original name", "Threat", "Verdict", "Quarantined", "Original path"],
                                     path_column=4, priority_column=1),
            "Process": ResultsTab(["Program", "PID", "Path", "Why flagged", "Status"],
                                  path_column=2, priority_column=3),
        }
        for name in self.TABS:
            tab = self.tabs[name]
            tab.path_clicked.connect(self.open_location)
            self._stack.addWidget(tab)
        layout.addWidget(self._stack, 1)

        self._tab_group.idClicked.connect(self._stack.setCurrentIndex)

        virus = self.tabs["Virus"]
        self.quarantine_button = virus.add_action("Quarantine Checked", self.quarantine_checked, primary=True)
        self.ignore_button = virus.add_action("Ignore Checked", self.ignore_checked)

        startup = self.tabs["Startup"]
        self.review_button = startup.add_action("Review", self.review_startup, primary=True)

        hidden = self.tabs["Hidden"]
        self.unhide_all_button = hidden.add_action("Unhide All", self.unhide_all, primary=True)
        self.unhide_checked_button = hidden.add_action("Unhide Checked", self.unhide_checked)

        process = self.tabs["Process"]
        self.suspend_button = process.add_action("Suspend", lambda: self.process_action("suspend"))
        self.resume_button = process.add_action("Resume", lambda: self.process_action("resume"))
        self.kill_button = process.add_action("Kill", lambda: self.process_action("kill"))
        process.table.itemChanged.connect(self._update_process_buttons)
        process.checks_changed.connect(self._update_process_buttons)

        quarantined = self.tabs["Quarantine"]
        self.restore_button = quarantined.add_action("Restore Checked", self.restore_checked)
        self.delete_button = quarantined.add_action("Delete Permanently", self.delete_checked)
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

    def pending_count(self):
        """How many of the last manual scan's results (memory only - lost on
        quit) are still waiting for the user: flagged files still on disk,
        startup entries whose target is still there, hidden files still
        hidden, flagged programs still running. Scan-log findings aren't
        counted - they're on disk and survive a restart."""
        store = self._store
        return (sum(1 for r in store.flagged if os.path.isfile(r["file_path"]))
                + sum(1 for e in store.startup if os.path.exists(e.get("resolved_path") or ""))
                + sum(1 for p in store.hidden if hidden_file_scanner.is_hidden(p))
                + sum(1 for p in store.processes
                      if p.get("create_time") is not None and still_same_process(p)))

    def virus_items(self):
        """Last-scan flagged files + unattended scan-log findings, one item
        per file (log ids kept so an action can resolve them in the log)."""
        items = {}
        for result in self._store.flagged:
            key = _norm(result["file_path"])
            items[key] = {"file_path": result["file_path"], "hash": result.get("hash"),
                          "tier": result["tier"], "threat": reason_text(result),
                          "sources": ["last_scan"], "log_ids": [], "from_store": True}
        for entry in scan_log.read_findings():
            if entry.get("tier") not in THREAT_TIERS or not entry.get("file_path"):
                continue
            key = _norm(entry["file_path"])
            item = items.setdefault(key, {
                "file_path": entry["file_path"], "hash": entry.get("hash"), "tier": entry["tier"],
                "threat": reason_text(entry), "sources": [], "log_ids": [], "from_store": False})
            if entry.get("source") not in item["sources"]:
                item["sources"].append(entry.get("source"))
            item["log_ids"].append(entry["id"])
        return list(items.values())

    def _refresh_virus(self):
        rows = []
        for item in self.virus_items():
            status = "On disk" if os.path.isfile(item["file_path"]) else "File missing"
            sources = ", ".join(SOURCE_LABELS.get(s, s or "?") for s in item["sources"])
            rows.append(([item["threat"] or NOTHING, verdict_cell(item), item["file_path"], sources, status],
                         item))
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
            scan = entry.get("scan") or {}
            reason = reason_text(scan)
            if scan.get("tier"):
                label, color = verdict_cell({**scan, "file_path": target})
                verdict = (label + (f" — {reason}" if reason else ""), color)
            else:
                verdict = NOTHING
            rows.append(([name, entry.get("source", "?"), target or NOTHING, verdict, status], entry))
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
            threat = entry.get("threat_name")
            # Older Results-page entries saved the table's placeholder as
            # the threat name - treat that as "nothing recorded".
            rows.append(([os.path.basename(original) or "?",
                          NOTHING if threat in _PLACEHOLDERS else threat,
                          verdict_cell(entry, check_self=False) if entry.get("tier") else NOTHING,
                          (entry.get("quarantined_at") or "").replace("T", " "),
                          original or NOTHING], entry))
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
            why = list(proc.get("reasons") or [])
            scan = proc.get("scan") or {}
            if scan.get("tier") in THREAT_TIERS:
                reason = reason_text(scan)
                label, _color = verdict_cell({**scan, "file_path": proc.get("exe")})
                why.append(f"its file: {label}" + (f" ({reason})" if reason else ""))
            rows.append(([proc.get("name") or "?", str(proc["pid"]), proc.get("exe") or NOTHING,
                          "; ".join(why) or NOTHING, self.process_status(proc)], proc))
        self.tabs["Process"].set_rows(rows)
        self._update_process_buttons()
        return len(rows)

    def _update_process_buttons(self, *_):
        """Resume only for a program DEVADARA itself suspended (shared
        ProcessGuard - the behavior popup's suspensions count too)."""
        if not hasattr(self, "resume_button"):
            return
        checked = self.tabs["Process"].checked_payloads()
        self.resume_button.setEnabled(len(checked) == 1 and self._guard.is_suspended(checked[0]))

    # ─── actions (every one behind dialogs.confirm) ───

    UNHIDE_MESSAGE = ("This removes the Hidden attribute so the file shows normally in File "
                      "Explorer. Nothing else about the file changes - it is not opened, run, "
                      "moved or deleted. You can hide it again from its Properties.")

    @staticmethod
    def _split_by_refusal(paths, reason_for):
        allowed, refused = [], []
        for path in paths:
            reason = reason_for(path)
            if reason is None:
                allowed.append(path)
            else:
                refused.append((path, reason))
        return allowed, refused

    @staticmethod
    def _refused_text(refused, limit=3):
        shown = "; ".join(f"{os.path.basename(p) or p}: {r}" for p, r in refused[:limit])
        more = f" (+{len(refused) - limit} more)" if len(refused) > limit else ""
        return f"{len(refused)} skipped — {shown}{more}"

    # ─── Virus tab ───

    @staticmethod
    def _quarantine_refusal(path):
        if not path or not os.path.isfile(path):
            return "the file no longer exists"
        if _norm(path).startswith(SYSTEM_ROOT + os.sep):
            return "it's a Windows component - quarantining it could break Windows"
        return None

    def _resolve_virus_item(self, item):
        """Drop a dealt-with item from both places it can come from: the
        last-scan store and the unattended scan log."""
        if item.get("log_ids"):
            scan_log.remove_findings(set(item["log_ids"]))
        if item.get("from_store"):
            self._store.remove_flagged(item["file_path"])

    def _partition_for_quarantine(self, items):
        allowed, refused = [], []
        for item in items:
            reason = self._quarantine_refusal(item["file_path"])
            (allowed.append(item) if reason is None else refused.append((item["file_path"], reason)))
        return allowed, refused

    def _large_file_note(self, allowed):
        large = [i for i in allowed if os.path.getsize(i["file_path"]) > LARGE_FILE_BYTES]
        return f"{len(large)} large file(s): DEVADARA may pause while it encrypts them." if large else ""

    def _run_quarantine(self, allowed, refused, tab):
        """Quarantine already-confirmed files and report. Returns the items
        actually quarantined (original gone from its location)."""
        done, in_use, failed = [], [], []
        for item in allowed:
            entry_id = quarantine.quarantine_file(
                item["file_path"], file_hash=item.get("hash"), threat_name=item.get("threat"),
                tier=item.get("tier"), source="results_page")
            if entry_id is None:
                failed.append(item)
            elif os.path.exists(item["file_path"]):
                # quarantine_file() made the encrypted copy but couldn't
                # remove the original - usually because a program has it open.
                in_use.append(item)
            else:
                done.append(item)
        text = f"// quarantined {len(done)} file(s)"
        if in_use:
            text += (f" — {len(in_use)} still on disk (in use by a program?): an encrypted copy is in "
                     "quarantine, but close the program and quarantine again")
        if failed:
            text += f" — {len(failed)} couldn't be quarantined (no access?)"
        if refused:
            text += " — " + self._refused_text(refused)
        tab.set_status(text, theme.WARN if (in_use or failed) else theme.NEON)
        return done

    def quarantine_files(self, items, tab):
        """Virus tab: warn, then quarantine each allowed file."""
        allowed, refused = self._partition_for_quarantine(items)
        if not allowed:
            tab.set_status("// " + self._refused_text(refused), theme.WARN)
            return []
        n = len(allowed)
        message = ("This encrypts each file and moves it into DEVADARA's quarantine folder, so it "
                   "can't be opened or run. Nothing is deleted - you can restore it later from the "
                   "Quarantine tab.")
        notes = [self._large_file_note(allowed)]
        if refused:
            notes.append("Skipped, never touched: " + self._refused_text(refused))
        if not dialogs.confirm(self, f"Quarantine {n} file(s)?", message, "Quarantine",
                               items=[i["file_path"] for i in allowed], details="  ".join(filter(None, notes))):
            return []
        return self._run_quarantine(allowed, refused, tab)

    def quarantine_checked(self):
        tab = self.tabs["Virus"]
        checked = tab.checked_payloads()
        if not checked:
            tab.set_status("// tick at least one file first", theme.TEXT_DIM)
            return
        for item in self.quarantine_files(checked, tab):
            self._resolve_virus_item(item)
        self.refresh()  # the status line is kept

    def _ignore_refusal(self, item):
        path = item["file_path"]
        if not os.path.isfile(path):
            return "the file no longer exists"
        current = compute_sha256(path)
        if current is None:
            return "the file can't be read"
        if item.get("hash") and current != item["hash"]:
            return "the file changed since it was flagged - scan it again first"
        item["current_hash"] = current
        return None

    def ignore_checked(self):
        tab = self.tabs["Virus"]
        checked = tab.checked_payloads()
        if not checked:
            tab.set_status("// tick at least one file first", theme.TEXT_DIM)
            return
        allowed, refused = [], []
        for item in checked:
            reason = self._ignore_refusal(item)
            (allowed.append(item) if reason is None else refused.append((item["file_path"], reason)))
        if not allowed:
            tab.set_status("// " + self._refused_text(refused), theme.WARN)
            return
        n = len(allowed)
        message = ("DEVADARA will stop flagging these files. They stay where they are and are not "
                   "changed. Only this exact content is ignored: if a file changes, it will be "
                   "scanned again. Only ignore a file you trust.")
        notes = []
        known = sum(1 for i in allowed if i.get("tier") == "known_bad")
        if known:
            notes.append(f"WARNING: {known} of these matched DEVADARA's list of known threats.")
        if refused:
            notes.append("Skipped: " + self._refused_text(refused))
        if not dialogs.confirm(self, f"Ignore {n} file(s)?", message, "Ignore",
                               items=[i["file_path"] for i in allowed], details="  ".join(notes)):
            return
        for item in allowed:
            ignore_list.add(item["file_path"], item["current_hash"], threat_name=item.get("threat"))
            self._resolve_virus_item(item)
        self.refresh()
        text = f"// ignoring {n} file(s) from now on (only while their content stays the same)"
        if refused:
            text += " — " + self._refused_text(refused)
        tab.set_status(text, theme.NEON)

    # ─── Startup tab ───

    def review_startup(self):
        """One entry at a time: explain what the entry does, then (after the
        warning) quarantine its TARGET FILE. The registry value, scheduled
        task or service itself is never changed - afterwards it points to a
        missing file, which is harmless, and the user can remove it."""
        tab = self.tabs["Startup"]
        checked = tab.checked_payloads()
        if len(checked) != 1:
            tab.set_status("// tick exactly one startup entry to review", theme.TEXT_DIM)
            return
        entry = checked[0]
        target = entry.get("resolved_path") or ""
        scan = entry.get("scan") or {}
        item = {"file_path": target, "hash": scan.get("hash"), "tier": scan.get("tier"),
                "threat": reason_text(scan) or f"Startup entry target ({entry.get('name') or entry.get('location')})"}
        allowed, refused = self._partition_for_quarantine([item])
        if not allowed:
            reason = refused[0][1]
            tab.set_status(f"// target not quarantined — {reason}", theme.WARN)
            return
        name = entry.get("name") or entry.get("location") or "startup entry"
        hint = STARTUP_REMOVAL_HINTS.get(entry.get("source"), "the place it is registered")
        message = ("Windows starts the target file below automatically. Reviewing this entry "
                   "QUARANTINES THAT TARGET FILE: it is encrypted and moved into quarantine "
                   "(restorable later from the Quarantine tab). The startup entry itself is NOT "
                   "changed or deleted - afterwards it points to a missing file, which is harmless. "
                   f"To remove the entry yourself: {hint}.")
        notes = [self._large_file_note(allowed)]
        if any(_norm(target).startswith(pf + os.sep) for pf in PROGRAM_FILES):
            notes.append("This target is an installed program (Program Files) - make sure it isn't "
                         "something you use.")
        details = "  ".join(filter(None, notes))
        items = [f"Entry:  {name}", f"Type:  {entry.get('source', '?')}",
                 f"Location:  {entry.get('location', '?')}", f"Command:  {entry.get('command', '?')}",
                 f"Target file:  {target}"]
        if not dialogs.confirm(self, f"Review startup entry: {name}", message, "Quarantine Target",
                               items=items, details=details):
            return
        for done in self._run_quarantine(allowed, [], tab):
            # The same file may also be on the Virus tab.
            for virus_item in self.virus_items():
                if _norm(virus_item["file_path"]) == _norm(done["file_path"]):
                    self._resolve_virus_item(virus_item)
        self.refresh()  # the row stays, now "TARGET MISSING — quarantined ..."

    # ─── Process tab ───

    def process_action(self, action):
        """Suspend / Resume / Kill one ticked program: the Phase 4 refusal
        rules first (process_guard), then the shared warning, then
        ProcessGuard.perform() - which re-checks everything right before it
        acts and logs every attempt."""
        tab = self.tabs["Process"]
        checked = tab.checked_payloads()
        if len(checked) != 1:
            tab.set_status("// tick exactly one program", theme.TEXT_DIM)
            return
        proc = checked[0]
        reason = refusal_reason(proc)
        if reason is None and not still_same_process(proc):
            reason = "it has exited or its PID was reused"
        if reason is None and action == "resume" and not self._guard.is_suspended(proc):
            reason = "it wasn't suspended by DEVADARA"
        if reason is not None:
            tab.set_status(f"// {action} refused — {reason}", theme.WARN)
            return
        if not dialogs.confirm_process_action(self, action, proc):
            return
        ok, message = self._guard.perform(action, proc)
        self.refresh()
        tab.set_status(f"// {proc.get('name')} (PID {proc['pid']}): {message}",
                       theme.NEON if ok else theme.WARN)

    # ─── Quarantine tab ───

    @staticmethod
    def _restore_refusal(entry):
        destination = entry.get("original_path")
        if not destination:
            return "its original location isn't recorded"
        if os.path.exists(destination):
            return "a file already exists at its original location"
        return None

    def restore_checked(self):
        tab = self.tabs["Quarantine"]
        checked = tab.checked_payloads()
        if not checked:
            tab.set_status("// tick at least one file first", theme.TEXT_DIM)
            return
        allowed, refused = [], []
        for entry in checked:
            reason = self._restore_refusal(entry)
            (allowed.append(entry) if reason is None else refused.append((entry["original_path"], reason)))
        if not allowed:
            tab.set_status("// " + self._refused_text(refused), theme.WARN)
            return
        n = len(allowed)
        message = ("This decrypts each file and puts it back at its original location, where it "
                   "can be opened and run again. Only restore a file you are sure is safe. If it "
                   "was flagged by its fingerprint, the next scan will flag it again unless you "
                   "also choose Ignore for it on the Virus tab.")
        details = ("Skipped, left in quarantine: " + self._refused_text(refused)) if refused else ""
        if not dialogs.confirm(self, f"Restore {n} file(s) from quarantine?", message, "Restore",
                               items=[e["original_path"] for e in allowed], details=details):
            return
        done, failed = [], []
        for entry in allowed:
            (done if quarantine.restore_file(entry["id"]) else failed).append(entry)
        self.refresh()
        text = f"// restored {len(done)} file(s) to their original location"
        if failed:
            text += f" — {len(failed)} couldn't be restored (left in quarantine)"
        if refused:
            text += " — " + self._refused_text(refused)
        tab.set_status(text, theme.WARN if failed else theme.NEON)

    def delete_checked(self):
        tab = self.tabs["Quarantine"]
        checked = tab.checked_payloads()
        if not checked:
            tab.set_status("// tick at least one file first", theme.TEXT_DIM)
            return
        n = len(checked)
        message = ("This permanently erases the encrypted copies from quarantine. They can NOT be "
                   "restored afterwards - this cannot be undone.")
        if not dialogs.confirm(self, f"Permanently delete {n} quarantined file(s)?", message,
                               "Delete Permanently", items=[e.get("original_path") or e["id"] for e in checked],
                               typed_word="DELETE"):
            return
        done = [e for e in checked if quarantine.delete_permanently(e["id"])]
        self.refresh()
        failed = n - len(done)
        tab.set_status(f"// permanently deleted {len(done)} file(s)"
                       + (f" — {failed} couldn't be deleted" if failed else ""),
                       theme.WARN if failed else theme.NEON)

    # ─── Hidden tab ───

    def unhide_checked(self):
        tab = self.tabs["Hidden"]
        checked = tab.checked_payloads()
        if not checked:
            tab.set_status("// tick at least one file first", theme.TEXT_DIM)
            return
        self._unhide(checked, bulk=False)

    def unhide_all(self):
        tab = self.tabs["Hidden"]
        everything = tab.payloads()
        if not everything:
            tab.set_status("// nothing to unhide", theme.TEXT_DIM)
            return
        self._unhide(everything, bulk=True)

    def _unhide(self, paths, bulk):
        tab = self.tabs["Hidden"]
        allowed, refused = self._split_by_refusal(paths, hidden_file_scanner.unhide_refusal_reason)
        if not allowed:
            tab.set_status("// " + self._refused_text(refused), theme.WARN)
            return
        n = len(allowed)
        details = ("Skipped, never changed: " + self._refused_text(refused)) if refused else ""
        if bulk:
            ok = dialogs.confirm(
                self, f"Unhide ALL {n} hidden file(s)?",
                self.UNHIDE_MESSAGE + f" This changes every one of the {n} files listed.",
                "Unhide All", items=allowed, details=details,
                tick_label=f"I understand this unhides {n} file(s) at once")
        else:
            ok = dialogs.confirm(self, f"Unhide {n} file(s)?", self.UNHIDE_MESSAGE, "Unhide",
                                 items=allowed, details=details)
        if not ok:
            return
        done, failed = [], []
        for path in allowed:
            (done if hidden_file_scanner.unhide(path) else failed).append(path)
        self.refresh()
        text = f"// unhid {len(done)} file(s)"
        if failed:
            text += f" — {len(failed)} couldn't be changed (no permission?)"
        if refused:
            text += " — " + self._refused_text(refused)
        tab.set_status(text, theme.WARN if failed else theme.NEON)

    def open_location(self, path):
        exists = os.path.isfile(path)
        message = ("This opens File Explorer at this file's location and highlights it. "
                   "It does not open or run the file." if exists else
                   "This file is no longer there. File Explorer will open the nearest folder "
                   "that still exists. Nothing is opened or run.")
        if not dialogs.confirm(self, "Open in File Explorer?", message, "Open in Explorer", items=[path]):
            return False
        return open_in_explorer(path)
