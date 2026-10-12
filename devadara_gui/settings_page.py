"""
settings_page.py

The Settings page: the mockup's left settings nav + one pane per tab
(assets/deepseek_html_20260917_f4ed9f.html, .settings-layout), with the
owner's three tabs - General, Exceptions, About.

General - every control is real and saved in gui_state.json (STATE_DIR,
config_store.py - runtime state, never in the integrity manifest):

  - Notifications (tray_notifications): the "scan finished" and "item(s)
    flagged" tray messages only. Never hides anything inside the app; the
    ransomware-alert and app-integrity tray messages always show.
  - Auto-delete (auto_delete): "Ask me every time" (default - Delete
    Permanently behind its typed-DELETE confirmation, as before) or "Never"
    (every Delete action in the GUI disabled; Quarantine still works).
    There is no third option: nothing in DEVADARA ever deletes on its own.
  - Clear scan history: after a confirmation (Cancel is the default),
    empties data/scan_log.jsonl - and nothing else.

Exceptions - the ignore list (devadara/ignore_list.py, data/ignored_files.json):

  - Ignored files: every entry with its fingerprint status, a search box,
    and Remove (after a confirmation) - the entry only; the file itself is
    never touched, and from then on it's scanned normally again.
  - Add a file: a picked FILE is pinned to path + fingerprint through the
    same ignore_list.add() the Results page's Ignore uses, after a
    confirmation. DEVADARA's own folders are refused; Windows system files
    get an extra warning.

About - one card, one row each: app, version (devadara/version.py),
developer, app integrity (the Dashboard's own check and wording, run by
MainWindow's IntegrityChecker on its thread), the data folder (STATE_DIR),
privacy, and two "coming in a future version" buttons. Nothing on this tab
goes online - no URLs, no browser, no network calls.
"""

import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from devadara import app_paths, ignore_list, memory, scan_log
from devadara.hash_scanner import compute_sha256
from devadara.version import APP_VERSION
from devadara_gui import config_store as config, dialogs, theme
from devadara_gui.dashboard_page import integrity_summary
from devadara_gui.components import Button, Card, ElidedLabel, PageHeader, RadioItem, ToggleSwitch

TABS = ["General", "Exceptions", "About"]
PAGE_SUBTITLE = "// configure system preferences"
TAB_SUBTITLES = {"Exceptions": "// ignored files · add or remove them here",
                 "About": "// about DEVADARA"}
COMING_LATER = "// coming in a future version"

SYSTEM_ROOT = os.path.normcase(os.path.abspath(os.environ.get("SystemRoot", r"C:\Windows")))

# Fingerprint status of an ignored file: (text, theme colour token).
FINGERPRINT_MATCH = ("Fingerprint matches — ignored", "NEON")
FINGERPRINT_CHANGED = ("Changed since ignored — scanned normally", "WARN")
FINGERPRINT_MISSING = ("File missing", "TEXT_DIM")
FINGERPRINT_UNREADABLE = ("Can't read file", "TEXT_DIM")


def pick_file(parent):
    """The Add-a-file picker: one existing FILE, never a folder. Returns a
    path or "" on cancel. (Tests replace this - the native Windows picker
    can't be clicked by Qt.)"""
    path, _filter = QFileDialog.getOpenFileName(parent, "Add a file to the ignore list")
    return path


def _norm_real(path):
    return os.path.normcase(os.path.realpath(path))


def _inside(path, folder):
    folder = _norm_real(folder)
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


def in_devadara_folder(path):
    """Inside the install folder, the bundled program files or DEVADARA's
    own runtime-state folder (quarantine, logs, the ignore list itself)."""
    real = _norm_real(path)
    return any(_inside(real, folder) for folder in
               (app_paths.INSTALL_ROOT, app_paths.APP_DIR, app_paths.STATE_DIR))


def in_system_folder(path):
    return _inside(_norm_real(path), SYSTEM_ROOT)


def _discard(layout, widget):
    """Take a rebuilt row out NOW - deleteLater() alone leaves it in the
    layout (and on screen) until the event loop gets round to it."""
    widget.hide()
    layout.removeWidget(widget)
    widget.deleteLater()


NAV_WIDTH = 180   # .settings-nav { width: 180px }
NAV_GAP = 24      # .settings-layout { gap: 24px }
ROW_PADDING = 14  # .setting-row { padding: 14px 0 }

AUTO_DELETE_CHOICES = [
    (config.AUTO_DELETE_ASK, "Ask me every time"),
    (config.AUTO_DELETE_NEVER, "Never"),
]


def _row_divider():
    line = QFrame()
    line.setObjectName("settingRowDivider")
    line.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
    return line


def _text_column(name, description):
    """.setting-name + .setting-desc"""
    column = QVBoxLayout()
    column.setContentsMargins(0, 0, 0, 0)
    column.setSpacing(3)
    name_label = QLabel(name.upper())
    name_label.setObjectName("settingName")
    name_label.setFont(theme.letter_spaced_font(size=9, bold=True, spacing=1.5))
    name_label.setWordWrap(True)
    column.addWidget(name_label)
    desc_label = QLabel(description)
    desc_label.setObjectName("settingDesc")
    desc_label.setFont(theme.letter_spaced_font(size=8, spacing=0.5))
    desc_label.setWordWrap(True)
    column.addWidget(desc_label)
    return column


class CurrentPaneStack(QWidget):
    """The tab panes, only the current one shown - sized by that pane alone.
    A QStackedWidget takes the largest size of ALL its panes: the tall
    Exceptions list stretched General's card, and the wide General pushed
    Exceptions past the window edge at the 960px minimum width. Hidden
    widgets take no space in a layout, so this has neither problem. Same
    method names as QStackedWidget for what this page uses."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._panes = []
        self._index = -1
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)

    def addWidget(self, pane):
        self._panes.append(pane)
        self._layout.addWidget(pane)
        if self._index < 0:
            self._index = 0
        pane.setVisible(len(self._panes) - 1 == self._index)

    def setCurrentIndex(self, index):
        self._index = index
        for i, pane in enumerate(self._panes):
            pane.setVisible(i == index)

    def currentIndex(self):
        return self._index

    def currentWidget(self):
        return self._panes[self._index] if self._panes else None

    def widget(self, index):
        return self._panes[index]

    def count(self):
        return len(self._panes)


class SettingsPage(QWidget):
    # Settings › General › Auto-delete changed: AUTO_DELETE_ASK / _NEVER.
    auto_delete_changed = Signal(str)
    # The scan log was just emptied - Results and Dashboard re-read it.
    history_cleared = Signal()
    # An entry was added to / removed from the ignore list.
    ignore_list_changed = Signal()
    # About › App integrity "Check now" - MainWindow runs the existing
    # IntegrityChecker and feeds the result back (set_integrity_*).
    integrity_check_requested = Signal()

    def __init__(self, config_store, parent=None):
        super().__init__(parent)
        self._config = config_store
        self._fingerprints = {}  # path -> ((mtime_ns, size), sha256) - no re-hash per filter

        # Scrolls (hidden bars, like the Protection page) instead of
        # squashing the rows at the window's minimum height.
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(40, 30, 40, 60)
        layout.setSpacing(20)
        self.header = PageHeader("Settings", PAGE_SUBTITLE)
        layout.addWidget(self.header)

        settings_layout = QHBoxLayout()
        settings_layout.setSpacing(NAV_GAP)
        settings_layout.addLayout(self._build_nav(), 0)

        self.stack = CurrentPaneStack()
        self.stack.addWidget(self._build_general())
        self.stack.addWidget(self._build_exceptions())
        self.stack.addWidget(self._build_about())
        settings_layout.addWidget(self.stack, 1, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(settings_layout)
        layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidget(content)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(scroll)

    # ─── nav ───

    def _build_nav(self):
        nav = QVBoxLayout()
        nav.setContentsMargins(0, 0, 0, 0)
        nav.setSpacing(2)
        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        self.nav_buttons = []
        for index, name in enumerate(TABS):
            button = QPushButton(name.upper())
            button.setObjectName("settingsNavItem")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setFont(theme.letter_spaced_font(size=8, bold=True, spacing=2))
            button.setFixedWidth(NAV_WIDTH)
            button.toggled.connect(lambda checked, b=button: b.setGraphicsEffect(
                theme.glow_effect(theme.NEON, blur=10) if checked else None))
            self._nav_group.addButton(button, index)
            nav.addWidget(button)
            self.nav_buttons.append(button)
        nav.addStretch(1)
        self._nav_group.idClicked.connect(self.show_tab)
        self.nav_buttons[0].setChecked(True)
        return nav

    def show_tab(self, index):
        self.nav_buttons[index].setChecked(True)
        self.stack.setCurrentIndex(index)
        self.header.sub_label.setText(TAB_SUBTITLES.get(TABS[index], PAGE_SUBTITLE))
        if TABS[index] == "Exceptions":
            self.refresh_exceptions()  # Results' Ignore may have added entries

    def showEvent(self, event):
        super().showEvent(event)
        if self.stack.currentIndex() == TABS.index("Exceptions"):
            self.refresh_exceptions()

    # ─── General ───

    def _build_general(self):
        card = Card("General", badge="[3]")
        rows = card.content_layout
        rows.setSpacing(0)

        # 1. Notifications
        widget, row = self._row()
        row.addLayout(_text_column(
            "Notifications",
            "// tray pop-ups when a scan finishes or something is flagged — "
            "never hides anything inside the app"), 1)
        self.notifications_toggle = ToggleSwitch(checked=config.tray_notifications_on(self._config))
        self.notifications_toggle.setToolTip(
            "Ransomware-activity and app-integrity alerts always show in the tray.")
        self.notifications_toggle.toggled.connect(self._on_notifications_toggled)
        row.addWidget(self.notifications_toggle, 0, Qt.AlignmentFlag.AlignVCenter)
        rows.addWidget(widget)
        rows.addWidget(_row_divider())

        # 2. Auto-delete - text on top, the two choices under it
        block = QWidget()
        column = QVBoxLayout(block)
        column.setContentsMargins(0, ROW_PADDING, 0, ROW_PADDING)
        column.setSpacing(10)
        column.addLayout(_text_column(
            "Auto-delete",
            "// \"never\" turns off every delete button — quarantine still works. "
            "Nothing is ever deleted automatically"))
        choices = QHBoxLayout()
        choices.setSpacing(10)
        self._auto_delete_group = QButtonGroup(self)
        self._auto_delete_group.setExclusive(True)
        self.auto_delete_buttons = {}
        current = (config.AUTO_DELETE_ASK if config.delete_allowed(self._config)
                   else config.AUTO_DELETE_NEVER)
        for value, label in AUTO_DELETE_CHOICES:
            button = RadioItem(label)
            self._auto_delete_group.addButton(button)
            choices.addWidget(button)
            self.auto_delete_buttons[value] = button
            if value == current:
                button.setChecked(True)
            button.toggled.connect(lambda checked, v=value: checked and self._on_auto_delete(v))
        choices.addStretch(1)
        column.addLayout(choices)
        rows.addWidget(block)
        rows.addWidget(_row_divider())

        # 3. Clear scan history
        widget, row = self._row()
        row.addLayout(_text_column(
            "Clear scan history",
            "// empties the auto-scan findings log — quarantine, ignore list and "
            "last scan dates are kept"), 1)
        self.clear_history_button = Button("Clear history")
        self.clear_history_button.clicked.connect(self.clear_history)
        row.addWidget(self.clear_history_button, 0, Qt.AlignmentFlag.AlignVCenter)
        rows.addWidget(widget)

        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setFont(theme.letter_spaced_font(size=8, spacing=0.3))
        self.status.hide()
        rows.addWidget(self.status)
        return card

    @staticmethod
    def _row():
        """.setting-row: text left, control right. Returns (widget, layout)."""
        widget = QWidget()
        row = QHBoxLayout(widget)
        row.setContentsMargins(0, ROW_PADDING, 0, ROW_PADDING)
        row.setSpacing(20)
        return widget, row

    # ─── About ───

    def _build_about(self):
        card = Card("About")
        rows = card.content_layout
        rows.setSpacing(0)

        def text_row(name, description):
            widget, row = self._row()
            row.addLayout(_text_column(name, description), 1)
            rows.addWidget(widget)
            rows.addWidget(_row_divider())

        text_row("DEVADARA", "// offline, privacy-first antivirus")
        text_row("Version", APP_VERSION)
        text_row("Developer", "Chavindu Jayawardana")

        # App integrity - the Dashboard's check and wording, not a second one
        widget, row = self._row()
        # Wraps instead of eliding: the Dashboard's one-line strip has to
        # elide, this row has the room to show the whole status.
        self.integrity_status = QLabel()
        self.integrity_status.setWordWrap(True)
        row.addLayout(self._label_over("App integrity", self.integrity_status), 1)
        self.integrity_button = Button("Check now")
        self.integrity_button.setToolTip("Compare DEVADARA's own program files with its signed "
                                         "manifest again. Only reads files - changes nothing.")
        self.integrity_button.clicked.connect(self.integrity_check_requested)
        row.addWidget(self.integrity_button, 0, Qt.AlignmentFlag.AlignVCenter)
        rows.addWidget(widget)
        rows.addWidget(_row_divider())
        self._show_integrity("WAITING — the self-check runs shortly after startup", "TEXT_DIM",
                             "DEVADARA compares its own program files with its signed manifest.")

        # Data folder - plain text, elided in the middle, full path in the tooltip
        widget, row = self._row()
        self.data_folder = ElidedLabel(app_paths.STATE_DIR)
        self.data_folder.setObjectName("settingDesc")
        row.addLayout(self._label_over("Data folder", self.data_folder), 1)
        rows.addWidget(widget)
        rows.addWidget(_row_divider())

        text_row("Privacy", "100% offline. Nothing is uploaded. Your files stay on your computer.")

        self.update_button, self.update_note = self._coming_later_row(
            rows, "Updates", "Check for Update")
        rows.addWidget(_row_divider())
        self.report_button, self.report_note = self._coming_later_row(
            rows, "Report", "Report a suspicious file")

        # Keep the card at the top instead of stretched to the pane's height.
        pane = QWidget()
        pane_layout = QVBoxLayout(pane)
        pane_layout.setContentsMargins(0, 0, 0, 0)
        pane_layout.addWidget(card)
        pane_layout.addStretch(1)
        return pane

    @staticmethod
    def _name_label(name):
        """_text_column()'s .setting-name label."""
        label = QLabel(name.upper())
        label.setObjectName("settingName")
        label.setFont(theme.letter_spaced_font(size=9, bold=True, spacing=1.5))
        return label

    def _label_over(self, name, value_label):
        """_text_column()'s look with a live label as the value."""
        column = QVBoxLayout()
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(3)
        column.addWidget(self._name_label(name))
        value_label.setFont(theme.letter_spaced_font(size=8, spacing=0.5))
        column.addWidget(value_label)
        return column

    def _coming_later_row(self, rows, name, button_text):
        """A row whose button only shows "coming in a future version" under
        it - nothing else, and never anything online."""
        block = QWidget()
        column = QVBoxLayout(block)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        widget, row = self._row()
        row.addWidget(self._name_label(name), 1, Qt.AlignmentFlag.AlignVCenter)
        button = Button(button_text)
        row.addWidget(button, 0, Qt.AlignmentFlag.AlignVCenter)
        column.addWidget(widget)
        note = QLabel(COMING_LATER)
        note.setFont(theme.letter_spaced_font(size=8, spacing=1))
        note.setStyleSheet(f"color: {theme.TEXT_DIM};")
        note.setContentsMargins(0, 0, 0, ROW_PADDING)
        note.hide()
        column.addWidget(note)
        button.clicked.connect(note.show)
        rows.addWidget(block)
        return button, note

    def _show_integrity(self, text, token, tooltip):
        self.integrity_status.setText(text)
        self.integrity_status.setToolTip(tooltip)
        self.integrity_status.setStyleSheet(f"color: {getattr(theme, token)};")

    def set_integrity_checking(self):
        """IntegrityChecker.started - the Dashboard's wording."""
        self.integrity_button.setEnabled(False)
        self._show_integrity("CHECKING — comparing DEVADARA's files with its signed manifest…",
                             "TEXT_DIM", "Only reads files - changes nothing.")

    def set_integrity_result(self, result):
        """IntegrityChecker.finished - the Dashboard's integrity_summary().
        Never raises on an odd result."""
        self.integrity_button.setEnabled(True)
        try:
            self._show_integrity(*integrity_summary(result or {}))
        except Exception as exc:
            self._show_integrity(f"CHECK COULDN'T RUN — {exc}", "WARN", "")

    # ─── Exceptions ───

    @staticmethod
    def _card_subtitle(text):
        label = QLabel(text)
        label.setObjectName("settingDesc")
        label.setFont(theme.letter_spaced_font(size=8, spacing=0.5))
        label.setWordWrap(True)
        return label

    @staticmethod
    def _dim_note(text):
        label = QLabel(text)
        label.setFont(theme.letter_spaced_font(size=8, spacing=1))
        label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        label.setWordWrap(True)
        return label

    def _build_exceptions(self):
        pane = QWidget()
        pane_layout = QVBoxLayout(pane)
        pane_layout.setContentsMargins(0, 0, 0, 0)
        pane_layout.setSpacing(20)

        # 1. Ignored files
        card = Card("Ignored files")
        rows = card.content_layout
        rows.addWidget(self._card_subtitle("// files you chose to ignore · remove to scan again"))
        self.ignored_search = QLineEdit()
        self.ignored_search.setObjectName("exceptionsSearch")
        self.ignored_search.setPlaceholderText("Search by name or path")
        self.ignored_search.setFont(theme.letter_spaced_font(size=9, spacing=0.3))
        self.ignored_search.setClearButtonEnabled(True)
        self.ignored_search.textChanged.connect(self._render_ignored)
        rows.addWidget(self.ignored_search)

        list_widget = QWidget()
        self._ignored_list = QVBoxLayout(list_widget)
        self._ignored_list.setContentsMargins(0, 0, 0, 0)
        self._ignored_list.setSpacing(0)
        rows.addWidget(list_widget)
        self.ignored_empty = self._dim_note("")
        rows.addWidget(self.ignored_empty)
        self.ignored_row_widgets = []  # (entry, row widget, Remove button) currently shown
        rows.addWidget(_row_divider())

        # 2. Add a file
        widget, row = self._row()
        row.addLayout(_text_column("Add a file", "// add a trusted file · files only"), 1)
        self.add_file_button = Button("Add a file")
        self.add_file_button.clicked.connect(self.add_file)
        row.addWidget(self.add_file_button, 0, Qt.AlignmentFlag.AlignVCenter)
        rows.addWidget(widget)

        self.exceptions_status = QLabel()
        self.exceptions_status.setWordWrap(True)
        self.exceptions_status.setFont(theme.letter_spaced_font(size=8, spacing=0.3))
        self.exceptions_status.hide()
        rows.addWidget(self.exceptions_status)
        pane_layout.addWidget(card)
        pane_layout.addStretch(1)

        self.refresh_exceptions()
        return pane

    def _fingerprint_status(self, entry):
        path = entry.get("path") or ""
        try:
            if not os.path.isfile(path):
                return FINGERPRINT_MISSING
            stat = os.stat(path)
        except OSError:
            return FINGERPRINT_MISSING
        stamp = (stat.st_mtime_ns, stat.st_size)
        cached = self._fingerprints.get(path)
        if cached and cached[0] == stamp:
            current = cached[1]
        else:
            current = compute_sha256(path)
            self._fingerprints[path] = (stamp, current)
        if current is None:
            return FINGERPRINT_UNREADABLE
        return FINGERPRINT_MATCH if current == entry.get("hash") else FINGERPRINT_CHANGED

    def refresh_exceptions(self):
        """Re-read the ignore list from disk. A missing or broken file shows
        as empty - never an error."""
        try:
            entries = ignore_list.list_ignored()
        except Exception:  # any unreadable state: show the empty list
            entries = []
        entries = sorted(entries, key=lambda e: (os.path.basename(e["path"]).lower(), e["path"].lower()))
        self._ignored_entries = [(e, self._fingerprint_status(e)) for e in entries]
        self._ignore_file_broken = ignore_list.file_status() == "broken"
        self._render_ignored()

    def _render_ignored(self, *_):
        for _entry, widget, _button in self.ignored_row_widgets:
            _discard(self._ignored_list, widget)
        self.ignored_row_widgets = []
        needle = self.ignored_search.text().strip().lower()
        shown = [(e, s) for e, s in self._ignored_entries
                 if not needle or needle in os.path.basename(e["path"]).lower()
                 or needle in e["path"].lower()]
        for index, (entry, status) in enumerate(shown):
            widget = self._ignored_row(entry, status, first=index == 0)
            self._ignored_list.addWidget(widget)
        if not self._ignored_entries:
            text = "// no ignored files yet"
            if self._ignore_file_broken:
                text += " (ignored_files.json couldn't be read — shown as empty)"
            self.ignored_empty.setText(text)
        elif not shown:
            self.ignored_empty.setText("// no matches found")
        self.ignored_empty.setVisible(not shown)

    def _ignored_row(self, entry, status, first):
        path = entry["path"]
        widget = QWidget()
        outer = QVBoxLayout(widget)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        if not first:
            outer.addWidget(_row_divider())
        row = QHBoxLayout()
        row.setContentsMargins(0, 10, 0, 10)
        row.setSpacing(16)
        column = QVBoxLayout()
        column.setSpacing(3)
        name = ElidedLabel(os.path.basename(path) or path)
        name.setObjectName("settingName")
        name.setFont(theme.letter_spaced_font(size=9, bold=True, spacing=0.5))
        column.addWidget(name)
        full_path = ElidedLabel(path)
        full_path.setObjectName("settingDesc")
        full_path.setFont(theme.letter_spaced_font(size=8, spacing=0.3))
        column.addWidget(full_path)
        text, token = status
        status_label = QLabel(text)
        status_label.setFont(theme.letter_spaced_font(size=8, spacing=0.3))
        status_label.setStyleSheet(f"color: {getattr(theme, token)};")
        status_label.setWordWrap(True)
        column.addWidget(status_label)
        row.addLayout(column, 1)
        button = Button("Remove")
        button.setToolTip("Take this file off the ignore list - the file itself is not touched.")
        button.clicked.connect(lambda _=False, e=entry: self.remove_ignored(e))
        row.addWidget(button, 0, Qt.AlignmentFlag.AlignVCenter)
        outer.addLayout(row)
        self.ignored_row_widgets.append((entry, widget, button))
        return widget

    def set_exceptions_status(self, text, color=None):
        self.exceptions_status.setText(text)
        self.exceptions_status.setStyleSheet(f"color: {color or theme.TEXT_DIM};")
        self.exceptions_status.setVisible(bool(text))

    def remove_ignored(self, entry):
        """Confirm, then take ONE entry off the ignore list. The file itself
        is never touched; from now on it's scanned like any other file."""
        path = entry["path"]
        name = os.path.basename(path) or path
        message = ("DEVADARA will stop ignoring this file and scan it normally again - it may be "
                   "flagged by the next scan. The file itself is not touched, moved or deleted.")
        if not dialogs.confirm(self, f"Remove {name} from the ignore list?", message,
                               "Remove", items=[path]):
            return
        try:
            removed = ignore_list.remove(path)
        except OSError:
            self.set_exceptions_status("// couldn't update the ignore list (file in use or no access?)",
                                       theme.WARN)
            return
        self.refresh_exceptions()
        self.ignore_list_changed.emit()
        if removed:
            self.set_exceptions_status(f"// {name} removed from the ignore list — it will be scanned "
                                       "normally again", theme.NEON)
        else:
            self.set_exceptions_status(f"// {name} was already off the ignore list", theme.TEXT_DIM)

    def add_file(self):
        """Pick a file, refuse DEVADARA's own folders and duplicates, warn
        about Windows system files, confirm, then ignore_list.add() - the
        same path + fingerprint entry the Results page's Ignore makes."""
        path = pick_file(self)
        if not path:
            return
        path = os.path.abspath(path)
        name = os.path.basename(path) or path
        if not os.path.isfile(path):
            self.set_exceptions_status(f"// {name} is not a file — only files can be added", theme.WARN)
            return
        if in_devadara_folder(path):
            self.set_exceptions_status(
                f"// blocked — {name} is inside DEVADARA's own folder. DEVADARA's files are checked "
                "against its signed file list instead and can't be added here.", theme.WARN)
            return
        file_hash = compute_sha256(path)
        if file_hash is None:
            self.set_exceptions_status(f"// can't read {name} (in use or no access?) — not added",
                                       theme.WARN)
            return
        existing = ignore_list.is_listed(path)
        if existing is not None:
            if existing.get("hash") == file_hash:
                text = f"// {name} is already in the list — not added again"
            else:
                text = (f"// {name} is already in the list, but its content changed since — remove "
                        "it and add it again to trust the new content")
            self.set_exceptions_status(text, theme.TEXT_DIM)
            return

        system = in_system_folder(path)
        message = ("DEVADARA will stop flagging this file. Only this exact content is ignored: if the "
                   "file changes, it will be scanned again. The file itself is not changed. Only add "
                   "a file you trust.")
        notes = []
        if system:
            notes.append("WARNING: this file is inside the Windows system folder. Malware often hides "
                         "there under a Windows-like name - only continue if you are sure.")
        try:
            known_bad = memory.get_combined_known_bad_hashes()
        except Exception:
            known_bad = {}
        if isinstance(known_bad, dict) and file_hash in known_bad:
            notes.append("WARNING: this file matches DEVADARA's list of known threats.")
        title = (f"Add a Windows system file ({name}) to the ignore list?" if system
                 else f"Add {name} to the ignore list?")
        if not dialogs.confirm(self, title, message, "Add file", items=[path],
                               details="  ".join(notes)):
            return
        try:
            ignore_list.add(path, file_hash)
        except OSError:
            self.set_exceptions_status("// couldn't update the ignore list (file in use or no access?)",
                                       theme.WARN)
            return
        self.refresh_exceptions()
        self.ignore_list_changed.emit()
        self.set_exceptions_status(f"// {name} added — ignored from now on (only while its content "
                                   "stays the same)", theme.NEON)

    def set_status(self, text, color=None):
        self.status.setText(text)
        self.status.setStyleSheet(f"color: {color or theme.TEXT_DIM};")
        self.status.setVisible(bool(text))

    # ─── actions ───

    def _on_notifications_toggled(self, checked):
        self._config.set(config.TRAY_NOTIFICATIONS_KEY, bool(checked))

    def _on_auto_delete(self, value):
        self._config.set(config.AUTO_DELETE_KEY, value)
        self.auto_delete_changed.emit(value)

    def clear_history(self):
        """Confirm (always - also when the log is already empty, so a click
        never looks like nothing happened), then empty data/scan_log.jsonl
        - the only file touched."""
        count = len(scan_log.read_findings())
        if count:
            message = (f"This empties DEVADARA's scan history: {count} finding(s) recorded by "
                       "auto-scans (Downloads, USB, startup scan) and ransomware-like activity "
                       "alerts. They disappear from Results › Virus and from the Dashboard's "
                       "counts. This cannot be undone.")
        else:
            message = ("The scan history is already empty - there are no auto-scan findings or "
                       "ransomware-like activity alerts to clear. Clearing it changes nothing.")
        details = ("Not touched: quarantined files, the ignore list, trusted publishers, the "
                   "threat database, the last scan dates and the process action log. No file on "
                   "your PC is deleted, quarantined or marked safe.")
        if not dialogs.confirm(self, f"Clear scan history ({count} entries)?", message,
                               "Clear history", items=[scan_log.LOG_PATH], details=details):
            return
        if scan_log.clear_findings():
            self.set_status(f"// scan history cleared ({count} entries)" if count
                            else "// scan history was already empty — nothing to clear", theme.NEON)
            self.history_cleared.emit()
        else:
            self.set_status("// couldn't clear the scan history (file in use or no access?)", theme.WARN)
