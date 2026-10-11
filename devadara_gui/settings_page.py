"""
settings_page.py

The Settings page: the mockup's left settings nav + one pane per tab
(assets/deepseek_html_20260917_f4ed9f.html, .settings-layout), with the
owner's three tabs - General, Exceptions, About. Only General has content
so far; the other two say "coming soon".

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
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from devadara import scan_log
from devadara_gui import config_store as config, dialogs, theme
from devadara_gui.components import Button, Card, PageHeader, RadioItem, ToggleSwitch

TABS = ["General", "Exceptions", "About"]
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


class SettingsPage(QWidget):
    # Settings › General › Auto-delete changed: AUTO_DELETE_ASK / _NEVER.
    auto_delete_changed = Signal(str)
    # The scan log was just emptied - Results and Dashboard re-read it.
    history_cleared = Signal()

    def __init__(self, config_store, parent=None):
        super().__init__(parent)
        self._config = config_store

        # Scrolls (hidden bars, like the Protection page) instead of
        # squashing the rows at the window's minimum height.
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(40, 30, 40, 60)
        layout.setSpacing(20)
        layout.addWidget(PageHeader("Settings", "// configure system preferences"))

        settings_layout = QHBoxLayout()
        settings_layout.setSpacing(NAV_GAP)
        settings_layout.addLayout(self._build_nav(), 0)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_general())
        self.stack.addWidget(self._coming_soon("Exceptions"))
        self.stack.addWidget(self._coming_soon("About"))
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

    def _coming_soon(self, title):
        card = Card(title)
        label = QLabel("// coming soon")
        label.setFont(theme.letter_spaced_font(size=8, spacing=1))
        label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        card.content_layout.addWidget(label)
        # The stack gives every pane General's height - keep this short card
        # at the top instead of stretched to fill it.
        pane = QWidget()
        pane_layout = QVBoxLayout(pane)
        pane_layout.setContentsMargins(0, 0, 0, 0)
        pane_layout.addWidget(card)
        pane_layout.addStretch(1)
        return pane

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
