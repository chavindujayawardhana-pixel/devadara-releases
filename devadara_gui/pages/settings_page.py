"""
settings_page.py

The Settings page (Section 9): its own left-hand sub-navigation, five
sections. Protection toggles here stay synchronized with the standalone
Protection page (both read/write the same devadara_gui.services.app_state)
- there is only ever one real state, never two independent copies.
"""

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from devadara_gui import theme
from devadara_gui.components import (
    Card,
    ModuleCard,
    body_secondary,
    body_text,
    hairline,
    make_label,
    page_title,
    section_title,
    toggle_row,
)
from devadara_gui.dialogs import ConfirmationDialog
from devadara_gui.icons import icon_label

SECTIONS = ["General", "Protection", "Exceptions", "Notifications", "About"]


class SettingsNavButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self._apply_style(False)

    def _apply_style(self, active):
        color = theme.TEXT_PRIMARY if active else theme.TEXT_SECONDARY
        border = f"border-left: 2px solid {theme.KELLY_GREEN};" if active else "border-left: 2px solid transparent;"
        weight = "600" if active else "500"
        self.setStyleSheet(
            f"QPushButton {{ background: transparent; border: none; {border} text-align: left; "
            f"padding: 10px 14px; color: {color}; font-size: 13px; font-weight: {weight}; }}"
            f"QPushButton:hover {{ color: {theme.TEXT_PRIMARY}; }}"
        )

    def setChecked(self, checked):
        super().setChecked(checked)
        self._apply_style(checked)


class SettingsPage(theme.PageCanvas):
    def __init__(self, app_state, parent=None):
        super().__init__(parent)
        self.app_state = app_state
        self.setObjectName("pageRoot")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(theme.PAGE_PADDING, theme.PAGE_PADDING, theme.PAGE_PADDING, theme.PAGE_PADDING)
        outer.setSpacing(theme.CARD_GAP)
        outer.addWidget(page_title("Settings"))

        body_row = QHBoxLayout()
        body_row.setSpacing(24)
        outer.addLayout(body_row, 1)

        nav_col = QVBoxLayout()
        nav_col.setSpacing(2)
        nav_widget = QWidget()
        nav_widget.setFixedWidth(180)
        nav_widget.setLayout(nav_col)
        body_row.addWidget(nav_widget)

        self.stack = QStackedWidget()
        body_row.addWidget(self.stack, 1)

        self.nav_buttons = []
        pages = [
            self._build_general(), self._build_protection(), self._build_exceptions(),
            self._build_notifications(), self._build_about(),
        ]
        for label, page in zip(SECTIONS, pages):
            btn = SettingsNavButton(label)
            btn.clicked.connect(lambda _checked=False, p=page, b=None: self._select(p))
            nav_col.addWidget(btn)
            self.nav_buttons.append(btn)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(page)
            self.stack.addWidget(scroll)
        nav_col.addStretch()

        self.nav_buttons[0].setChecked(True)
        self.stack.setCurrentIndex(0)

        self.app_state.protection_changed.connect(self._sync_protection_toggles)

    def _select(self, page):
        index = None
        for i in range(self.stack.count()):
            if self.stack.widget(i).widget() is page:
                index = i
        if index is None:
            return
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)

    # ------------------------------------------------------------------
    def _page_container(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(theme.CARD_GAP)
        layout.setContentsMargins(0, 0, 0, 0)
        return widget, layout

    def _build_general(self):
        widget, layout = self._page_container()
        card = Card()
        row, self.startup_toggle = toggle_row("Start DEVADARA with Windows")
        self.startup_toggle.setChecked(self.app_state.is_startup_enabled())
        self.startup_toggle.toggled.connect(self.app_state.set_startup_enabled)
        card.addWidget(row)
        card.addWidget(hairline())

        row, self.tray_toggle = toggle_row("Minimize to system tray")
        self.tray_toggle.setChecked(self.app_state.config.get("minimize_to_tray", False))
        self.tray_toggle.toggled.connect(lambda v: self.app_state.config.set("minimize_to_tray", v))
        card.addWidget(row)
        card.addWidget(hairline())

        row, self.notifications_master_toggle = toggle_row("Notifications")
        self.notifications_master_toggle.setChecked(self.app_state.config.get("notifications_enabled", True))
        self.notifications_master_toggle.toggled.connect(lambda v: self.app_state.config.set("notifications_enabled", v))
        card.addWidget(row)

        layout.addWidget(card)
        layout.addStretch()
        return widget

    def _build_protection(self):
        widget, layout = self._page_container()
        self.settings_master_card = ModuleCard(
            "Real-Time Protection", "Monitors files and system activity for suspicious behavior.",
            initial_state=self.app_state.is_realtime_protection_enabled(), show_status=False,
        )
        self.settings_master_card.toggled.connect(self.app_state.set_realtime_protection)
        layout.addWidget(self.settings_master_card)

        self.settings_behavior_card = ModuleCard(
            "Behavior Monitoring", "Watches Downloads for ransomware-like bursts of activity.",
            initial_state=self.app_state.is_module_enabled("behavior_monitoring"), show_status=False,
        )
        self.settings_behavior_card.toggled.connect(lambda v: self.app_state.set_module_enabled("behavior_monitoring", v))
        layout.addWidget(self.settings_behavior_card)

        self.settings_downloads_card = ModuleCard(
            "Downloads Auto-Scan", "Automatically scans every new file in Downloads.",
            initial_state=self.app_state.is_module_enabled("downloads_autoscan"), show_status=False,
        )
        self.settings_downloads_card.toggled.connect(lambda v: self.app_state.set_module_enabled("downloads_autoscan", v))
        layout.addWidget(self.settings_downloads_card)

        self.settings_usb_card = ModuleCard(
            "USB Auto-Scan", "Automatically scans removable drives when connected.",
            initial_state=self.app_state.is_module_enabled("usb_autoscan"), show_status=False,
        )
        self.settings_usb_card.toggled.connect(lambda v: self.app_state.set_module_enabled("usb_autoscan", v))
        layout.addWidget(self.settings_usb_card)

        layout.addStretch()
        return widget

    def _sync_protection_toggles(self):
        self.settings_master_card.set_checked_silently(self.app_state.is_realtime_protection_enabled())
        self.settings_behavior_card.set_checked_silently(self.app_state.is_module_enabled("behavior_monitoring"))
        self.settings_downloads_card.set_checked_silently(self.app_state.is_module_enabled("downloads_autoscan"))
        self.settings_usb_card.set_checked_silently(self.app_state.is_module_enabled("usb_autoscan"))
        self.startup_toggle.blockSignals(True)
        self.startup_toggle.setChecked(self.app_state.is_startup_enabled())
        self.startup_toggle.blockSignals(False)

    def _build_exceptions(self):
        widget, layout = self._page_container()
        card = Card()
        card.addWidget(section_title("Excluded locations"))
        self.exceptions_list_layout = QVBoxLayout()
        card.addLayout(self.exceptions_list_layout)

        add_row = QHBoxLayout()
        add_btn = QPushButton("+ Add Exception")
        add_btn.setObjectName("secondaryButton")
        add_btn.setCursor(Qt.PointingHandCursor)
        add_btn.clicked.connect(self._add_exception)
        add_row.addWidget(add_btn)
        add_row.addStretch()
        card.addLayout(add_row)

        layout.addWidget(card)
        layout.addStretch()
        self._refresh_exceptions()
        return widget

    def _refresh_exceptions(self):
        while self.exceptions_list_layout.count():
            item = self.exceptions_list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        paths = self.app_state.list_exceptions()
        if not paths:
            note = make_label(
                "No exceptions added - files and folders you exclude from scanning will appear here.",
                "metadataDisabled",
            )
            note.setWordWrap(True)
            self.exceptions_list_layout.addWidget(note)
            return

        for path in paths:
            row = QHBoxLayout()
            label = body_text(path, wrap=True)
            row.addWidget(label, 1)
            remove_btn = QPushButton("Remove")
            remove_btn.setObjectName("textButton")
            remove_btn.setCursor(Qt.PointingHandCursor)
            remove_btn.clicked.connect(lambda _checked=False, p=path: self._remove_exception(p))
            row.addWidget(remove_btn)
            row_widget = QWidget()
            row_widget.setObjectName("transparentPanel")
            row_widget.setLayout(row)
            self.exceptions_list_layout.addWidget(row_widget)
            self.exceptions_list_layout.addWidget(hairline())

    def _add_exception(self):
        path = QFileDialog.getExistingDirectory(self, "Add Folder Exception")
        if not path:
            path, _ = QFileDialog.getOpenFileName(self, "Add File Exception")
        if path:
            self.app_state.add_exception_path(path)
            self._refresh_exceptions()

    def _remove_exception(self, path):
        if ConfirmationDialog.confirm(
            self, "Remove this exception?",
            f"DEVADARA will resume scanning '{path}'.",
            confirm_label="Remove",
        ):
            self.app_state.remove_exception_path(path)
            self._refresh_exceptions()

    def _build_notifications(self):
        widget, layout = self._page_container()
        card = Card()
        specs = [
            ("Scan completed", "notify_scan_completed"),
            ("Threat detected", "notify_threat_detected"),
            ("USB scan completed", "notify_usb_scan_completed"),
            ("Protection status changes", "notify_protection_status"),
        ]
        for index, (label, key) in enumerate(specs):
            row, switch = toggle_row(label)
            switch.setChecked(self.app_state.config.get(key, True))
            switch.toggled.connect(lambda v, k=key: self.app_state.config.set(k, v))
            card.addWidget(row)
            if index < len(specs) - 1:
                card.addWidget(hairline())
        layout.addWidget(card)
        layout.addStretch()
        return widget

    def _build_about(self):
        # Unlike every other Settings sub-tab (General/Protection/Exceptions/
        # Notifications all wrap their content in a Card()), this content
        # used to be added directly to the bare page container - no card at
        # all, so there was nothing to paint the gradient/border background
        # every other sub-tab has. Wrapped in a Card() here to match.
        widget, layout = self._page_container()
        card = Card()
        card.layout_.setAlignment(Qt.AlignTop)

        logo_row = QHBoxLayout()
        logo_row.addStretch()
        logo_row.addWidget(icon_label("logo", size=40, color=theme.ACCENT_GREEN))
        logo_row.addStretch()
        card.addLayout(logo_row)

        name = make_label("DEVADARA", "sectionTitle")
        name.setAlignment(Qt.AlignCenter)
        name.setStyleSheet(f"font-size: 20px; font-weight: 700; color: {theme.TEXT_PRIMARY};")
        card.addWidget(name)

        version = make_label("Version 1.0.0", "metadataText")
        version.setAlignment(Qt.AlignCenter)
        card.addWidget(version)

        desc = body_secondary(
            "Local, offline security. All scanning and detection happens on this device - "
            "nothing is sent externally.", wrap=True,
        )
        desc.setAlignment(Qt.AlignCenter)
        card.addWidget(desc)

        engines = body_secondary(
            "Detection engines: SHA256 Hash Matching, YARA Rules, Local ML Classification, "
            "Digital Signature Verification, Behavior Monitoring.", wrap=True,
        )
        engines.setAlignment(Qt.AlignCenter)
        card.addWidget(engines)

        layout.addWidget(card)
        layout.addStretch()
        return widget
