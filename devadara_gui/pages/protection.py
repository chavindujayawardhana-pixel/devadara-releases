"""
protection.py

The Protection page (Section 5): five module cards, each backed by a real
monitor in devadara_gui.services.app_state. Toggling a card starts/stops
the actual devadara/ watcher (behavior_monitor, downloads_monitor,
usb_monitor) or edits the real Windows Registry Run key
(devadara.startup_registration), never a fake/demo flag.
"""

from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from devadara_gui import theme
from devadara_gui.components import ModuleCard, page_title


class ProtectionPage(theme.PageCanvas):
    def __init__(self, app_state, parent=None):
        super().__init__(parent)
        self.app_state = app_state
        self.setObjectName("pageRoot")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)

        content = QWidget()
        scroll.setWidget(content)

        layout = QVBoxLayout(content)
        layout.setContentsMargins(theme.PAGE_PADDING, theme.PAGE_PADDING, theme.PAGE_PADDING, theme.PAGE_PADDING)
        layout.setSpacing(theme.CARD_GAP)
        layout.addWidget(page_title("Protection"))

        self.master_card = ModuleCard(
            "Real-Time Protection",
            "Monitors files and system activity for suspicious behavior.",
            initial_state=app_state.is_realtime_protection_enabled(),
        )
        self.master_card.toggled.connect(self._on_master_toggled)
        layout.addWidget(self.master_card)

        self.behavior_card = ModuleCard(
            "Behavior Monitoring",
            "Watches your Downloads folder for ransomware-like bursts of file activity.",
            initial_state=app_state.is_module_enabled("behavior_monitoring"),
        )
        self.behavior_card.toggled.connect(lambda checked: self._on_module_toggled("behavior_monitoring", checked))
        layout.addWidget(self.behavior_card)

        self.downloads_card = ModuleCard(
            "Downloads Auto-Scan",
            "Automatically scans every new file that finishes arriving in Downloads.",
            initial_state=app_state.is_module_enabled("downloads_autoscan"),
        )
        self.downloads_card.toggled.connect(lambda checked: self._on_module_toggled("downloads_autoscan", checked))
        layout.addWidget(self.downloads_card)

        self.usb_card = ModuleCard(
            "USB Auto-Scan",
            "Automatically scans removable drives the moment they're connected.",
            initial_state=app_state.is_module_enabled("usb_autoscan"),
        )
        self.usb_card.toggled.connect(lambda checked: self._on_module_toggled("usb_autoscan", checked))
        layout.addWidget(self.usb_card)

        self.startup_card = ModuleCard(
            "Windows Startup",
            "Start DEVADARA automatically when Windows starts.",
            initial_state=app_state.is_startup_enabled(),
        )
        self.startup_card.toggled.connect(self._on_startup_toggled)
        layout.addWidget(self.startup_card)

        layout.addStretch()

        self.app_state.protection_changed.connect(self._sync_from_state)

    def _on_master_toggled(self, checked):
        self.app_state.set_realtime_protection(checked)

    def _on_module_toggled(self, key, checked):
        self.app_state.set_module_enabled(key, checked)

    def _on_startup_toggled(self, checked):
        self.app_state.set_startup_enabled(checked)

    def _sync_from_state(self):
        self.master_card.set_checked_silently(self.app_state.is_realtime_protection_enabled())
        self.behavior_card.set_checked_silently(self.app_state.is_module_enabled("behavior_monitoring"))
        self.downloads_card.set_checked_silently(self.app_state.is_module_enabled("downloads_autoscan"))
        self.usb_card.set_checked_silently(self.app_state.is_module_enabled("usb_autoscan"))
