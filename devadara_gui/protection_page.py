"""
protection_page.py

The Protection page - the Downloads/USB Auto-Scan toggles (Phase 3c-2),
the Behavior Monitoring toggle (Phase 4) and the Windows Startup toggle
(Phase 3d). A Real-Time Protection master switch was part of an earlier,
unrelated design (see dump_services.txt/dump_pages.txt from before the GUI
rewrite) and is out of scope - this page only covers what's wired up.

The module toggles (one card per protection_modules.PROTECTION_MODULES
entry - Downloads/USB Auto-Scan, Behavior Monitoring, and any module added
there later) read their initial state from AutoScanController.config_store
and, on change, persist it there and start/stop the matching watcher on
the controller - never a fake/demo flag. The Windows Startup toggle has no config flag of its own: the HKCU
Run-key entry itself (devadara.startup_registration) is the source of
truth, so it always matches what Task Manager's Startup Apps tab shows.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QScrollArea, QVBoxLayout, QWidget

from devadara import startup_registration
from devadara_gui.components import ModuleToggleCard, PageHeader
from devadara_gui.protection_modules import PROTECTION_MODULES


class ProtectionPage(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self._controller = controller

        # The cards don't fit the window's minimum height (560) at their own
        # minimum height - without scrolling, Qt squeezes them until title
        # and description overlap. At normal sizes nothing scrolls.
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(40, 30, 40, 60)
        layout.setSpacing(20)

        layout.addWidget(PageHeader("Protection", "// security modules — status and control"))

        # One card per protection module, in registry order.
        self.module_cards = {}
        for module in PROTECTION_MODULES:
            card = ModuleToggleCard(
                module.title, module.description,
                initial_checked=controller.config_store.get(module.config_key, module.default_on),
            )
            card.toggled.connect(lambda checked, m=module: self._on_module_toggled(m, checked))
            layout.addWidget(card)
            self.module_cards[module.key] = card

        # This page is built inside MainWindow(), before gui_app.py runs
        # startup_sync for the very first time - so on a first-ever launch
        # the entry isn't registered *yet* but is about to be (default ON).
        startup_enabled = (startup_registration.is_in_startup()
                           or not controller.config_store.get("startup_setup_done", False))
        self._startup_card = ModuleToggleCard(
            "Windows Startup",
            "Launches DEVADARA automatically when you sign in to Windows.",
            initial_checked=startup_enabled,
        )
        self._startup_card.toggled.connect(self._on_startup_toggled)
        layout.addWidget(self._startup_card)

        layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidget(content)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        # Page-level scrolling has no visible bars: the mouse wheel / touchpad
        # still scroll it (the hidden scroll bar keeps working) when the
        # window is too short. Bars inside data tables/lists are unaffected.
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(scroll)

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_startup_state()

    def refresh_startup_state(self):
        """Re-read the real startup state (Task Manager's Startup apps tab
        can enable/disable us behind our back) - display only, never
        writes to the registry. Skipped until first-launch setup has run,
        so the "about to be registered" ON state isn't overwritten."""
        if self._controller.config_store.get("startup_setup_done", False):
            self._startup_card.set_checked_silently(startup_registration.is_in_startup())

    def _on_module_toggled(self, module, checked):
        self._controller.config_store.set(module.config_key, checked)
        if checked:
            module.start(self._controller)
        else:
            module.stop(self._controller)

    def _on_startup_toggled(self, checked):
        if checked:
            startup_registration.add_to_startup()
        else:
            startup_registration.remove_from_startup()
