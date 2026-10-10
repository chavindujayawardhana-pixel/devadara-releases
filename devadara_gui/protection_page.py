"""
protection_page.py

The Protection page - the Downloads/USB Auto-Scan toggles (Phase 3c-2)
and the Windows Startup toggle (Phase 3d). Real-Time Protection master
switch and Behavior Monitoring were part of an earlier, unrelated design
(see dump_services.txt/dump_pages.txt from before the GUI rewrite) and are
out of scope here - this page only covers what's actually wired up.

The Auto-Scan toggles read their initial state from
AutoScanController.config_store and, on change, persist it there and
start/stop the matching watcher on the controller - never a fake/demo
flag. The Windows Startup toggle has no config flag of its own: the HKCU
Run-key entry itself (devadara.startup_registration) is the source of
truth, so it always matches what Task Manager's Startup Apps tab shows.
"""

from PySide6.QtWidgets import QVBoxLayout, QWidget

from devadara import startup_registration
from devadara_gui.components import ModuleToggleCard, PageHeader


class ProtectionPage(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self._controller = controller

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 60)
        layout.setSpacing(20)

        layout.addWidget(PageHeader("Protection", "// security modules — status and control"))

        self._downloads_card = ModuleToggleCard(
            "Downloads Auto-Scan",
            "Automatically scans every new file that finishes arriving in your Downloads folder.",
            initial_checked=controller.config_store.get("downloads_autoscan_enabled", True),
        )
        self._downloads_card.toggled.connect(self._on_downloads_toggled)
        layout.addWidget(self._downloads_card)

        self._usb_card = ModuleToggleCard(
            "USB Auto-Scan",
            "Automatically scans a removable drive the moment it's connected.",
            initial_checked=controller.config_store.get("usb_autoscan_enabled", True),
        )
        self._usb_card.toggled.connect(self._on_usb_toggled)
        layout.addWidget(self._usb_card)

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

    def _on_downloads_toggled(self, checked):
        self._controller.config_store.set("downloads_autoscan_enabled", checked)
        if checked:
            self._controller.start_downloads_watch()
        else:
            self._controller.stop_downloads_watch()

    def _on_usb_toggled(self, checked):
        self._controller.config_store.set("usb_autoscan_enabled", checked)
        if checked:
            self._controller.start_usb_watch()
        else:
            self._controller.stop_usb_watch()

    def _on_startup_toggled(self, checked):
        if checked:
            startup_registration.add_to_startup()
        else:
            startup_registration.remove_from_startup()
