"""
scan_page.py

Phase 3a: the Scan page's mode radios and checkbox tree - selection UI and
its logic only. No backend scan connection yet (Phase 3b); the Scan button
is a no-op for this phase.

Drive detection: devadara.usb_monitor.list_removable_drives() is a real,
already-used backend function - imported and called directly for USB
drives, including for live hot-plug polling (see _poll_usb_drives below).
No existing devadara/ function returns fixed-only drives (drive_scanner.py
only walks a given root; full_drive_scan_cli.py's _list_drives() is a
private CLI helper mixing fixed+removable) - list_fixed_drives() below is
new, but read-only and backend-untouched, using the same psutil approach
list_removable_drives() already does with the opposite opts filter.
"""

import psutil
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from devadara.usb_monitor import list_removable_drives

from devadara_gui import theme
from devadara_gui.components import Button, Card, PageHeader, RadioItem, TreeRow

FIXED_PREFIX = "fixed:"
USB_PREFIX = "usb:"

MODES = ["Quick Scan", "Full Scan", "Scan Downloads", "Scan USB"]

SYSTEM_AREA_CHILD_KEYS = ["memory_processes", "services", "registry", "startup"]
SYSTEM_AREA_LABELS = {
    "memory_processes": "Memory Processes",
    "services": "Services",
    "registry": "Registry Area",
    "startup": "Start-Up Area",
}

USB_POLL_INTERVAL_MS = 500


def list_fixed_drives():
    """Real fixed drive mountpoints (e.g. ["C:\\", "D:\\"]), sorted. See
    module docstring for why this is new (no reusable devadara/ function)
    but backend-untouched (same psutil.disk_partitions() approach
    list_removable_drives() already uses)."""
    drives = []
    for partition in psutil.disk_partitions(all=False):
        if "fixed" in partition.opts.split(","):
            drives.append(partition.mountpoint)
    return sorted(drives)


def _drive_label(mountpoint, is_usb):
    letter = mountpoint.rstrip("\\")
    if is_usb:
        return f"USB Drive ({letter})"
    if letter.upper() == "C:":
        return f"Local Disk ({letter})"
    return f"Drive ({letter})"


class ScanPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self._rows = {}  # key -> TreeRow
        self._system_area_keys = set()
        self._current_mode = MODES[0]
        self._fixed_drives = []
        self._usb_drives = []
        self._known_usb = set()
        self._system_area_row = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 60)
        layout.setSpacing(20)

        layout.addWidget(PageHeader("Scan", "// select scan mode or configure targets"))

        config_card = Card(title="Scan Configuration", badge="[READY]")

        hint = QLabel("// pick a mode, or check/uncheck items yourself for a custom scan")
        hint.setObjectName("pageSub")
        hint.setFont(theme.letter_spaced_font(size=8, spacing=0.5))
        config_card.content_layout.addWidget(hint)

        config_card.content_layout.addLayout(self._build_radio_row())
        config_card.content_layout.addLayout(self._build_scan_content())

        layout.addWidget(config_card)
        layout.addStretch(1)

        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_usb_drives)

        self._radio_buttons[MODES[0]].setChecked(True)
        self._apply_mode(MODES[0])

    # ─── construction ───

    def _build_radio_row(self):
        row = QHBoxLayout()
        row.setSpacing(10)

        self._radio_group = QButtonGroup(self)
        self._radio_group.setExclusive(True)
        self._radio_buttons = {}
        for index, mode in enumerate(MODES):
            button = RadioItem(mode)
            self._radio_group.addButton(button, index)
            row.addWidget(button)
            self._radio_buttons[mode] = button
        row.addStretch(1)

        self._radio_group.idClicked.connect(lambda index: self._apply_mode(MODES[index]))
        return row

    def _build_scan_content(self):
        row = QHBoxLayout()
        row.setSpacing(16)

        tree_container = QFrame()
        tree_container.setObjectName("treeContainer")
        tree_container.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._tree_layout = QVBoxLayout(tree_container)
        self._tree_layout.setContentsMargins(8, 8, 8, 8)
        self._tree_layout.setSpacing(2)
        self._build_tree()
        row.addWidget(tree_container, 1)

        right_col = QVBoxLayout()
        right_col.setSpacing(10)

        self._scan_button = Button("Start", variant="primary")
        self._scan_button.setMinimumSize(140, 54)
        self._scan_button.clicked.connect(self._on_scan_clicked)
        right_col.addWidget(self._scan_button)

        self._usb_warning_label = QLabel("Not USB connected")
        self._usb_warning_label.setObjectName("usbNotConnected")
        self._usb_warning_label.setFont(theme.letter_spaced_font(size=8, spacing=0.5))
        self._usb_warning_label.setWordWrap(True)
        self._usb_warning_label.setMaximumWidth(140)
        self._usb_warning_label.hide()
        right_col.addWidget(self._usb_warning_label)

        right_col.addStretch(1)
        row.addLayout(right_col)
        return row

    def _build_tree(self):
        self._fixed_drives = list_fixed_drives()
        self._usb_drives = sorted(list_removable_drives())
        self._known_usb = set(self._usb_drives)

        computer_drive_row = TreeRow("Computer Drive", is_group=True, icon="\U0001F4BE")
        self._tree_layout.addWidget(computer_drive_row)
        self._register_row("computer_drive", computer_drive_row)
        computer_drive_row.collapse_toggled.connect(
            lambda expanded: self._set_children_visible(self._computer_drive_child_keys(), expanded)
        )

        for mountpoint in self._fixed_drives:
            row = TreeRow(_drive_label(mountpoint, is_usb=False), indent=True)
            self._tree_layout.addWidget(row)
            self._register_row(f"{FIXED_PREFIX}{mountpoint}", row)

        for mountpoint in self._usb_drives:
            row = TreeRow(_drive_label(mountpoint, is_usb=True), indent=True)
            self._tree_layout.addWidget(row)
            self._register_row(f"{USB_PREFIX}{mountpoint}", row)

        self._system_area_row = TreeRow("System Area", is_group=True, icon="\u2699\ufe0f")
        self._tree_layout.addWidget(self._system_area_row)
        self._register_row("system_area", self._system_area_row, is_system_area=True)
        self._system_area_row.collapse_toggled.connect(
            lambda expanded: self._set_children_visible(SYSTEM_AREA_CHILD_KEYS, expanded)
        )

        for key in SYSTEM_AREA_CHILD_KEYS:
            row = TreeRow(SYSTEM_AREA_LABELS[key], indent=True)
            self._tree_layout.addWidget(row)
            self._register_row(key, row, is_system_area=True)

    def _register_row(self, key, row, is_system_area=False):
        self._rows[key] = row
        row.toggled.connect(lambda requested, k=key: self._on_row_toggled(k, requested))
        if is_system_area:
            self._system_area_keys.add(key)

    def _computer_drive_child_keys(self):
        return [k for k in self._rows if k.startswith(FIXED_PREFIX) or k.startswith(USB_PREFIX)]

    def _set_children_visible(self, keys, visible):
        for key in keys:
            row = self._rows.get(key)
            if row is not None:
                row.setVisible(visible)

    # ─── checking / mode logic ───

    def _on_row_toggled(self, key, requested_checked):
        """A checkbox was clicked - requested_checked is the state the user
        is asking for, not yet applied (see components.TreeCheckbox)."""
        if key in self._system_area_keys and not requested_checked:
            if not self._confirm_skip_system_area():
                return  # "Keep Checked" (or dialog dismissed) - no change
        self._set_checked(key, requested_checked)

    def _set_checked(self, key, value):
        row = self._rows.get(key)
        if row is None:
            return
        row.setChecked(value)
        if key == "computer_drive":
            for child_key in self._computer_drive_child_keys():
                self._rows[child_key].setChecked(value)
        elif key == "system_area":
            for child_key in SYSTEM_AREA_CHILD_KEYS:
                self._rows[child_key].setChecked(value)

    def _confirm_skip_system_area(self):
        box = QMessageBox(self)
        box.setWindowTitle("Skip System Area check?")
        box.setText(
            "System Area protection catches malware hiding in startup, "
            "registry, and background processes. We recommend keeping "
            "this on."
        )
        keep_button = box.addButton("Keep Checked", QMessageBox.ButtonRole.RejectRole)
        skip_button = box.addButton("Skip Anyway", QMessageBox.ButtonRole.DestructiveRole)
        box.setDefaultButton(keep_button)
        box.exec()
        return box.clickedButton() is skip_button

    def _mode_checked_keys(self, mode):
        """Exactly which tree keys should be checked for a given mode -
        System Area is always fully checked, every mode (the protection
        rule applies the same regardless of which mode is active)."""
        checked = set(SYSTEM_AREA_CHILD_KEYS) | {"system_area"}

        if mode == "Quick Scan":
            for mountpoint in self._fixed_drives:
                if mountpoint.upper().startswith("C:"):
                    checked.add(f"{FIXED_PREFIX}{mountpoint}")
        elif mode == "Full Scan":
            checked.add("computer_drive")
            checked.update(f"{FIXED_PREFIX}{m}" for m in self._fixed_drives)
            checked.update(f"{USB_PREFIX}{m}" for m in self._usb_drives)
        elif mode == "Scan Downloads":
            pass  # Downloads is a direct backend path in Phase 3b, not a tree item
        elif mode == "Scan USB":
            checked.update(f"{USB_PREFIX}{m}" for m in self._usb_drives)

        return checked

    def _apply_mode(self, mode):
        """Re-applies mode's full default checked-state, overwriting any
        manual customization - a silent, direct setter that never shows
        the System Area dialog (that's only for user-initiated unchecks,
        never a mode switch resetting state)."""
        self._current_mode = mode
        checked_keys = self._mode_checked_keys(mode)
        for key, row in self._rows.items():
            row.setChecked(key in checked_keys)
        self._update_usb_gate()

    def select_mode(self, mode_name):
        """Programmatically select a mode (e.g. from Dashboard's Quick Scan/
        Full Scan Quick Actions) - checks the matching radio button and
        applies its auto-check behavior, same as a real click would (radio
        buttons don't emit idClicked on a programmatic setChecked())."""
        button = self._radio_buttons.get(mode_name)
        if button is None:
            return
        button.setChecked(True)
        self._apply_mode(mode_name)

    def _update_usb_gate(self):
        no_usb = self._current_mode == "Scan USB" and not self._usb_drives
        self._usb_warning_label.setVisible(no_usb)
        self._scan_button.setEnabled(not no_usb)

    def _on_scan_clicked(self):
        pass  # Phase 3b wires real scanning - no-op for this phase

    # ─── live USB hot-plug detection ───

    def showEvent(self, event):
        super().showEvent(event)
        self._poll_usb_drives()  # catch anything that changed while hidden
        self._poll_timer.start(USB_POLL_INTERVAL_MS)

    def hideEvent(self, event):
        super().hideEvent(event)
        self._poll_timer.stop()

    def _poll_usb_drives(self):
        current = list_removable_drives()
        added = current - self._known_usb
        removed = self._known_usb - current
        if not added and not removed:
            return
        self._known_usb = current

        for mountpoint in sorted(removed):
            row = self._rows.pop(f"{USB_PREFIX}{mountpoint}", None)
            if row is not None:
                self._tree_layout.removeWidget(row)
                row.deleteLater()
            if mountpoint in self._usb_drives:
                self._usb_drives.remove(mountpoint)

        for mountpoint in sorted(added):
            self._usb_drives.append(mountpoint)
            row = TreeRow(_drive_label(mountpoint, is_usb=True), indent=True)
            insert_index = self._tree_layout.indexOf(self._system_area_row)
            self._tree_layout.insertWidget(insert_index, row)
            self._register_row(f"{USB_PREFIX}{mountpoint}", row)

        # re-apply the current mode's rule so a newly-added/removed drive is
        # correctly (un)checked under Full Scan/Scan USB, and the "Not USB
        # connected" gate re-evaluates immediately.
        self._apply_mode(self._current_mode)
