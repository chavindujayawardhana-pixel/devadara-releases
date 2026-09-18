"""
scan_tree.py

The Scan page's mode-radio-row + checkbox tree (assets/scan_page_reference.html,
confirmed with the user - see that file's inline <script> for the exact
selection/expand-collapse behavior this reproduces in PySide6). Computer
Drive's children are the only dynamic part - populated from the real fixed
drives on this machine (see AppState.list_fixed_drive_items()), everything
else is the reference's fixed tree shape.

Behavior (kept identical to the reference's plain-JS implementation):
  - Clicking a mode radio re-applies that mode's default checked set,
    replacing whatever was checked before.
  - Clicking a GROUP checkbox toggles all its children to match it.
  - Clicking a CHILD checkbox toggles only that child - it never touches
    its parent's or siblings' checked state.
  - Clicking a group's arrow toggles that group's expanded/collapsed
    state only - it never touches any checked state.
  - Which mode radio reads as "selected" only changes when a radio itself
    is clicked - manually editing checkboxes afterward does not clear it
    (exactly the reference's `current` variable semantics).
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QRadioButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from devadara_gui import theme
from devadara_gui.icons import icon_label

# Pulled from theme.py's shared tokens, not the reference file's raw hex,
# per the app-wide color-consistency pass: the reference mockup's own
# #3CDC8C/#5D8571 were a one-off third accent/muted-text pair that didn't
# match any other screen in the app - KELLY_GREEN/TEXT_DISABLED are the
# app's real accent and muted-text tiers (see theme.py), used here instead
# so the tree reads as the same system as the rest of the app rather than
# its own palette.
TREE_ACCENT = theme.CYBER_NEON
TEXT_CHECKED_PARENT = theme.CYBER_TEXT_PRIMARY
TEXT_CHECKED_CHILD = theme.CYBER_TEXT_SECONDARY
TEXT_UNCHECKED = theme.CYBER_TEXT_MUTE
ARROW_COLOR = theme.CYBER_NEON
MODE_ACTIVE_TEXT = theme.CYBER_TEXT_PRIMARY
MODE_INACTIVE_TEXT = theme.CYBER_TEXT_MUTE

STATIC_TREE = [
    # Group rows carry an "icon" key naming an devadara_gui.icons.GLYPHS
    # entry - a proper single-color line-icon glyph (Segoe Fluent Icons),
    # rendered through icon_label()/icon_style() so it fully respects the
    # app's theme color tokens. The reference mockup's own group labels
    # used raw color-emoji characters (\ud83d\udcbe/\u2699\ufe0f/\ud83d\udcc1/\ud83d\udee0\ufe0f/\ud83d\udd0c) instead - a color-emoji
    # glyph is rendered by the OS's own multi-color emoji font (Segoe UI
    # Emoji on Windows) with its own BAKED-IN palette, immune to any QSS
    # `color:` override. Confirmed live: that's exactly why these rows
    # appeared purple/pink-tinted rather than the app's green accent - not
    # a QSS/theme-token bug, an uncontrollable native emoji render that no
    # color token could ever fix. Child rows (e.g. "Local Disk (C:)",
    # "Memory Processes") intentionally carry no icon at all, unchanged.
    {"id": "drive", "text": "Computer Drive", "indent": 0, "parent": None, "group": True, "icon": "drive"},
    # "drive_<n>" children are inserted here at runtime (see build_tree_spec)
    {"id": "sys", "text": "System Area", "indent": 0, "parent": None, "group": True, "icon": "settings"},
    {"id": "mem", "text": "Memory Processes", "indent": 1, "parent": "sys"},
    {"id": "svc", "text": "Services", "indent": 1, "parent": "sys"},
    {"id": "reg", "text": "Registry Area", "indent": 1, "parent": "sys"},
    {"id": "startup", "text": "Start-Up Area", "indent": 1, "parent": "sys"},
    {"id": "quickfolders", "text": "Common Locations", "indent": 0, "parent": None, "group": True, "icon": "folder"},
    {"id": "dl", "text": "Downloads", "indent": 1, "parent": "quickfolders"},
    {"id": "desktop", "text": "Desktop", "indent": 1, "parent": "quickfolders"},
    {"id": "docs", "text": "Documents", "indent": 1, "parent": "quickfolders"},
    {"id": "temp", "text": "Temp", "indent": 1, "parent": "quickfolders"},
    {"id": "tools", "text": "Deep Inspection", "indent": 0, "parent": None, "group": True, "icon": "tools"},
    {"id": "proc", "text": "Running Processes", "indent": 1, "parent": "tools"},
    {"id": "ram", "text": "Process Memory", "indent": 1, "parent": "tools"},
    {"id": "usb", "text": "USB Drive", "indent": 0, "parent": None, "group": False, "icon": "usb"},
]

SYSTEM_AREA_IDS = ("mem", "svc", "reg", "startup")
COMMON_LOCATION_IDS = {"dl": "Downloads", "desktop": "Desktop", "docs": "Documents", "temp": "Temp"}
DEEP_INSPECTION_IDS = ("proc", "ram")


def build_tree_spec(drive_items):
    """
    drive_items: [{"id", "label", "path"}, ...] from
    AppState.list_fixed_drive_items() - inserted as Computer Drive's
    children, in place of the reference's hardcoded C:/D:/E: mockup rows.
    """
    spec = []
    for item in STATIC_TREE:
        spec.append(item)
        if item["id"] == "drive":
            for drive in drive_items:
                spec.append({"id": drive["id"], "text": drive["label"], "indent": 1, "parent": "drive"})
    return spec


def default_mode_checks(tree_spec):
    all_ids = [item["id"] for item in tree_spec]
    return {
        "quick": ["quickfolders"] + list(COMMON_LOCATION_IDS.keys()),
        "full": all_ids,
        "downloads": ["quickfolders", "dl"],
        "usb": ["usb"],
    }


MODE_LABELS = {
    "quick": "Quick Scan",
    "full": "Full Scan",
    "downloads": "Scan Downloads",
    "usb": "Scan USB",
}


class _TreeCheckBox(QCheckBox):
    """Plain QCheckBox, re-skinned to the reference's accent-green indicator."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet(f"""
            QCheckBox::indicator {{
                width: 14px; height: 14px; border-radius: 3px;
                border: 1px solid {theme.CYBER_BORDER_STRONG};
                background: {theme.CYBER_BG_INSET};
            }}
            QCheckBox::indicator:checked {{
                border: 1px solid {TREE_ACCENT};
                background: {TREE_ACCENT};
            }}
        """)


class _ArrowLabel(QLabel):
    clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(14)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet(f"color: {ARROW_COLOR}; font-size: 11px; background: transparent;")

    def mousePressEvent(self, event):
        self.clicked.emit()
        super().mousePressEvent(event)


class _ClickableLabel(QLabel):
    clicked = Signal()

    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.PointingHandCursor)

    def mousePressEvent(self, event):
        self.clicked.emit()
        super().mousePressEvent(event)


class _TreeRow(QWidget):
    def __init__(self, item, on_checkbox_toggled, on_arrow_clicked, parent=None):
        super().__init__(parent)
        self.item = item
        layout = QHBoxLayout(self)
        layout.setContentsMargins(item["indent"] * 20, 3, 0, 3)
        layout.setSpacing(6)

        if item.get("group"):
            self.arrow = _ArrowLabel()
            self.arrow.clicked.connect(lambda: on_arrow_clicked(item["id"]))
            layout.addWidget(self.arrow)
        else:
            self.arrow = None
            spacer = QLabel("")
            spacer.setFixedWidth(14)
            layout.addWidget(spacer)

        self.checkbox = _TreeCheckBox()
        self.checkbox.toggled.connect(lambda checked: on_checkbox_toggled(item["id"], checked))
        layout.addWidget(self.checkbox)

        icon_name = item.get("icon")
        if icon_name:
            layout.addWidget(icon_label(icon_name, size=14, color=TREE_ACCENT))

        self.label = _ClickableLabel(item["text"])
        self.label.clicked.connect(self.checkbox.click)
        layout.addWidget(self.label, 1)

    def set_arrow_expanded(self, expanded):
        if self.arrow is not None:
            self.arrow.setText("\u25be" if expanded else "\u25b8")

    def set_checked_silently(self, checked):
        self.checkbox.blockSignals(True)
        self.checkbox.setChecked(checked)
        self.checkbox.blockSignals(False)
        self._restyle(checked)

    def _restyle(self, checked):
        if not checked:
            color = TEXT_UNCHECKED
        elif self.item["indent"] == 0:
            color = TEXT_CHECKED_PARENT
        else:
            color = TEXT_CHECKED_CHILD
        weight = "600" if (checked and self.item["indent"] == 0) else "400"
        self.label.setStyleSheet(f"color: {color}; font-weight: {weight}; font-size: 12px; background: transparent;")


class ScanModeRow(QWidget):
    """The four mode radios, laid out full-width above the tree box."""

    mode_selected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_mode = None
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(20)
        self.mode_group = QButtonGroup(self)
        self.mode_group.setExclusive(True)
        self._buttons = {}
        for key in ("quick", "full", "downloads", "usb"):
            radio = QRadioButton(MODE_LABELS[key])
            radio.setCursor(Qt.PointingHandCursor)
            radio.toggled.connect(lambda checked, k=key: self._on_toggled(k, checked))
            self.mode_group.addButton(radio)
            self._buttons[key] = radio
            row.addWidget(radio)
        row.addStretch()
        self.set_active_mode("quick")

    def _on_toggled(self, key, checked):
        if checked:
            self.current_mode = key
            self._restyle()
            self.mode_selected.emit(key)

    def set_active_mode(self, key):
        self._buttons[key].blockSignals(True)
        self._buttons[key].setChecked(True)
        self._buttons[key].blockSignals(False)
        self.current_mode = key
        self._restyle()

    def _restyle(self):
        for key, radio in self._buttons.items():
            active = key == self.current_mode
            color = MODE_ACTIVE_TEXT if active else MODE_INACTIVE_TEXT
            weight = "600" if active else "400"
            radio.setStyleSheet(f"""
                QRadioButton {{ color: {color}; font-weight: {weight}; font-size: 12px; spacing: 6px; }}
                QRadioButton::indicator {{
                    width: 13px; height: 13px; border-radius: 7px;
                    border: 1px solid {theme.CYBER_BORDER_STRONG};
                    background: {theme.CYBER_BG_INSET};
                }}
                QRadioButton::indicator:checked {{
                    border: 1px solid {TREE_ACCENT};
                    background: {TREE_ACCENT};
                }}
            """)


class ScanTreeWidget(QWidget):
    """
    The checkbox tree box only (no mode radios - see ScanModeRow, a
    separate sibling widget the Scan page wires to apply_mode() below, so
    the page can lay the two out exactly like the reference: the mode row
    full-width above, the tree box and the Scan button side by side below
    it). `tree_spec` is built once (via build_tree_spec()) and passed in -
    this widget owns no knowledge of where drive items come from, only how
    to render/toggle a flat list of {id, text, indent, parent, group?} rows.
    """

    selection_changed = Signal()

    def __init__(self, tree_spec, parent=None):
        super().__init__(parent)
        self.tree_spec = tree_spec
        self.mode_checks = default_mode_checks(tree_spec)
        self.children_of = {}
        for item in tree_spec:
            if item["parent"] is not None:
                self.children_of.setdefault(item["parent"], []).append(item["id"])

        self.state = {item["id"]: False for item in tree_spec}
        self.expanded = {item["id"]: True for item in tree_spec if item.get("group")}
        self.current_mode = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.tree_scroll = QScrollArea()
        self.tree_scroll.setWidgetResizable(True)
        self.tree_scroll.setObjectName("scanTreeBox")
        self.tree_scroll.setFixedHeight(260)
        tree_body = QWidget()
        tree_body.setObjectName("scanTreeBody")
        self.tree_layout = QVBoxLayout(tree_body)
        self.tree_layout.setContentsMargins(14, 12, 14, 12)
        self.tree_layout.setSpacing(2)
        self.tree_scroll.setWidget(tree_body)
        outer.addWidget(self.tree_scroll)

        self.tree_scroll.setStyleSheet(f"""
            #scanTreeBox {{
                border-radius: {theme.RADIUS_CARD}px;
                border: 1px solid {theme.CYBER_BORDER_DEFAULT};
                background: {theme.GRADIENT_NEUTRAL_CARD};
            }}
            #scanTreeBody {{ background: transparent; }}
        """)

        self._rows = {}
        for item in tree_spec:
            row = _TreeRow(item, self._on_checkbox_toggled, self._on_arrow_clicked)
            self._rows[item["id"]] = row
            self.tree_layout.addWidget(row)
        self.tree_layout.addStretch()

        self.apply_mode("quick")

    # ------------------------------------------------------------------
    def apply_mode(self, mode):
        self.current_mode = mode
        checked_ids = set(self.mode_checks[mode])
        for item_id in self.state:
            self.state[item_id] = item_id in checked_ids
        self._render_rows()
        self.selection_changed.emit()

    def checked_ids(self):
        return [item_id for item_id, checked in self.state.items() if checked]

    def is_checked(self, item_id):
        return bool(self.state.get(item_id))

    def any_checked(self, item_ids):
        return any(self.state.get(i) for i in item_ids)

    # ------------------------------------------------------------------
    def _on_checkbox_toggled(self, item_id, checked):
        if self.state.get(item_id) == checked:
            return
        self.state[item_id] = checked
        if item_id in self.children_of:  # a group checkbox - cascade to children
            for child_id in self.children_of[item_id]:
                self.state[child_id] = checked
        self._render_rows()
        self.selection_changed.emit()

    def _on_arrow_clicked(self, group_id):
        self.expanded[group_id] = not self.expanded[group_id]
        self._render_rows()

    def _render_rows(self):
        for item in self.tree_spec:
            row = self._rows[item["id"]]
            parent = item["parent"]
            visible = parent is None or self.expanded.get(parent, True)
            row.setVisible(visible)
            row.set_checked_silently(self.state[item["id"]])
            if item.get("group"):
                row.set_arrow_expanded(self.expanded.get(item["id"], True))
