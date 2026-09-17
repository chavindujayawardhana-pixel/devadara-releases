"""
icons.py

DEVADARA's line-icon set. Rather than shipping a folder of SVG/PNG assets
(none exist right now - see the project's logo decision log), icons are
glyphs from "Segoe MDL2 Assets" / "Segoe Fluent Icons", the icon fonts that
ship with every Windows 10/11 install. Rendered as plain text in the app's
own text colors, this gives a consistent, native-feeling line-icon system
with zero binary assets to manage - fully in keeping with the "no random
icon styles, no colorful icons" rule, and easy to swap for real vector
assets later without touching any call site (only GLYPHS below would change).
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QLabel

from devadara_gui import theme

_ICON_FONT_CANDIDATES = ["Segoe Fluent Icons", "Segoe MDL2 Assets"]

GLYPHS = {
    "dashboard": "",   # Home
    "scan": "",        # Zoom/search
    "protection": "",  # Shield
    "threats": "",     # Warning
    "tools": "",       # Repair/wrench
    "settings": "",    # Gear
    "close": "",
    "chevron_down": "",
    "chevron_right": "",
    "copy": "",
    "search": "",
    "more": "",
    "check": "",
    "dot": "",         # StatusCircleOuter-ish small circle glyph
    "activity": "",
    "usb": "",
    "download": "",
    "registry": "",
    "process": "",
    "memory": "",
    "folder": "",
    "logo": "",
    "flash": "",    # Lightning bolt - verified live via a rendered glyph probe grid
    "monitor": "",  # Desktop monitor - verified live via a rendered glyph probe grid
    "drive": "",  # Floppy disk/save glyph, reused for "Computer Drive" - verified live via a rendered glyph probe grid (replaces the raw color-emoji character that caused the uncontrollable purple/pink tint bug)
}


def icon_font(size=16):
    font = QFont(_ICON_FONT_CANDIDATES[0])
    font.setFamilies(_ICON_FONT_CANDIDATES)
    font.setPixelSize(size)
    return font


def icon_style(color, extra=""):
    """
    The stylesheet string every icon QLabel must carry - not just color/
    background, but font-family too. The app-wide stylesheet's
    `* { font-family: ... }` rule (see theme.py) otherwise wins the QSS
    cascade for every QLabel, silently substituting Segoe UI Variable (no
    icon glyphs) for the icon font and rendering every icon as a tofu box -
    confirmed live: QFontInfo(label.font()).family() reported "Segoe UI
    Variable" instead of the icon font until this was added. Any call site
    that re-styles an icon label later (e.g. to recolor it on a state
    change) must build its stylesheet through this helper, not a bare
    f"color: ...; background: transparent;" string, or it silently
    reintroduces the same bug for that one label.
    """
    return (
        f"color: {color}; background: transparent; "
        f"font-family: '{_ICON_FONT_CANDIDATES[0]}', '{_ICON_FONT_CANDIDATES[1]}'; {extra}"
    )


def icon_label(name, size=18, color=theme.ICON_MUTED):
    label = QLabel(GLYPHS.get(name, ""))
    label.setFont(icon_font(size))
    label.setStyleSheet(icon_style(color))
    label.setAlignment(Qt.AlignCenter)
    label.setFixedSize(size + 6, size + 6)
    return label
