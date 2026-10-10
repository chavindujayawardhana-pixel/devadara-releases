"""
theme.py

Color tokens and QSS for DEVADARA's cyberpunk GUI, copied exactly from the
reference mockup's CSS custom properties
(assets/deepseek_html_20260917_f4ed9f.html, :root block) - no approximated or
"improved" values.

Qt has no QSS equivalent for CSS text-shadow/box-shadow (the mockup's neon
glow) or letter-spacing on QPushButton/QLabel, so those are handled outside
QSS: glow_effect() returns a QGraphicsDropShadowEffect per widget, and
letter_spaced_font() returns a QFont with Qt's native letter-spacing applied.
"""

import os

from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QGraphicsDropShadowEffect

# Lives here (not main_window.py, the only other place that needs it) so
# devadara_gui/mini_form_popup.py can also import it without creating a
# main_window -> scan_page -> mini_form_popup -> main_window import cycle.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICON_PATH = os.path.join(PROJECT_ROOT, "assets", "app_icon.png")
# Orbit-animation layers, split once from app_icon.png: the logo with its
# orbit ring removed, and the ring alone as additive light on black - see
# components.ScanOrbitLogo.
ICON_BASE_PATH = os.path.join(PROJECT_ROOT, "assets", "app_icon_base.png")
ICON_ORBIT_PATH = os.path.join(PROJECT_ROOT, "assets", "app_icon_orbit.png")

# Sidebar header - deliberately larger than the mockup (user decision).
# SIDEBAR_LOGO_SIZE is the one knob for the logo: ScanOrbitLogo sizes
# itself and scales its glow from it.
SIDEBAR_WIDTH = 240
SIDEBAR_LOGO_SIZE = 56
SIDEBAR_NAME_PT = 15
SIDEBAR_TAGLINE_PT = 7

# ─── Color tokens (exact hex from the mockup's :root) ───
BG = "#0a0a0f"
BG2 = "#0f0f1a"
PANEL_SOLID = "#121220"
BORDER = "#1a3a3a"
NEON = "#00ffaa"
NEON_DIM = "#00cc88"
CYAN = "#00e5ff"
DANGER = "#ff3355"
WARN = "#ffcc00"
TEXT = "#d4fff0"
TEXT_DIM = "#5a8a7a"
TEXT_MUTE = "#3a5a4a"

FONT_FAMILY = "Consolas"
FONT_FALLBACKS = ["Consolas", "SF Mono", "Courier New"]
# Icon glyphs (▣ ⌖ ◈ ▤ ⚙ ...) must always be requested in this font
# specifically, everywhere in the app - Consolas has none of them, and
# Windows' automatic fallback resolves some of them (confirmed: the ⚙ gear)
# to a color-glyph font that ignores QPainter/QSS color entirely. This one
# is confirmed to render all of them as plain, colorable outlines.
ICON_FONT_FAMILY = "Segoe UI Symbol"

# Qt QSS colors are "#AARRGGBB" (alpha first) - the opposite byte order from
# CSS's "#RRGGBBAA" - so translucent tokens from the mockup are kept as
# (r, g, b, a) tuples (0-255) and rendered via QSS's rgba() function instead,
# which uses the same byte order and range as QColor.
PANEL_RGBA = (0x12, 0x12, 0x20, 0x99)       # --panel: #12122099
BORDER_GLOW_RGBA = (0x00, 0xFF, 0xAA, 0x33)  # --border-glow: #00ffaa33


def rgba_css(rgba):
    r, g, b, a = rgba
    return f"rgba({r}, {g}, {b}, {a})"


def qcolor(hex6, alpha=255):
    color = QColor(hex6)
    color.setAlpha(alpha)
    return color


def glow_effect(color=NEON, blur=18, x=0, y=0):
    """
    A new QGraphicsDropShadowEffect approximating CSS text-shadow/box-shadow.

    Always returns a fresh instance - a QGraphicsEffect can only ever be
    attached to one widget at a time, so sharing a single instance across
    widgets silently detaches it from whichever widget had it first.
    """
    effect = QGraphicsDropShadowEffect()
    effect.setColor(QColor(color))
    effect.setBlurRadius(blur)
    effect.setOffset(x, y)
    return effect


def letter_spaced_font(size=11, bold=False, spacing=1.0, black=False):
    """
    A QFont with Qt's native letter-spacing applied (AbsoluteSpacing, in px) -
    there is no QSS letter-spacing property for QPushButton/QLabel text.
    """
    font = QFont(FONT_FALLBACKS)
    font.setPointSize(size)
    if black:
        font.setWeight(QFont.Weight.Black)
    elif bold:
        font.setWeight(QFont.Weight.Bold)
    font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, spacing)
    return font


def build_stylesheet():
    """One QSS string for QApplication.setStyleSheet() - see module docstring
    for what's deliberately NOT handled here (glow, letter-spacing)."""
    return f"""
        * {{
            font-family: "{FONT_FAMILY}";
            color: {TEXT};
        }}

        QWidget {{
            background: transparent;
        }}

        QMainWindow {{
            background: {BG};
        }}

        QToolTip {{
            background-color: {PANEL_SOLID};
            color: {TEXT};
            border: 1px solid {NEON};
            padding: 4px 8px;
        }}

        /* ─── Sidebar ─── */
        QFrame#sidebar {{
            background: qlineargradient(
                x1:0, y1:0, x2:0, y2:1,
                stop:0 #0d0d1a, stop:1 #060610
            );
            border: none;
            border-right: 1px solid {BORDER};
        }}

        QFrame#divider {{
            background-color: {BORDER};
            border: none;
            max-height: 1px;
            min-height: 1px;
        }}

        QLabel#navSection {{
            color: {TEXT_MUTE};
        }}

        /* ─── Nav items ─── */
        QPushButton#navItem {{
            text-align: left;
            padding: 10px 14px;
            border: 1px solid transparent;
            border-radius: 4px;
            background: transparent;
            color: {TEXT_DIM};
        }}

        QPushButton#navItem:hover {{
            color: {NEON};
            background: {rgba_css((0, 255, 170, 13))};
            border-color: {rgba_css((0, 255, 170, 51))};
        }}

        QPushButton#navItem[active="true"] {{
            color: {NEON};
            background: {rgba_css((0, 255, 170, 26))};
            border: 1px solid {NEON};
        }}

        /* ─── Status box ─── */
        QFrame#statusBox {{
            border: 1px solid {BORDER};
            border-radius: 4px;
            background: {rgba_css((0, 255, 170, 8))};
        }}

        QLabel#statusLabel {{
            color: {TEXT_MUTE};
        }}

        QLabel#statusValue {{
            color: {NEON};
        }}

        /* ─── Card / panel ─── */
        QFrame#card {{
            background: {rgba_css(PANEL_RGBA)};
            border: 1px solid {BORDER};
            border-radius: 6px;
        }}

        QLabel#cardTitle {{
            color: {TEXT_MUTE};
        }}

        QLabel#cardBadge {{
            color: {NEON};
        }}

        /* ─── Buttons ─── */
        QPushButton#themedButton {{
            border-radius: 4px;
            padding: 10px 18px;
            font-weight: 700;
        }}

        QPushButton#themedButton[variant="secondary"] {{
            background: transparent;
            border: 1px solid {BORDER};
            color: {TEXT};
        }}

        QPushButton#themedButton[variant="secondary"]:hover {{
            border-color: {NEON};
            color: {NEON};
        }}

        QPushButton#themedButton[variant="primary"] {{
            background: {NEON};
            border: 1px solid {NEON};
            color: #000000;
        }}

        QPushButton#themedButton[variant="primary"]:hover {{
            background: #00ffcc;
        }}

        QPushButton#themedButton:disabled {{
            background: {rgba_css((90, 138, 122, 25))};
            border: 1px solid {BORDER};
            color: {TEXT_MUTE};
        }}

        /* ─── Hero status card ─── */
        QFrame#heroCard {{
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 {rgba_css((0, 255, 170, 20))}, stop:1 {rgba_css((0, 229, 255, 10))}
            );
            border: 1px solid {NEON};
            border-radius: 6px;
        }}

        QLabel#heroGreeting {{
            color: {TEXT_DIM};
        }}

        QLabel#heroDesc {{
            color: {TEXT_DIM};
        }}

        /* ─── Stat cards ─── */
        QFrame#statCard {{
            background: {rgba_css(PANEL_RGBA)};
            border: 1px solid {BORDER};
            border-radius: 4px;
        }}

        QFrame#statCard:hover {{
            border-color: {NEON};
        }}

        QLabel#statLabel {{
            color: {TEXT_MUTE};
        }}

        /* ─── Action cards (Quick Actions) ─── */
        QFrame#actionCard {{
            background: {rgba_css(PANEL_RGBA)};
            border: 1px solid {BORDER};
            border-radius: 4px;
        }}

        QFrame#actionCard:hover {{
            border-color: {NEON};
        }}

        QLabel#actionIconBox {{
            background: {rgba_css((0, 255, 170, 20))};
            border: 1px solid {rgba_css((0, 255, 170, 51))};
            border-radius: 4px;
            color: {NEON};
            font-family: "{ICON_FONT_FAMILY}";
        }}

        QLabel#actionTitle {{
            color: {TEXT};
        }}

        /* ─── Radio items (Scan page mode row) ─── */
        QPushButton#radioItem {{
            padding: 8px 14px 8px 34px;
            border: 1px solid {BORDER};
            border-radius: 4px;
            background: transparent;
            color: {TEXT_DIM};
        }}

        QPushButton#radioItem:hover {{
            color: {TEXT};
            border-color: {TEXT_DIM};
        }}

        QPushButton#radioItem[active="true"] {{
            color: {NEON};
            border-color: {NEON};
            background: {rgba_css((0, 255, 170, 20))};
        }}

        /* ─── Checkbox tree (Scan page) ─── */
        QFrame#treeContainer {{
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid {BORDER};
            border-radius: 4px;
        }}

        QWidget#treeRow[hoverable="true"]:hover {{
            background: {rgba_css((0, 255, 170, 15))};
            border-radius: 3px;
        }}

        QLabel#treeLabel {{
            color: {TEXT};
        }}

        QLabel#treeArrow {{
            color: {NEON};
        }}

        QLabel#usbNotConnected {{
            color: {WARN};
        }}

        /* ─── Scan progress ─── */
        QProgressBar#scanProgressBar {{
            background: {rgba_css((0, 255, 170, 20))};
            border: 1px solid {BORDER};
            border-radius: 3px;
        }}

        QProgressBar#scanProgressBar::chunk {{
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:0,
                stop:0 {NEON}, stop:1 {CYAN}
            );
            border-radius: 3px;
        }}

        QPlainTextEdit#scanLogPanel {{
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid {BORDER};
            border-radius: 4px;
            color: {TEXT_DIM};
            padding: 8px;
        }}

        /* ─── Page header ─── */
        QFrame#pageAccentBar {{
            background-color: {NEON};
            border: none;
        }}

        QLabel#pageTitle {{
            color: {NEON};
        }}

        QLabel#pageSub {{
            color: {TEXT_DIM};
        }}

        /* ─── Mini-Form popup ─── */
        QFrame#miniWindowPanel {{
            background: rgba(10, 10, 15, 0.95);
            border: 1px solid {BORDER};
            border-radius: 6px;
        }}

        QFrame#miniHeaderDivider {{
            background: transparent;
            border: none;
            border-bottom: 1px dashed {BORDER};
            max-height: 1px;
            min-height: 1px;
        }}

        QFrame#miniStatsBox {{
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid {BORDER};
            border-radius: 4px;
        }}

        /* ─── Scrollbars ─── */
        QScrollBar:vertical {{
            background: transparent;
            width: 8px;
            margin: 0;
        }}

        QScrollBar::handle:vertical {{
            background: {NEON_DIM};
            border-radius: 4px;
            min-height: 24px;
        }}

        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
    """
