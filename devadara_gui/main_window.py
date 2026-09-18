"""
main_window.py

The app shell (Phase 1): sidebar navigation + a content area that switches
between empty placeholder pages. No backend wiring and no real page content
yet - see components.py for the reusable pieces this is built from, and
CLAUDE.md / the mockup at assets/deepseek_html_20260917_f4ed9f.html for the
target design this replicates.
"""

import os

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QBrush, QColor, QIcon, QPainter, QPen, QPixmap, QRadialGradient
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from devadara_gui import theme
from devadara_gui.components import NavItem

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The sidebar logo source file has been renamed on disk since Phase 1
# (was assets/logo_eye.png.jpg, now assets/logo_eye.png (2).jpg - same
# rounded-square-tile artwork, just re-saved under a new name). Sidebar
# rendering is unchanged; only this path needed to follow the rename.
LOGO_PATH = os.path.join(PROJECT_ROOT, "assets", "logo_eye.png (2).jpg")
# Background-removed version of the same artwork (black rounded-square
# backdrop stripped), used only for the window/taskbar icon - the sidebar
# keeps using LOGO_PATH (the original tile) unchanged.
APP_ICON_PATH = os.path.join(PROJECT_ROOT, "assets", "app_icon.png")

NAV_ITEMS = [
    ("▣", "Dashboard"),   # ▣
    ("⌖", "Scan"),        # ⌖
    ("◈", "Protection"),  # ◈
    ("▤", "Results"),     # ▤
    ("⚙", "Settings"),    # ⚙
]

PAGES = [
    ("Dashboard", "// system_status: secured — welcome back, operator"),
    ("Scan", "// select scan mode or configure targets"),
    ("Protection", "// security modules — status and control"),
    ("Results", "// findings from last scan — click path to locate"),
    ("Settings", "// configure system preferences"),
]


def _divider():
    line = QFrame()
    line.setObjectName("divider")
    line.setFixedHeight(1)
    line.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
    return line


class Sidebar(QFrame):
    """Logo + nav + real-time status box, matching the mockup's .sidebar."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(230)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 20, 0, 20)
        root.setSpacing(0)

        root.addWidget(self._build_logo())
        root.addWidget(_divider())
        root.addWidget(self._build_nav())
        root.addStretch(1)
        root.addWidget(self._build_status_box())

    def _build_logo(self):
        wrap = QWidget()
        outer = QVBoxLayout(wrap)
        outer.setContentsMargins(20, 0, 20, 20)
        outer.setSpacing(0)

        row = QHBoxLayout()
        row.setSpacing(12)

        icon = QLabel()
        icon.setFixedSize(36, 36)
        pixmap = QPixmap(LOGO_PATH)
        if not pixmap.isNull():
            pixmap = pixmap.scaled(
                36, 36,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            icon.setPixmap(pixmap)
        icon.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=14))
        row.addWidget(icon)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)

        wordmark = QLabel(
            f'<span style="color:{theme.NEON};">DEVA</span>'
            f'<span style="color:{theme.TEXT};">DARA</span>'
        )
        wordmark.setFont(theme.letter_spaced_font(size=11, black=True, spacing=2))
        wordmark.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=10))
        text_col.addWidget(wordmark)

        tagline = QLabel("// ANTIVIRUS v1.0")
        tagline.setFont(theme.letter_spaced_font(size=6, spacing=2))
        tagline.setStyleSheet(f"color: {theme.TEXT_DIM};")
        text_col.addWidget(tagline)

        row.addLayout(text_col)
        row.addStretch(1)
        outer.addLayout(row)
        return wrap

    def _build_nav(self):
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(10, 14, 10, 6)
        layout.setSpacing(2)

        section = QLabel("// MAIN")
        section.setObjectName("navSection")
        section.setFont(theme.letter_spaced_font(size=7, bold=True, spacing=2))
        layout.addWidget(section)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_items = []
        for index, (icon, label) in enumerate(NAV_ITEMS):
            item = NavItem(icon, label)
            self.nav_group.addButton(item, index)
            layout.addWidget(item)
            self.nav_items.append(item)
        self.nav_items[0].setChecked(True)

        return wrap

    def _build_status_box(self):
        wrap = QWidget()
        wrap_layout = QVBoxLayout(wrap)
        wrap_layout.setContentsMargins(10, 0, 10, 0)
        wrap_layout.setSpacing(0)

        box = QFrame()
        box.setObjectName("statusBox")
        box.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(12, 12, 12, 12)
        box_layout.setSpacing(8)

        label = QLabel("// REAL-TIME")
        label.setObjectName("statusLabel")
        label.setFont(theme.letter_spaced_font(size=7, bold=True, spacing=2))
        box_layout.addWidget(label)

        row = QHBoxLayout()
        row.setSpacing(8)

        self._dot = QLabel()
        self._dot.setFixedSize(8, 8)
        self._dot.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._dot_on = True
        self._update_dot()
        row.addWidget(self._dot)

        value = QLabel("ACTIVE")
        value.setObjectName("statusValue")
        value.setFont(theme.letter_spaced_font(size=9, bold=True, spacing=1))
        value.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=8))
        row.addWidget(value)
        row.addStretch(1)

        box_layout.addLayout(row)
        wrap_layout.addWidget(box)

        self._blink_timer = QTimer(self)
        self._blink_timer.timeout.connect(self._toggle_dot)
        self._blink_timer.start(1000)

        return wrap

    def _toggle_dot(self):
        self._dot_on = not self._dot_on
        self._update_dot()

    def _update_dot(self):
        alpha = 255 if self._dot_on else 70
        self._dot.setStyleSheet(
            f"background-color: rgba(0, 255, 170, {alpha}); border-radius: 4px; border: none;"
        )


class PagePlaceholder(QWidget):
    """A page-header-only stand-in for real page content (later phases)."""

    def __init__(self, title, subtitle, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 60)
        layout.setSpacing(0)

        header = QHBoxLayout()
        header.setSpacing(14)

        accent = QFrame()
        accent.setObjectName("pageAccentBar")
        accent.setFixedWidth(3)
        accent.setMinimumHeight(48)
        accent.setMaximumHeight(48)
        accent.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        header.addWidget(accent)

        text_col = QVBoxLayout()
        text_col.setSpacing(6)

        title_label = QLabel(title.upper())
        title_label.setObjectName("pageTitle")
        title_label.setFont(theme.letter_spaced_font(size=18, black=True, spacing=4))
        title_label.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=20))
        text_col.addWidget(title_label)

        sub_label = QLabel(subtitle)
        sub_label.setObjectName("pageSub")
        sub_label.setFont(theme.letter_spaced_font(size=8, spacing=1))
        text_col.addWidget(sub_label)

        header.addLayout(text_col)
        header.addStretch(1)

        layout.addLayout(header)
        layout.addStretch(1)


class BackgroundCanvas(QWidget):
    """
    The window's central widget - paints the mockup's dark radial-gradient +
    grid + scanline background, then holds the sidebar/content as children.

    This is deliberately the bottom-of-the-z-order central widget, not a
    transparent overlay drawn on top of other widgets - a prior invisible
    overlay widget in this project silently ate every click app-wide, and
    painting here instead of on an overlay makes that class of bug structurally
    impossible: children painted on top of a QWidget always still receive their
    own mouse events.
    """

    def paintEvent(self, event):
        painter = QPainter(self)
        rect = self.rect()
        span = max(rect.width(), rect.height())

        painter.fillRect(rect, QColor(theme.BG))

        green_glow = QRadialGradient(rect.width() * 0.2, rect.height() * 0.1, span * 0.55)
        green_glow.setColorAt(0.0, QColor("#0a2a20"))
        green_glow.setColorAt(1.0, QColor(theme.BG))
        painter.fillRect(rect, QBrush(green_glow))

        purple_glow = QRadialGradient(rect.width() * 0.8, rect.height() * 0.9, span * 0.5)
        purple_glow.setColorAt(0.0, QColor("#1a0a2a"))
        fade = QColor("#1a0a2a")
        fade.setAlpha(0)
        purple_glow.setColorAt(1.0, fade)
        painter.fillRect(rect, QBrush(purple_glow))

        painter.setPen(QPen(QColor(0, 255, 170, 10), 1))
        step = 40
        x = 0
        while x < rect.width():
            painter.drawLine(x, 0, x, rect.height())
            x += step
        y = 0
        while y < rect.height():
            painter.drawLine(0, y, rect.width(), y)
            y += step

        painter.setPen(QPen(QColor(0, 255, 170, 5), 2))
        y = 0
        while y < rect.height():
            painter.drawLine(0, y, rect.width(), y)
            y += 4

        painter.end()


class MainWindow(QMainWindow):
    MAX_WIDTH = 1120
    MAX_HEIGHT = 655
    MIN_WIDTH = 900
    MIN_HEIGHT = 560

    def __init__(self):
        super().__init__()
        self.setWindowTitle("DEVADARA — Antivirus Guard")
        icon_path = APP_ICON_PATH if os.path.exists(APP_ICON_PATH) else LOGO_PATH
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.setStyleSheet(theme.build_stylesheet())

        central = BackgroundCanvas()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.sidebar = Sidebar()
        layout.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        for title, subtitle in PAGES:
            self.stack.addWidget(PagePlaceholder(title, subtitle))
        layout.addWidget(self.stack, 1)

        self.setCentralWidget(central)
        self.sidebar.nav_group.idClicked.connect(self.stack.setCurrentIndex)

        self.setMinimumSize(self.MIN_WIDTH, self.MIN_HEIGHT)
        self.setMaximumSize(self.MAX_WIDTH, self.MAX_HEIGHT)
        self.resize(self.MAX_WIDTH, self.MAX_HEIGHT)
