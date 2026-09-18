"""
main_window.py

The application shell: a fixed sidebar (never collapses) plus a
QStackedWidget content area, with a toast overlay on top. Sidebar
navigation and page wiring live here; each page only ever talks to the
shared AppState, never to another page directly.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from devadara_gui import theme
from devadara_gui.components import StatusDot, make_label
from devadara_gui.icons import icon_label, icon_style
from devadara_gui.pages.dashboard import DashboardPage
from devadara_gui.pages.protection import ProtectionPage
from devadara_gui.pages.scan import ScanPage
from devadara_gui.pages.settings_page import SettingsPage
from devadara_gui.pages.threats import ThreatsPage
from devadara_gui.realtime_scan_popup import RealTimeScanPopup
from devadara_gui.services.app_state import AppState
from devadara_gui.services.realtime_scan import RealtimeScanController
from devadara_gui.toast import ToastHost

# Nav key, display label, icon glyph name.
# "results" is the new name for the old "threats" page.
NAV_ITEMS = [
    ("dashboard", "Dashboard", "dashboard"),
    ("scan", "Scan", "scan"),
    ("protection", "Protection", "protection"),
    ("results", "Results", "threats"),
    ("settings", "Settings", "settings"),
]


class NavButton(QPushButton):
    """One sidebar navigation row: icon + label, checkable, with a glow
    when active. Visual layer only — no logic lives here."""

    def __init__(self, icon_name, label, parent=None):
        super().__init__(parent)
        self.setObjectName("navRow")
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(42)
        self._icon_name = icon_name

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 12, 0)
        layout.setSpacing(12)
        self._icon = icon_label(icon_name, size=15, color=theme.CYBER_TEXT_SECONDARY)
        layout.addWidget(self._icon)
        self._label = make_label(label, "bodyText")
        self._label.setStyleSheet(
            f"color: {theme.CYBER_TEXT_SECONDARY}; font-size: 12px; "
            f"letter-spacing: 1.5px; background: transparent; font-weight: 500;"
        )
        layout.addWidget(self._label)
        layout.addStretch()

    def setChecked(self, checked):
        super().setChecked(checked)
        self.setProperty("active", "true" if checked else "false")
        self.style().unpolish(self)
        self.style().polish(self)

        label_color = theme.CYBER_NEON if checked else theme.CYBER_TEXT_SECONDARY
        icon_color = theme.CYBER_NEON if checked else theme.CYBER_TEXT_SECONDARY

        self._icon.setStyleSheet(icon_style(icon_color))
        self._label.setStyleSheet(
            f"color: {label_color}; font-size: 12px; "
            f"font-weight: {'700' if checked else '500'}; "
            f"letter-spacing: 1.5px; background: transparent;"
        )

        if checked:
            theme.apply_glow(self, theme.CYBER_GLOW_NEON, blur=14, alpha=100)
        else:
            theme.clear_glow(self)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DEVADARA")
        self.setMinimumSize(800, 520)
        self.resize(900, 600)

        self.app_state = AppState()

        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        root_layout.addWidget(self._build_sidebar())

        content_wrap = QWidget()
        content_wrap.setObjectName("contentArea")
        content_layout = QVBoxLayout(content_wrap)
        content_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.addWidget(content_wrap, 1)

        self.stack = QStackedWidget()
        content_layout.addWidget(self.stack)

        self.dashboard_page = DashboardPage(self.app_state)
        self.scan_page = ScanPage(self.app_state)
        self.protection_page = ProtectionPage(self.app_state)
        self.results_page = ThreatsPage(self.app_state)  # class still ThreatsPage
        self.settings_page = SettingsPage(self.app_state)

        self.pages = {
            "dashboard": self.dashboard_page,
            "scan": self.scan_page,
            "protection": self.protection_page,
            "results": self.results_page,
            "settings": self.settings_page,
        }
        for page in self.pages.values():
            self.stack.addWidget(page)

        self.dashboard_page.scan_requested.connect(self._on_dashboard_scan_requested)
        self.scan_page.navigate_requested.connect(self.navigate_to)

        self.toast_host = ToastHost(central)
        self.toast_host.setGeometry(central.rect())
        self.toast_host.raise_()
        self.app_state.toast_requested.connect(self.toast_host.show_toast)

        self.realtime_popup = RealTimeScanPopup()
        self.realtime_scan_controller = RealtimeScanController(
            self.app_state, self.realtime_popup, on_review=self._on_realtime_review,
        )

        self.navigate_to("dashboard")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.toast_host.setGeometry(self.centralWidget().rect())
        self.toast_host.raise_()

    def _build_sidebar(self):
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(theme.SIDEBAR_WIDTH)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(14, 20, 14, 16)
        layout.setSpacing(0)

        # --- Logo block ---
        logo_wrap = QWidget()
        logo_wrap.setObjectName("transparentPanel")
        logo_row = QHBoxLayout(logo_wrap)
        logo_row.setContentsMargins(8, 0, 8, 20)
        logo_row.setSpacing(10)

        logo_icon = icon_label("logo", size=22, color=theme.CYBER_NEON)
        theme.apply_glow(logo_icon, theme.CYBER_GLOW_NEON, blur=14, alpha=180)
        logo_row.addWidget(logo_icon)

        wordmark_col = QVBoxLayout()
        wordmark_col.setSpacing(3)
        wordmark_col.setContentsMargins(0, 0, 0, 0)

        wordmark = QLabel('DEVA<span style="color:#d4fff0;">DARA</span>')
        wordmark.setTextFormat(Qt.RichText)
        wordmark.setStyleSheet(
            f"color: {theme.CYBER_NEON}; font-size: 14px; font-weight: 900; "
            f"letter-spacing: 2px; background: transparent;"
        )
        wordmark_col.addWidget(wordmark)

        tagline = make_label("// ANTIVIRUS v1.0", "metadataDisabled")
        tagline.setStyleSheet(
            f"color: {theme.CYBER_TEXT_MUTE}; font-size: 8px; "
            f"letter-spacing: 2px; background: transparent;"
        )
        wordmark_col.addWidget(tagline)

        logo_row.addLayout(wordmark_col)
        logo_row.addStretch()
        layout.addWidget(logo_wrap)

        # Divider under logo
        logo_divider = QFrame()
        logo_divider.setObjectName("sidebarDivider")
        logo_divider.setFixedHeight(1)
        layout.addWidget(logo_divider)
        layout.addSpacing(10)

        # --- Section label ---
        section_label = make_label("// MAIN", "sidebarSectionLabel")
        section_label.setStyleSheet(
            f"color: {theme.CYBER_TEXT_MUTE}; font-size: 9px; font-weight: 700; "
            f"letter-spacing: 2px; background: transparent; padding: 4px 8px;"
        )
        layout.addWidget(section_label)
        layout.addSpacing(4)

        # --- Nav items ---
        self.nav_buttons = {}
        for key, label, icon_name in NAV_ITEMS:
            button = NavButton(icon_name, label)
            button.clicked.connect(lambda _checked=False, k=key: self.navigate_to(k))
            layout.addWidget(button)
            layout.addSpacing(2)
            self.nav_buttons[key] = button

        layout.addStretch()

        # --- Status box ---
        status_box = QFrame()
        status_box.setObjectName("card")
        status_box.setStyleSheet(
            f"QFrame#card {{ background: rgba(0, 255, 170, 0.03); "
            f"border: 1px solid {theme.CYBER_BORDER_DEFAULT}; "
            f"border-radius: 4px; }}"
        )
        status_layout = QVBoxLayout(status_box)
        status_layout.setContentsMargins(12, 12, 12, 12)
        status_layout.setSpacing(8)

        status_eyebrow = make_label("// REAL-TIME", "metadataDisabled")
        status_eyebrow.setStyleSheet(
            f"color: {theme.CYBER_TEXT_MUTE}; font-size: 9px; font-weight: 700; "
            f"letter-spacing: 2px; background: transparent;"
        )
        status_layout.addWidget(status_eyebrow)

        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        self.sidebar_status_dot = StatusDot("active", glow=True, pulse=True)
        status_row.addWidget(self.sidebar_status_dot)
        self.sidebar_status_label = make_label("ACTIVE", "bodyText")
        self.sidebar_status_label.setStyleSheet(
            f"color: {theme.CYBER_NEON}; font-size: 11px; font-weight: 700; "
            f"letter-spacing: 1.5px; background: transparent;"
        )
        status_row.addWidget(self.sidebar_status_label)
        status_row.addStretch()
        status_layout.addLayout(status_row)

        layout.addWidget(status_box)
        layout.addSpacing(8)

        # --- Footer divider + version ---
        footer_divider = QFrame()
        footer_divider.setObjectName("sidebarDivider")
        footer_divider.setFixedHeight(1)
        layout.addWidget(footer_divider)

        footer = make_label("DEVADARA v1.0", "sidebarFooter")
        footer.setStyleSheet(
            f"color: {theme.CYBER_TEXT_MUTE}; font-size: 10px; "
            f"letter-spacing: 1px; background: transparent; padding: 10px 8px 0 8px;"
        )
        layout.addWidget(footer)

        self.app_state.protection_changed.connect(self._refresh_sidebar_status)
        self._refresh_sidebar_status()

        return sidebar

    def _refresh_sidebar_status(self):
        active = self.app_state.is_realtime_protection_enabled()
        self.sidebar_status_dot.set_state("active" if active else "attention")
        self.sidebar_status_label.setText("ACTIVE" if active else "OFF")
        color = theme.CYBER_NEON if active else theme.CYBER_TEXT_SECONDARY
        self.sidebar_status_label.setStyleSheet(
            f"color: {color}; font-size: 11px; font-weight: 700; "
            f"letter-spacing: 1.5px; background: transparent;"
        )

    def navigate_to(self, key):
        page = self.pages.get(key)
        if page is None:
            return
        self.stack.setCurrentWidget(page)
        for k, button in self.nav_buttons.items():
            button.setChecked(k == key)
        if key == "results":
            self.results_page.open_detected_tab()

    def _on_dashboard_scan_requested(self, mode):
        self.navigate_to("scan")
        self.scan_page.start_scan(mode)

    def _on_realtime_review(self, file_path):
        """Review, clicked on the real-time scan popup: same Results page,
        same scan_log-backed data — never a second threat-management UI."""
        self.navigate_to("results")
        self.results_page.open_detected_tab()
        if file_path:
            match = next(
                (f for f in self.app_state.list_detected_threats()
                 if f.get("file_path") == file_path),
                None,
            )
            if match is not None:
                self.results_page._show_details(match)

    def closeEvent(self, event):
        self.realtime_popup.close()
        self.scan_page.mini_popup.close()
        self.app_state.shutdown()
        super().closeEvent(event)