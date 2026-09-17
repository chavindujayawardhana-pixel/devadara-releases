"""
main_window.py

The application shell (Section 2): a fixed 240px sidebar (never collapses)
plus a QStackedWidget content area, with a toast overlay on top. Sidebar
navigation and page wiring live here; each page only ever talks to the
shared AppState, never to another page directly.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
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

NAV_ITEMS = [
    ("dashboard", "Dashboard"),
    ("scan", "Scan"),
    ("protection", "Protection"),
    ("threats", "Threats"),
    ("settings", "Settings"),
]


class NavButton(QPushButton):
    def __init__(self, icon_name, label, parent=None):
        super().__init__(parent)
        self.setObjectName("navRow")
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(44)
        self._icon_name = icon_name

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 12, 0)
        layout.setSpacing(10)
        self._icon = icon_label(icon_name, size=15, color=theme.NAV_INACTIVE_ICON)
        layout.addWidget(self._icon)
        self._label = make_label(label, "bodyText")
        self._label.setStyleSheet(f"color: {theme.NAV_INACTIVE_TEXT}; font-size: 12px; background: transparent;")
        layout.addWidget(self._label)
        layout.addStretch()

    def setChecked(self, checked):
        super().setChecked(checked)
        self.setProperty("active", "true" if checked else "false")
        self.style().unpolish(self)
        self.style().polish(self)
        # Exact reference values: active nav text #EFFFF6, active icon
        # #7CFFB2 - both distinct from the inactive #B7D9C4 / #7AA98C pair.
        label_color = theme.NAV_ACTIVE_TEXT if checked else theme.NAV_INACTIVE_TEXT
        icon_color = theme.NAV_ACTIVE_ICON if checked else theme.NAV_INACTIVE_ICON
        self._icon.setStyleSheet(icon_style(icon_color))
        self._label.setStyleSheet(
            f"color: {label_color}; font-size: 12px; font-weight: {'600' if checked else '500'}; background: transparent;"
        )
        if checked:
            # box-shadow 0 0 12px rgba(60,220,140,0.25) - the reference's
            # exact active-nav-item glow value.
            theme.apply_glow(self, theme.NAV_ACTIVE_GLOW, blur=12)
        else:
            theme.clear_glow(self)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DEVADARA")
        self.setMinimumSize(1180, 720)

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
        self.threats_page = ThreatsPage(self.app_state)
        self.settings_page = SettingsPage(self.app_state)

        self.pages = {
            "dashboard": self.dashboard_page,
            "scan": self.scan_page,
            "protection": self.protection_page,
            "threats": self.threats_page,
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

        # RealTimeScanPopup is a separate top-level window (near the screen's
        # bottom-right corner, not confined to this window's bounds - see
        # its own docstring for why), shared by both the Downloads watcher
        # and USB auto-scan real-time triggers via AppState.realtime_scan_requested.
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
        layout.setContentsMargins(12, 20, 12, 16)
        layout.setSpacing(0)

        # Logo mark + wordmark - reintroduced per the new reference file's
        # exact spec (a prior design pass had removed this as a duplicate
        # of the window titlebar's "DEVADARA" text; the new reference
        # explicitly specifies this element's own gradient/glow, so it's
        # back, superseding that earlier call).
        logo_row = QHBoxLayout()
        logo_row.setSpacing(8)
        logo_row.setContentsMargins(8, 0, 0, 0)
        logo_dot = QFrame()
        logo_dot.setFixedSize(26, 26)
        logo_dot.setStyleSheet(f"background: {theme.GRADIENT_LOGO}; border-radius: 13px; border: none;")
        theme.apply_glow(logo_dot, theme.LOGO_GLOW, blur=14)
        logo_row.addWidget(logo_dot)
        logo_row.addWidget(make_label("DEVADARA", "sidebarLogo"))
        logo_row.addStretch()
        logo_wrap = QWidget()
        logo_wrap.setObjectName("transparentPanel")
        logo_wrap.setLayout(logo_row)
        logo_wrap.setContentsMargins(0, 0, 0, 24)
        layout.addWidget(logo_wrap)

        self.nav_buttons = {}
        for key, label in NAV_ITEMS:
            button = NavButton(key, label)
            button.clicked.connect(lambda _checked=False, k=key: self.navigate_to(k))
            layout.addWidget(button)
            self.nav_buttons[key] = button

        divider = QFrame()
        divider.setObjectName("sidebarDivider")
        divider.setFixedHeight(1)
        layout.addWidget(divider)

        # Moved to sit directly below the nav items (no stretch before it)
        # rather than pinned to the bottom with everything else - pinning
        # both this block AND the footer to the bottom left a large dead
        # gap directly under Settings. Only the stretch below (pushing just
        # the version footer down) is left to create bottom spacing now.
        status_block = QVBoxLayout()
        status_block.setContentsMargins(10, 14, 10, 14)
        status_block.setSpacing(8)
        status_label = make_label("REAL-TIME\nPROTECTION", "eyebrowLabel")
        status_label.setWordWrap(True)
        status_block.addWidget(status_label)
        status_row = QHBoxLayout()
        self.sidebar_status_dot = StatusDot("active", glow=True)
        status_row.addWidget(self.sidebar_status_dot)
        self.sidebar_status_label = make_label("Active", "bodyText")
        status_row.addWidget(self.sidebar_status_label)
        status_row.addStretch()
        status_block.addLayout(status_row)
        layout.addLayout(status_block)

        layout.addStretch()

        footer_divider = QFrame()
        footer_divider.setObjectName("sidebarDivider")
        footer_divider.setFixedHeight(1)
        layout.addWidget(footer_divider)

        footer = make_label("DEVADARA v1.0", "sidebarFooter")
        footer.setContentsMargins(20, 12, 20, 0)
        layout.addWidget(footer)

        self.app_state.protection_changed.connect(self._refresh_sidebar_status)
        self._refresh_sidebar_status()

        return sidebar

    def _refresh_sidebar_status(self):
        active = self.app_state.is_realtime_protection_enabled()
        self.sidebar_status_dot.set_state("active" if active else "attention")
        self.sidebar_status_label.setText("Active" if active else "Off")
        color = theme.ROW_ACTIVE_VALUE_COLOR if active else theme.TEXT_SECONDARY
        self.sidebar_status_label.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: 600;")

    def navigate_to(self, key):
        page = self.pages.get(key)
        if page is None:
            return
        self.stack.setCurrentWidget(page)
        for k, button in self.nav_buttons.items():
            button.setChecked(k == key)
        if key == "threats":
            self.threats_page.open_detected_tab()

    def _on_dashboard_scan_requested(self, mode):
        self.navigate_to("scan")
        self.scan_page.start_scan(mode)

    def _on_realtime_review(self, file_path):
        """Review, clicked on the real-time scan popup: same Threats page,
        same scan_log-backed data - never a second threat-management UI."""
        self.navigate_to("threats")
        self.threats_page.open_detected_tab()
        if file_path:
            match = next(
                (f for f in self.app_state.list_detected_threats() if f.get("file_path") == file_path),
                None,
            )
            if match is not None:
                self.threats_page._show_details(match)

    def closeEvent(self, event):
        self.realtime_popup.close()
        self.scan_page.mini_popup.close()
        self.app_state.shutdown()
        super().closeEvent(event)
