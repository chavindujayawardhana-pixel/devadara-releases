"""
main_window.py

The app shell (Phase 1): sidebar navigation + a content area that switches
between empty placeholder pages. No backend wiring and no real page content
yet - see components.py for the reusable pieces this is built from, and
CLAUDE.md / the mockup at assets/deepseek_html_20260917_f4ed9f.html for the
target design this replicates.
"""

import os

from PySide6.QtCore import QElapsedTimer, QEvent, QObject, Qt, QTimer
from PySide6.QtGui import QBrush, QColor, QFontMetrics, QIcon, QPainter, QPen, QPixmap, QRadialGradient
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from devadara import scan_log
from devadara.self_integrity import BAD_SIGNATURE, PROBLEMS
from devadara_gui import config_store as config, dialogs, protection_modules, scan_history, theme
from devadara_gui.auto_scan_controller import AutoScanController
from devadara_gui.behavior_alert_popup import BehaviorAlertPopup
from devadara_gui.process_guard import ProcessGuard
from devadara_gui.results_store import ResultsStore
from devadara_gui.components import (
    NavItem, PageHeader, ScanOrbitLogo, load_orbit_layers, orbit_frame, scaled_image,
)
from devadara_gui.dashboard_page import DashboardPage
from devadara_gui.integrity_check import IntegrityChecker
from devadara_gui.protection_page import ProtectionPage
from devadara_gui.results_page import ResultsPage
from devadara_gui.scan_page import ScanPage
from devadara_gui.settings_page import SettingsPage

# The processed (transparent-cornered) icon - used for the window/taskbar
# icon, the sidebar logo, and the Mini-Form popup header, so all three are
# always identical. Lives in theme.py (see its own comment) so
# mini_form_popup.py can import it too without an import cycle back here.
ICON_PATH = theme.ICON_PATH

TRAY_TOOLTIP = "DEVADARA — Antivirus Guard"
TRAY_MESSAGE_MS = 10_000
# The app-integrity self-check starts this long after start_background_init()
# - after the window is painted, alongside the model load.
INTEGRITY_CHECK_DELAY_MS = 3_000

NAV_ITEMS = [
    ("▣", "Dashboard"),         # ▣
    ("⌖", "Scan"),              # ⌖
    ("\U0001F6E1", "Protection"),  # 🛡 - was ◈, duplicated Scan's icon
    ("▤", "Results"),           # ▤
    ("⚙", "Settings"),          # ⚙
]

# Every NAV_ITEMS page has real content (DashboardPage, ScanPage,
# ProtectionPage, ResultsPage, SettingsPage). PagePlaceholder stays for any
# page added later before its content exists.


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
        self.setFixedWidth(theme.SIDEBAR_WIDTH)
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

        # Rotates its orbit ring while a scan runs - wired up in MainWindow.
        self.logo = ScanOrbitLogo(theme.SIDEBAR_LOGO_SIZE)
        row.addWidget(self.logo)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)

        wordmark = QLabel(
            f'<span style="color:{theme.NEON};">DEVA</span>'
            f'<span style="color:{theme.TEXT};">DARA</span>'
        )
        wordmark.setFont(theme.letter_spaced_font(size=theme.SIDEBAR_NAME_PT, black=True, spacing=2))
        wordmark.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=14))
        text_col.addWidget(wordmark)

        # One line under the wordmark, left-aligned with it. Fixed height
        # (one line) and never wrapped: the logo row stays the logo's height,
        # so nothing below it moves; SIDEBAR_WIDTH is sized so it never clips.
        font = theme.letter_spaced_font(spacing=theme.SIDEBAR_TAGLINE_SPACING)
        font.setPixelSize(theme.SIDEBAR_TAGLINE_PX)
        self.tagline = QLabel("Natural Defense. Digital World.")
        self.tagline.setFont(font)
        self.tagline.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.tagline.setWordWrap(False)
        self.tagline.setFixedHeight(QFontMetrics(font).lineSpacing())
        text_col.addWidget(self.tagline)

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

        label = QLabel("// PROTECTION")
        label.setObjectName("statusLabel")
        label.setFont(theme.letter_spaced_font(size=7, bold=True, spacing=2))
        box_layout.addWidget(label)

        row = QHBoxLayout()
        row.setSpacing(8)

        self._dot = QLabel()
        self._dot.setFixedSize(8, 8)
        self._dot.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._dot_on = True
        row.addWidget(self._dot)

        self._status_value = QLabel()
        self._status_value.setObjectName("statusValue")
        self._status_value.setFont(theme.letter_spaced_font(size=9, bold=True, spacing=1))
        row.addWidget(self._status_value)
        row.addStretch(1)

        box_layout.addLayout(row)

        # Shown only while no scan was ever finished - so SECURED never
        # reads as "already scanned" (same text as the Dashboard hero).
        self._scan_note = QLabel(scan_history.NO_SCAN_YET)
        self._scan_note.setObjectName("statusLabel")
        self._scan_note.setFont(theme.letter_spaced_font(size=7, spacing=1))
        self._scan_note.setStyleSheet(f"color: {theme.TEXT_DIM};")
        box_layout.addWidget(self._scan_note)
        wrap_layout.addWidget(box)

        self._blink_timer = QTimer(self)
        self._blink_timer.timeout.connect(self._toggle_dot)

        # Starts as STARTING... - never SECURED - until the controller
        # reports the watchers are really running (set_protection_level).
        self._dot_color = QColor(theme.TEXT_DIM)
        self._status_value.setText("STARTING…")
        self._status_value.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self._update_dot()

        return wrap

    def set_protection_level(self, level):
        """Connected to AutoScanController.protection_level_changed - the
        same label and colour as the Dashboard (protection_modules.
        LEVEL_VIEW). The dot blinks while anything is protecting."""
        label, token = protection_modules.LEVEL_VIEW.get(
            level, protection_modules.LEVEL_VIEW[protection_modules.STARTING])
        color = getattr(theme, token)
        running = level in (protection_modules.SECURED, protection_modules.PARTIAL)
        self._dot_color = QColor(color)
        self._status_value.setText(label)
        self._status_value.setStyleSheet(f"color: {color};")
        self._status_value.setGraphicsEffect(theme.glow_effect(color, blur=8) if running else None)
        if running:
            self._blink_timer.start(1000)
        else:
            self._blink_timer.stop()
        self._dot_on = True
        self._update_dot()

    def set_scan_done(self, done):
        """Hide "No scan yet" once a scan has been recorded."""
        self._scan_note.setVisible(not done)

    def _toggle_dot(self):
        self._dot_on = not self._dot_on
        self._update_dot()

    def _update_dot(self):
        color = self._dot_color
        alpha = 255 if self._dot_on else 70
        self._dot.setStyleSheet(
            f"background-color: rgba({color.red()}, {color.green()}, {color.blue()}, {alpha}); "
            f"border-radius: 4px; border: none;"
        )


class PagePlaceholder(QWidget):
    """A page-header-only stand-in for real page content (later phases)."""

    def __init__(self, title, subtitle, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 60)
        layout.setSpacing(0)

        layout.addWidget(PageHeader(title, subtitle))
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


class TrayOrbitAnimator(QObject):
    """Rotates the tray icon's orbit ring while a scan runs (the sidebar's
    version is components.ScanOrbitLogo). Frames are built once, on the
    first scan, and cached: the ring is 180-degree symmetric, so 12 frames
    at 15-degree steps loop seamlessly - same speed as the sidebar, but at
    ~10fps since every setIcon() is a round-trip to the Windows shell."""

    FRAME_COUNT = 12
    FRAME_MS = 100
    # A single-file auto-scan (e.g. one new PDF in Downloads) can finish in
    # ~0.1s - before the first tick - so it would never visibly spin. Once
    # started, the ring always completes at least one full loop.
    MIN_SPIN_MS = FRAME_COUNT * FRAME_MS
    ICON_SIZES = (16, 24, 32)
    SCANNING_TOOLTIP = "DEVADARA — scanning…"

    def __init__(self, tray_icon, parent=None):
        super().__init__(parent)
        self._tray = tray_icon
        self._layers = load_orbit_layers()
        self._frames = None
        self._index = 0
        self._timer = QTimer(self)
        self._timer.setInterval(self.FRAME_MS)
        self._timer.timeout.connect(self._next_frame)
        self._spin_clock = QElapsedTimer()
        self._stop_timer = QTimer(self)
        self._stop_timer.setSingleShot(True)
        self._stop_timer.timeout.connect(self._stop)

    def set_scanning(self, scanning):
        """Connected to ScanPage.scan_active_changed."""
        if self._layers is None:
            return
        if scanning:
            self._stop_timer.stop()
            if self._timer.isActive():
                return  # still finishing the previous scan's minimum loop
            if self._frames is None:
                self._frames = self._build_frames()
            self._index = 1  # frame 0 looks identical to the static icon
            self._spin_clock.start()
            self._tray.setToolTip(self.SCANNING_TOOLTIP)
            self._next_frame()  # visibly rotated now, not one tick later
            self._timer.start()
        elif self._timer.isActive():
            remaining = self.MIN_SPIN_MS - self._spin_clock.elapsed()
            if remaining > 0:
                self._stop_timer.start(remaining)
            else:
                self._stop()

    def _stop(self):
        self._timer.stop()
        self._tray.setIcon(QIcon(ICON_PATH))
        self._tray.setToolTip(TRAY_TOOLTIP)

    def _build_frames(self):
        base, orbit = self._layers
        sized = [(scaled_image(base, s), scaled_image(orbit, s)) for s in self.ICON_SIZES]
        frames = []
        for i in range(self.FRAME_COUNT):
            angle = 180.0 * i / self.FRAME_COUNT
            icon = QIcon()
            for b, o in sized:
                icon.addPixmap(QPixmap.fromImage(orbit_frame(b, o, angle)))
            frames.append(icon)
        return frames

    def _next_frame(self):
        self._tray.setIcon(self._frames[self._index])
        self._index = (self._index + 1) % self.FRAME_COUNT


class MainWindow(QMainWindow):
    # Widths include the sidebar (theme.SIDEBAR_WIDTH, 300): the content
    # area is 880px at the default/largest size and 660px at the smallest -
    # widened by the same 60px as the sidebar so every page keeps its room.
    MAX_WIDTH = 1180
    MAX_HEIGHT = 655
    MIN_WIDTH = 960
    MIN_HEIGHT = 560

    def __init__(self):
        super().__init__()
        self.setWindowTitle("DEVADARA — Antivirus Guard")
        if os.path.exists(ICON_PATH):
            self.setWindowIcon(QIcon(ICON_PATH))

        self.setStyleSheet(theme.build_stylesheet())

        self.auto_scan_controller = AutoScanController(self)
        # One ProcessGuard for the whole app (behavior popup + Results page),
        # so "suspended by DEVADARA" - what Resume requires - is shared.
        self.process_guard = ProcessGuard()
        # The last manual scan's results, in memory only (Results page).
        self.results_store = ResultsStore(self)

        central = BackgroundCanvas()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.sidebar = Sidebar()
        layout.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        self.dashboard_page = DashboardPage(navigate=self.navigate_to,
                                            config_store=self.auto_scan_controller.config_store)
        self.stack.addWidget(self.dashboard_page)
        self.scan_page = ScanPage(navigate=self.navigate_to, main_window=self,
                                   controller=self.auto_scan_controller)
        self.stack.addWidget(self.scan_page)
        self.protection_page = ProtectionPage(self.auto_scan_controller)
        self.stack.addWidget(self.protection_page)
        self.results_page = ResultsPage(self.results_store, self.process_guard,
                                        config_store=self.auto_scan_controller.config_store)
        self.stack.addWidget(self.results_page)
        self.settings_page = SettingsPage(self.auto_scan_controller.config_store)
        self.stack.addWidget(self.settings_page)
        layout.addWidget(self.stack, 1)

        self.setCentralWidget(central)
        self.sidebar.nav_group.idClicked.connect(self.stack.setCurrentIndex)

        self.setMinimumSize(self.MIN_WIDTH, self.MIN_HEIGHT)
        self.setMaximumSize(self.MAX_WIDTH, self.MAX_HEIGHT)
        self.resize(self.MAX_WIDTH, self.MAX_HEIGHT)

        self.auto_scan_controller.protection_level_changed.connect(self.sidebar.set_protection_level)
        self.auto_scan_controller.protection_level_changed.connect(self.dashboard_page.set_protection_level)
        self.refresh_last_scan()

        self._build_tray_icon()

        # App integrity self-check (read-only): shortly after startup and on
        # the Dashboard's "Check now" - see integrity_check.py.
        self.integrity_checker = IntegrityChecker(self)
        self.integrity_checker.started.connect(self.dashboard_page.set_integrity_checking)
        self.integrity_checker.finished.connect(self.dashboard_page.set_integrity_result)
        self.integrity_checker.finished.connect(self._on_integrity_result)
        self.dashboard_page.integrity_check_requested.connect(self.integrity_checker.start)

        # Orbit animation while any scan runs (manual, Downloads, USB,
        # queued) - see ScanPage.scan_active_changed.
        self.scan_page.scan_active_changed.connect(self.sidebar.logo.set_scanning)
        self.tray_animator = None
        if self.tray_icon is not None:
            self.tray_animator = TrayOrbitAnimator(self.tray_icon, self)
            self.scan_page.scan_active_changed.connect(self.tray_animator.set_scanning)
        self.scan_page.auto_scan_flagged.connect(self._on_auto_scan_flagged)
        self.scan_page.manual_scan_results.connect(self.results_store.set_last_scan)
        self.scan_page.scan_recorded.connect(self.refresh_last_scan)
        self.scan_page.scan_completed.connect(self._on_scan_completed)

        # Settings › General: Auto-delete gates the Results page's Delete
        # Permanently; Clear scan history -> re-read the emptied scan log.
        self.settings_page.auto_delete_changed.connect(
            lambda value: self.results_page.set_delete_allowed(value != config.AUTO_DELETE_NEVER))
        self.settings_page.history_cleared.connect(self.results_page.refresh)
        self.settings_page.history_cleared.connect(self.dashboard_page.refresh_stats)
        # Settings › Exceptions added/removed an ignore-list entry. Neither
        # page reads the ignore list today; refreshing keeps them in step
        # if one ever does.
        self.settings_page.ignore_list_changed.connect(self.results_page.refresh)
        self.settings_page.ignore_list_changed.connect(self.dashboard_page.refresh_stats)

        # Windows is logging off / shutting down: never hold that up with
        # the unreviewed-results reminder (see _ok_to_quit).
        self._session_ending = False
        QApplication.instance().commitDataRequest.connect(self._on_session_ending)

        # Behavior monitoring (alert only): log, popup, tray message. The
        # popup's Suspend/Resume/Kill each need their own confirmation.
        self.behavior_popup = BehaviorAlertPopup(guard=self.process_guard, parent=self)
        self.auto_scan_controller.behavior_alert.connect(self._on_behavior_alert)

        # Logon auto-hide (see schedule_auto_hide) - only ever started for
        # an --autostart launch.
        self._auto_hide_timer = QTimer(self)
        self._auto_hide_timer.setSingleShot(True)
        self._auto_hide_timer.timeout.connect(self._on_auto_hide_timeout)

    def schedule_boot_sweep(self, delay_ms):
        """For a Windows-logon (--autostart) launch only: one Downloads
        sweep through the normal scan queue, delay_ms after startup (well
        after the model load), catching what arrived while the PC was off."""
        QTimer.singleShot(delay_ms, self.scan_page.start_boot_sweep)

    def _on_auto_scan_flagged(self, label, findings):
        """Tray notification for an auto-scan's findings - only while the
        window is hidden/minimized (otherwise the scan popup already shows
        the result). Qt's own tray balloon, no PowerShell. Off with Settings ›
        Notifications. Never acts on the findings."""
        if not self._tray_message_wanted():
            return
        first = findings[0]
        area = label.split(":", 1)[0]  # "Downloads" / "USB drive" / "Startup scan"
        name = os.path.basename(first["file_path"])
        more = f" and {len(findings) - 1} more" if len(findings) > 1 else ""
        self.tray_icon.showMessage(
            f"DEVADARA: {len(findings)} item(s) flagged",
            f"{area}: {name} — {first['tier']}{more}. Open DEVADARA to review.",
            QSystemTrayIcon.MessageIcon.Warning,
            TRAY_MESSAGE_MS,
        )

    def _tray_message_wanted(self):
        """The "item(s) flagged" and "scan finished" tray messages: only
        while the window is hidden/minimized, and only with Settings ›
        Notifications on. (The ransomware-alert and app-integrity messages
        don't use this - they always show.)"""
        if self.tray_icon is None or (self.isVisible() and not self.isMinimized()):
            return False
        return config.tray_notifications_on(self.auto_scan_controller.config_store)

    def _on_scan_completed(self, kind, checked, threats, flagged_announced):
        """Tray message for a finished manual scan or startup scan - skipped
        when the "item(s) flagged" message already went out for it."""
        if flagged_announced or not self._tray_message_wanted():
            return
        self.tray_icon.showMessage(
            "DEVADARA: scan finished",
            f"{kind} finished — {checked} file(s) checked, {threats} flagged."
            + (" Open DEVADARA to review." if threats else ""),
            QSystemTrayIcon.MessageIcon.Warning if threats else QSystemTrayIcon.MessageIcon.Information,
            TRAY_MESSAGE_MS,
        )

    def _on_behavior_alert(self, alert):
        scan_log.record_behavior_alert(alert)
        # Tray message first: decided and sent before the popup is shown and
        # takes focus, so the popup can't affect either.
        if self.tray_icon is not None and (not self.isVisible() or self.isMinimized()):
            folder = os.path.basename(os.path.normpath(alert["folder"])) or alert["folder"]
            self.tray_icon.showMessage(
                "DEVADARA: possible ransomware-like activity",
                f"Unusually many file changes in {folder}. Open DEVADARA to review.",
                QSystemTrayIcon.MessageIcon.Warning,
                TRAY_MESSAGE_MS,
            )
        self.behavior_popup.show_alert(alert)

    def refresh_last_scan(self):
        """Sidebar "No scan yet" + Dashboard hero, from scan_history."""
        self.sidebar.set_scan_done(
            scan_history.last_scan(self.auto_scan_controller.config_store) is not None)
        self.dashboard_page.refresh_last_scan()

    def start_background_init(self):
        """Call right after show(). Loading the ML model is a real ~3-7s
        blocking call that has to stay on the GUI thread (see
        auto_scan_controller.py), so it's delayed long enough for the
        window to actually be painted first rather than raced against the
        first paint. Watchers only start once it's done, so a detection
        can never race an unloaded model, and the sidebar only says SECURED
        once they have."""
        QTimer.singleShot(150, self.auto_scan_controller.load_model)
        QTimer.singleShot(INTEGRITY_CHECK_DELAY_MS, self.integrity_checker.start)

    def _on_integrity_result(self, result):
        """Tray message when the self-check finds a problem while the window
        is hidden - the Dashboard shows it otherwise. Notifies only; the
        check never changes or removes anything."""
        if result.get("status") not in (PROBLEMS, BAD_SIGNATURE):
            return
        if self.tray_icon is None or (self.isVisible() and not self.isMinimized()):
            return
        self.tray_icon.showMessage(
            "DEVADARA: app integrity problem",
            "Some of DEVADARA's own program files don't match its signed manifest. "
            "Open DEVADARA → Dashboard → App integrity for details.",
            QSystemTrayIcon.MessageIcon.Warning,
            TRAY_MESSAGE_MS,
        )

    def schedule_auto_hide(self, delay_ms):
        """For a Windows-logon (--autostart) launch: hide to the tray after
        delay_ms unless the user clicks or types in the window first.
        Never armed without a tray icon to hide into."""
        if self.tray_icon is None:
            return
        QApplication.instance().installEventFilter(self)
        self._auto_hide_timer.start(delay_ms)

    def cancel_auto_hide(self):
        if not self._auto_hide_timer.isActive():
            return
        self._auto_hide_timer.stop()
        QApplication.instance().removeEventFilter(self)

    def _on_auto_hide_timeout(self):
        QApplication.instance().removeEventFilter(self)
        if self.tray_icon is None or self.scan_page.is_scan_running():
            return
        # Hide to the tray, watchers keep running - directly, not via
        # close(), so this automatic hide never shows the X-button's
        # unreviewed-results reminder.
        self.hide()

    def eventFilter(self, watched, event):
        # Only installed while an auto-hide is pending.
        if event.type() in (QEvent.Type.MouseButtonPress,
                            QEvent.Type.NonClientAreaMouseButtonPress,
                            QEvent.Type.KeyPress):
            if isinstance(watched, QWidget) and watched.window() is self:
                self.cancel_auto_hide()
        return super().eventFilter(watched, event)

    def _build_tray_icon(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            # No tray to live in (e.g. the shell's tray area isn't up
            # yet) - closeEvent/_exit_app below both check for this and
            # fall back to a normal close instead of hiding to nothing.
            self.tray_icon = None
            return

        self.tray_icon = QSystemTrayIcon(self)
        if os.path.exists(ICON_PATH):
            self.tray_icon.setIcon(QIcon(ICON_PATH))
        self.tray_icon.setToolTip(TRAY_TOOLTIP)

        menu = QMenu()
        show_action = menu.addAction("Show DEVADARA")
        show_action.triggered.connect(self._restore_from_tray)
        menu.addSeparator()
        exit_action = menu.addAction("Exit")
        exit_action.triggered.connect(self._exit_app)
        self.tray_icon.setContextMenu(menu)

        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.messageClicked.connect(self._restore_from_tray)
        self.tray_icon.show()

    def _on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.Trigger,
                      QSystemTrayIcon.ActivationReason.DoubleClick):
            self._restore_from_tray()

    def _restore_from_tray(self):
        # Covers a second launch's SHOW message and the tray's "Show
        # DEVADARA" - an explicit request to see the window wins over a
        # pending logon auto-hide.
        self.cancel_auto_hide()
        self.show()
        self.raise_()
        self.activateWindow()

    def _on_session_ending(self, *_):
        self._session_ending = True

    def _ok_to_quit(self, action_label="Quit anyway", verb="Quitting"):
        """The unreviewed-results reminder: before a real quit (tray Exit,
        or X when there's no tray) and before X hides the window to the
        tray - never while Windows is logging off or shutting down.
        "Review now" (the default; Enter/Escape) keeps the window open on
        the Results page. The other button only forgets the in-memory
        results - nothing is ignored or marked safe, so the next scan flags
        those files again."""
        if self._session_ending:
            return True
        pending = self.results_page.pending_count()
        if pending == 0:
            return True
        if dialogs.confirm(
                self, "Unreviewed results",
                f"There are {pending} results you have not acted on. Do you want to review them now?",
                action_label,
                details=(f"{verb} just forgets them - nothing is marked safe or ignored, "
                         "and the next scan will flag these files again."),
                cancel_label="Review now"):
            return True
        self._restore_from_tray()
        self.navigate_to(3)  # Results
        return False

    def _exit_app(self):
        if not self._ok_to_quit():
            return
        self.scan_page.force_stop_running_scan()
        self.auto_scan_controller.stop_all_watches()
        if self.tray_icon is not None:
            self.tray_icon.hide()
        QApplication.instance().quit()

    def changeEvent(self, event):
        # Coming back to the window (e.g. from Task Manager's Startup apps
        # tab) - refresh the Windows Startup toggle so it never shows stale
        # state. Display only; nothing here writes to the registry.
        if event.type() == QEvent.Type.ActivationChange and self.isActiveWindow():
            self.protection_page.refresh_startup_state()
        super().changeEvent(event)

    def closeEvent(self, event):
        # X minimizes to the tray (the app keeps running so auto-scan
        # watchers stay active) rather than quitting - real quitting only
        # happens via the tray icon's own Exit action (_exit_app). If a
        # scan is actively running, confirm first: closing to tray with a
        # scan silently still running in the background with no visible
        # popup/window would be confusing, so this path stops it (after
        # confirmation) rather than leaving it orphaned.
        if self.tray_icon is None and not self._ok_to_quit():
            # No tray means X really quits - the unreviewed-results
            # reminder comes first, before anything is stopped.
            event.ignore()
            return
        # With a tray, X hides - but pending last-scan results get the same
        # reminder first. "Close anyway" forgets them (memory only), so the
        # window reopens on an empty Results page.
        forget_results = (self.tray_icon is not None and not self._session_ending
                          and self.results_page.pending_count() > 0)
        if forget_results and not self._ok_to_quit("Close anyway", "Closing"):
            event.ignore()
            return
        if self.scan_page.is_scan_running():
            box = QMessageBox(self)
            box.setWindowTitle("Scan is running")
            box.setText("Closing will stop the current scan. Are you sure?")
            keep_button = box.addButton("Keep Scanning", QMessageBox.ButtonRole.RejectRole)
            close_button = box.addButton("Yes, Close", QMessageBox.ButtonRole.DestructiveRole)
            box.setDefaultButton(keep_button)
            box.exec()
            if box.clickedButton() is not close_button:
                event.ignore()
                return
            self.scan_page.force_stop_running_scan()

        if self.tray_icon is None:
            # No tray to hide into - hiding would leave an invisible,
            # unreachable process, so close for real instead (the
            # unreviewed-results reminder already ran above).
            self.auto_scan_controller.stop_all_watches()
            event.accept()
            return

        if forget_results:
            self.results_store.clear()
        event.ignore()
        self.hide()

    def navigate_to(self, index, mode=None):
        """Switch both the content stack and the sidebar's active nav item
        to the given page index - used by DashboardPage's Quick Actions,
        and any later phase's own in-page navigation shortcuts.

        mode: optional - for the Scan page, also selects that mode (e.g.
        Dashboard's Quick Scan/Full Scan cards land with the matching mode
        already applied, not just whatever it last was)."""
        self.sidebar.nav_items[index].setChecked(True)
        self.stack.setCurrentIndex(index)
        if mode is not None:
            page = self.stack.widget(index)
            if isinstance(page, ScanPage):
                page.select_mode(mode)
