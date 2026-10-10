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
from PySide6.QtGui import QBrush, QColor, QIcon, QPainter, QPen, QPixmap, QRadialGradient
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
from devadara_gui import dialogs, theme
from devadara_gui.auto_scan_controller import AutoScanController
from devadara_gui.behavior_alert_popup import BehaviorAlertPopup
from devadara_gui.process_guard import ProcessGuard
from devadara_gui.results_store import ResultsStore
from devadara_gui.components import (
    NavItem, PageHeader, ScanOrbitLogo, load_orbit_layers, orbit_frame, scaled_image,
)
from devadara_gui.dashboard_page import DashboardPage
from devadara_gui.protection_page import ProtectionPage
from devadara_gui.results_page import ResultsPage
from devadara_gui.scan_page import ScanPage

# The processed (transparent-cornered) icon - used for the window/taskbar
# icon, the sidebar logo, and the Mini-Form popup header, so all three are
# always identical. Lives in theme.py (see its own comment) so
# mini_form_popup.py can import it too without an import cycle back here.
ICON_PATH = theme.ICON_PATH

TRAY_TOOLTIP = "DEVADARA — Antivirus Guard"
TRAY_MESSAGE_MS = 10_000

NAV_ITEMS = [
    ("▣", "Dashboard"),         # ▣
    ("⌖", "Scan"),              # ⌖
    ("\U0001F6E1", "Protection"),  # 🛡 - was ◈, duplicated Scan's icon
    ("▤", "Results"),           # ▤
    ("⚙", "Settings"),          # ⚙
]

# Dashboard (index 0), Scan (index 1), Protection (index 2) and Results
# (index 3) have real content - see DashboardPage/ScanPage/ProtectionPage/
# ResultsPage. The rest are still placeholders; this list stays in
# NAV_ITEMS order starting from index 4 so PLACEHOLDER_PAGES[i] lines up
# with NAV_ITEMS[i + 4].
PLACEHOLDER_PAGES = [
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

        tagline = QLabel("// ANTIVIRUS v1.0")
        tagline.setFont(theme.letter_spaced_font(size=theme.SIDEBAR_TAGLINE_PT, spacing=2))
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
        row.addWidget(self._dot)

        self._status_value = QLabel()
        self._status_value.setObjectName("statusValue")
        self._status_value.setFont(theme.letter_spaced_font(size=9, bold=True, spacing=1))
        row.addWidget(self._status_value)
        row.addStretch(1)

        box_layout.addLayout(row)
        wrap_layout.addWidget(box)

        self._blink_timer = QTimer(self)
        self._blink_timer.timeout.connect(self._toggle_dot)

        # Starts as STARTING... - never ACTIVE - until the controller
        # reports the watchers are really running (set_realtime_state).
        self._dot_color = QColor(theme.TEXT_DIM)
        self._status_value.setText("STARTING…")
        self._status_value.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self._update_dot()

        return wrap

    def set_realtime_state(self, active):
        """Connected to AutoScanController.realtime_state_changed."""
        if active:
            self._dot_color = QColor(theme.NEON)
            self._status_value.setText("ACTIVE")
            self._status_value.setStyleSheet(f"color: {theme.NEON};")
            self._status_value.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=8))
            self._blink_timer.start(1000)
        else:
            self._dot_color = QColor(theme.DANGER)
            self._status_value.setText("OFF")
            self._status_value.setStyleSheet(f"color: {theme.DANGER};")
            self._status_value.setGraphicsEffect(None)
            self._blink_timer.stop()
        self._dot_on = True
        self._update_dot()

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
    MAX_WIDTH = 1120
    MAX_HEIGHT = 655
    MIN_WIDTH = 900
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
        self.dashboard_page = DashboardPage(navigate=self.navigate_to)
        self.stack.addWidget(self.dashboard_page)
        self.scan_page = ScanPage(navigate=self.navigate_to, main_window=self,
                                   controller=self.auto_scan_controller)
        self.stack.addWidget(self.scan_page)
        self.protection_page = ProtectionPage(self.auto_scan_controller)
        self.stack.addWidget(self.protection_page)
        self.results_page = ResultsPage(self.results_store, self.process_guard)
        self.stack.addWidget(self.results_page)
        for title, subtitle in PLACEHOLDER_PAGES:
            self.stack.addWidget(PagePlaceholder(title, subtitle))
        layout.addWidget(self.stack, 1)

        self.setCentralWidget(central)
        self.sidebar.nav_group.idClicked.connect(self.stack.setCurrentIndex)

        self.setMinimumSize(self.MIN_WIDTH, self.MIN_HEIGHT)
        self.setMaximumSize(self.MAX_WIDTH, self.MAX_HEIGHT)
        self.resize(self.MAX_WIDTH, self.MAX_HEIGHT)

        self.auto_scan_controller.realtime_state_changed.connect(self.sidebar.set_realtime_state)
        self.auto_scan_controller.realtime_state_changed.connect(self.dashboard_page.set_realtime_state)

        self._build_tray_icon()

        # Orbit animation while any scan runs (manual, Downloads, USB,
        # queued) - see ScanPage.scan_active_changed.
        self.scan_page.scan_active_changed.connect(self.sidebar.logo.set_scanning)
        self.tray_animator = None
        if self.tray_icon is not None:
            self.tray_animator = TrayOrbitAnimator(self.tray_icon, self)
            self.scan_page.scan_active_changed.connect(self.tray_animator.set_scanning)
        self.scan_page.auto_scan_flagged.connect(self._on_auto_scan_flagged)
        self.scan_page.manual_scan_results.connect(self.results_store.set_last_scan)

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
        the result). Qt's own tray balloon, no PowerShell. Never acts on the
        findings."""
        if self.tray_icon is None or (self.isVisible() and not self.isMinimized()):
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

    def start_background_init(self):
        """Call right after show(). Loading the ML model is a real ~3-7s
        blocking call that has to stay on the GUI thread (see
        auto_scan_controller.py), so it's delayed long enough for the
        window to actually be painted first rather than raced against the
        first paint. Watchers only start once it's done, so a detection
        can never race an unloaded model, and the sidebar only says ACTIVE
        once they have."""
        QTimer.singleShot(150, self.auto_scan_controller.load_model)

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
        # Same path as pressing X - closeEvent hides to the tray, watchers
        # keep running.
        self.close()

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

    def _ok_to_quit(self):
        """The unreviewed-results reminder, for a REAL quit only (tray Exit,
        or X when there's no tray) - never for X-to-tray, and never while
        Windows is logging off or shutting down. "Review now" (the default;
        Enter/Escape) cancels the quit and opens the Results page. "Quit
        anyway" just drops the in-memory results - nothing is ignored or
        marked safe, so the next scan flags those files again."""
        if self._session_ending:
            return True
        pending = self.results_page.pending_count()
        if pending == 0:
            return True
        if dialogs.confirm(
                self, "Unreviewed results",
                f"There are {pending} results you have not acted on. Do you want to review them now?",
                "Quit anyway",
                details=("Quitting just forgets them - nothing is marked safe or ignored, "
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
