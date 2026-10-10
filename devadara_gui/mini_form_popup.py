"""
mini_form_popup.py

A small floating, frameless, always-on-top popup ("Mini-Form") shown when
the user clicks Minimize on the Scan page's active-scan screen - it
mirrors the SAME running scan's real ScanWorker signals (never fake/
simulated data), positioned bottom-right of the desktop like a Windows
toast notification. See scan_page.py's ScanPage for the wiring: the same
ScanWorker signals connected to ScanProgressView are also connected to
this popup's slots, and Minimize/Details >> hide/restore the main window
around it.

Visually matches assets/deepseek_html_20260918_dc9754.html, with two
confirmed, deliberate deviations:
  - No close (X) button, even though the mockup has one - Stop and
    Details >> cover everything needed.
  - The mockup's percent number is replaced with the live Files-Checked
    count, in the same slot/styling - there's no real "total" any more to
    compute a percent from (ScanWorker.progress is Signal(str, int), just
    label + checked), the same fix already applied to ScanProgressView's
    own progress row for the same reason.
"""

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from devadara_gui import theme
from devadara_gui.components import Button, Card


class _MiniStatsBox(QFrame):
    """The mockup's single shared dark box holding all 3 stats side by
    side - unlike StatCard (three separately-bordered tiles, used on the
    main Scan page), this is one box with plain, centered, unbordered
    stat items."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("miniStatsBox")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(6)

        self._files_value = self._add_stat(layout, "Files", theme.NEON)
        self._threats_value = self._add_stat(layout, "Threats", theme.DANGER)
        self._hidden_value = self._add_stat(layout, "Hidden", theme.WARN)

    def _add_stat(self, layout, label_text, color):
        col = QVBoxLayout()
        col.setSpacing(1)

        label = QLabel(f"// {label_text}".upper())
        label.setFont(theme.letter_spaced_font(size=6, bold=True, spacing=0.5))
        label.setStyleSheet(f"color: {theme.TEXT_MUTE};")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        col.addWidget(label)

        value = QLabel("0")
        value.setFont(theme.letter_spaced_font(size=10, black=True))
        value.setStyleSheet(f"color: {color};")
        value.setGraphicsEffect(theme.glow_effect(color, blur=6))
        value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        col.addWidget(value)

        layout.addLayout(col, 1)
        return value

    def set_values(self, checked, threats, hidden):
        self._files_value.setText(f"{checked:,}")
        self._threats_value.setText(str(threats))
        self._hidden_value.setText(str(hidden))


class MiniFormPopup(QWidget):
    """The floating popup itself. Not shown by default - ScanPage calls
    show_positioned()/hide() around it, and connects ScanWorker's real
    signals to update_progress()/update_stats()/show_finished() alongside
    its own ScanProgressView connections."""

    details_requested = Signal()
    stop_requested = Signal()

    # A genuinely compact size (SMADAV-style small scan dialog), not the
    # full 520px mockup card - same visual language, much smaller
    # footprint. Button/label sizes below are tuned to match.
    _WIDTH = 300
    _MARGIN = 20

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        self._card = card = Card(title="")
        card.setObjectName("miniWindowPanel")
        card.setFixedWidth(self._WIDTH)
        card.layout().setContentsMargins(12, 10, 12, 12)
        outer.addWidget(card)

        content = card.content_layout
        content.setSpacing(6)
        content.addLayout(self._build_header())
        content.addWidget(self._build_divider())

        self._path_label = QLabel("// initializing scan engine...")
        self._path_label.setWordWrap(True)
        self._path_label.setFont(theme.letter_spaced_font(size=7, spacing=0.2))
        self._set_path_color(theme.CYAN)
        content.addWidget(self._path_label)

        progress_row = QHBoxLayout()
        progress_row.setSpacing(8)

        # Occupies the mockup's percent slot - shows the live Files-Checked
        # count instead (see module docstring for why).
        self._checked_label = QLabel("0")
        self._checked_label.setFont(theme.letter_spaced_font(size=12, black=True, spacing=0.5))
        self._checked_label.setStyleSheet(f"color: {theme.NEON};")
        self._checked_label.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=8))
        self._checked_label.setMinimumWidth(36)
        progress_row.addWidget(self._checked_label)

        self._progress_bar = QProgressBar()
        self._progress_bar.setObjectName("scanProgressBar")
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setFixedHeight(5)
        self._progress_bar.setRange(0, 0)  # always indeterminate - no real total exists
        progress_row.addWidget(self._progress_bar, 1)

        content.addLayout(progress_row)

        self._stats_box = _MiniStatsBox()
        content.addWidget(self._stats_box)

        buttons_row = QHBoxLayout()
        buttons_row.setSpacing(6)

        self._stop_button = Button("Stop", variant="secondary")
        self._stop_button.setStyleSheet("padding: 5px 8px;")
        self._stop_button.clicked.connect(self.stop_requested.emit)
        buttons_row.addWidget(self._stop_button, 1)

        details_button = Button("Details >>", variant="primary")
        details_button.setStyleSheet("padding: 5px 8px;")
        details_button.clicked.connect(self.details_requested.emit)
        buttons_row.addWidget(details_button, 1)

        content.addLayout(buttons_row)

        # Auto-scan-only fade-out (see show_auto_scan_result): a clean
        # result shows briefly then fades on its own; a threat result never
        # starts this timer at all, so it stays until Details >>. Applied
        # to the whole popup (a top-level frameless/translucent window),
        # not a child label - the first use of QGraphicsOpacityEffect in
        # this codebase in that configuration, verify it renders correctly.
        self._opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._opacity_effect)
        self._fade_anim = QPropertyAnimation(self._opacity_effect, b"opacity", self)
        self._fade_anim.setDuration(400)
        self._fade_anim.setEasingCurve(QEasingCurve.Type.OutQuad)
        self._fade_anim.finished.connect(self._on_fade_finished)
        self._fade_timer = QTimer(self)
        self._fade_timer.setSingleShot(True)
        self._fade_timer.timeout.connect(self._start_fade)

    def _set_path_color(self, color_hex):
        c = QColor(color_hex)
        self._path_label.setStyleSheet(
            f"color: {color_hex}; background: rgba({c.red()}, {c.green()}, {c.blue()}, 13); "
            f"border-left: 2px solid {color_hex}; padding: 5px 6px;"
        )

    def _build_header(self):
        row = QHBoxLayout()
        row.setSpacing(6)

        logo = QLabel()
        logo.setFixedSize(16, 16)
        pixmap = QPixmap(theme.ICON_PATH)
        if not pixmap.isNull():
            pixmap = pixmap.scaled(
                16, 16,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            logo.setPixmap(pixmap)
        logo.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=6))
        row.addWidget(logo)

        title = QLabel("// DEVADARA SCANNING")
        title.setFont(theme.letter_spaced_font(size=8, black=True, spacing=1))
        title.setStyleSheet(f"color: {theme.NEON};")
        title.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=8))
        row.addWidget(title)

        row.addStretch(1)
        return row

    def _build_divider(self):
        divider = QFrame()
        divider.setObjectName("miniHeaderDivider")
        divider.setFixedHeight(1)
        divider.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        return divider

    # ─── real-data slots - connected to a live ScanWorker's signals in
    # ScanPage, alongside its existing ScanProgressView connections; never
    # fed simulated/placeholder data ───

    def reset(self):
        self._fade_timer.stop()
        self._fade_anim.stop()
        self._opacity_effect.setOpacity(1.0)
        self._card.set_accent(theme.NEON)
        self._set_path_color(theme.CYAN)
        self._path_label.setText("// initializing scan engine...")
        self._checked_label.setText("0")
        self._stats_box.set_values(0, 0, 0)
        self._stop_button.setEnabled(True)

    def set_stop_enabled(self, enabled):
        self._stop_button.setEnabled(enabled)

    def update_progress(self, label, checked):
        self._checked_label.setText(f"{checked:,}")
        if label:
            self._path_label.setText(f"> {label}")

    def update_stats(self, checked, threats, hidden):
        self._stats_box.set_values(checked, threats, hidden)

    def show_finished(self, stopped, checked, threats, hidden, elapsed):
        self._checked_label.setText(f"{checked:,}")
        self._stats_box.set_values(checked, threats, hidden)
        self._path_label.setText("> scan stopped." if stopped else "> scan complete.")
        self.set_stop_enabled(False)

    def show_auto_scan_result(self, stopped, checked, threats, hidden, elapsed):
        """Only for auto-triggered scans (see scan_page.py's
        _on_scan_finished) - a user-initiated Stop already means they're
        looking at the popup, so that case just reuses show_finished's
        plain frozen state. Otherwise: threats found freezes the popup red
        with no auto-dismiss (stays until Details >>); clean shows a green
        message and starts the 2s-delayed fade-out."""
        if stopped:
            self.show_finished(stopped, checked, threats, hidden, elapsed)
            return

        self._checked_label.setText(f"{checked:,}")
        self._stats_box.set_values(checked, threats, hidden)
        self.set_stop_enabled(False)

        if threats > 0:
            self._card.set_accent(theme.DANGER)
            self._set_path_color(theme.DANGER)
            plural = "" if threats == 1 else "s"
            self._path_label.setText(f"> {threats} threat{plural} found — click Details for more.")
        else:
            self._card.set_accent(theme.NEON)
            self._set_path_color(theme.NEON)
            self._path_label.setText("> no threats found.")
            self._fade_timer.start(2000)

    def _start_fade(self):
        self._fade_anim.setStartValue(self._opacity_effect.opacity())
        self._fade_anim.setEndValue(0.0)
        self._fade_anim.start()

    def _on_fade_finished(self):
        if self._opacity_effect.opacity() <= 0.0:
            self.hide()

    # ─── show/hide as a positioned toast ───

    def show_positioned(self):
        self.adjustSize()
        screen = self.screen() or QApplication.primaryScreen()
        geo = screen.availableGeometry()
        x = geo.right() - self.width() - self._MARGIN
        y = geo.bottom() - self.height() - self._MARGIN
        self.move(x, y)
        self.show()
