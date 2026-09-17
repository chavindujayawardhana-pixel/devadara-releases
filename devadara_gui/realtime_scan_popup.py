"""
realtime_scan_popup.py

RealTimeScanPopup - the ONE shared notification surface for DEVADARA's two
real-time auto-scan triggers (a new file finishing in Downloads, a USB
drive being plugged in). Both devadara_gui.services.realtime_scan's
controller and, through it, AppState's downloads/USB watcher callbacks
drive this same widget instance - there is deliberately no second
implementation and no per-trigger popup class.

This is a small, frameless, always-on-top, non-modal top-level window
(like a native Windows security notification) parked near the bottom-right
of the screen - NOT a widget embedded inside MainWindow, unlike toast.py's
ToastHost (which is confined to the main window's own bounds). It is only
a status/notification surface: it never quarantines, deletes, ignores, or
otherwise mutates a finding - see devadara_gui/services/realtime_scan.py
for what OK/Stop/Review actually do against the real backend.
"""

from PySide6.QtCore import QEasingCurve, QParallelAnimationGroup, QPoint, QPropertyAnimation, Qt, QTimer, Signal
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (
    QApplication,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from devadara_gui import theme
from devadara_gui.components import Card, StatusDot, hairline, make_label
from devadara_gui.icons import icon_label

POPUP_WIDTH = 412
POPUP_HEIGHT = 206
SCREEN_MARGIN = 20
ENTRANCE_OFFSET = 18
AUTO_CLOSE_MS = 4000
_CARD_PADDING = 16
_CONTENT_WIDTH = POPUP_WIDTH - 2 * _CARD_PADDING


class RealTimeScanPopup(QWidget):
    ok_clicked = Signal()
    stop_clicked = Signal()
    review_clicked = Signal()
    dismissed = Signal()  # fires once actually hidden, whatever the reason

    def __init__(self, parent=None):
        super().__init__(parent, Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(POPUP_WIDTH, POPUP_HEIGHT)

        self._scanning = False
        self._final_pos = QPoint(0, 0)
        self._stable_target_label = ""

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.card = Card(object_name="cardRaised", padding=16, glow=True)
        self.card.layout_.setSpacing(10)
        outer.addWidget(self.card)

        # -- Header: logo + "DEVADARA" + close -----------------------------
        header = QHBoxLayout()
        header.setSpacing(8)
        header.addWidget(icon_label("logo", size=16, color=theme.ACCENT_GREEN))
        title = make_label("DEVADARA", "bodyText")
        title.setStyleSheet(f"font-size: 13px; font-weight: 700; color: {theme.TEXT_PRIMARY};")
        header.addWidget(title)
        header.addStretch()
        close_btn = QPushButton("✕")
        close_btn.setObjectName("textButton")
        close_btn.setFixedSize(20, 20)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setToolTip("Dismiss")
        close_btn.clicked.connect(self._on_ok_clicked)
        header.addWidget(close_btn)
        self.card.addLayout(header)

        # -- Detection status: dot + "Detection -> ..." ---------------------
        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        self.status_dot = StatusDot("inactive")
        status_row.addWidget(self.status_dot)
        self.status_label = make_label("Detection → Scanning...", "bodyText")
        self.status_label.setStyleSheet(f"font-size: 14px; font-weight: 600; color: {theme.TEXT_PRIMARY};")
        status_row.addWidget(self.status_label)
        status_row.addStretch()
        self.card.addLayout(status_row)

        # -- Scanning target (elided) ----------------------------------------
        self.target_label = make_label("", "metadataText")
        self.card.addWidget(self.target_label)

        # -- Progress bar + percentage ----------------------------------------
        progress_row = QHBoxLayout()
        progress_row.setSpacing(10)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.valueChanged.connect(self._on_progress_value_changed)
        progress_row.addWidget(self.progress_bar, 1)
        self.percent_label = make_label("0%", "metadataText")
        self.percent_label.setFixedWidth(36)
        self.percent_label.setStyleSheet(f"font-size: 12px; color: {theme.TEXT_SECONDARY}; font-weight: 600;")
        progress_row.addWidget(self.percent_label)
        self.card.addLayout(progress_row)

        self.card.addWidget(hairline())

        # -- Buttons -----------------------------------------------------------
        button_row = QHBoxLayout()
        button_row.setSpacing(8)
        button_row.addStretch()

        self.stop_button = QPushButton("Stop")
        self.stop_button.setObjectName("secondaryButton")
        self.stop_button.setCursor(Qt.PointingHandCursor)
        self.stop_button.clicked.connect(self._on_stop_clicked)
        button_row.addWidget(self.stop_button)

        self.review_button = QPushButton("Review")
        self.review_button.setObjectName("secondaryButton")
        self.review_button.setCursor(Qt.PointingHandCursor)
        self.review_button.clicked.connect(self._on_review_clicked)
        self.review_button.hide()
        button_row.addWidget(self.review_button)

        self.ok_button = QPushButton("OK")
        self.ok_button.setObjectName("primaryButton")
        self.ok_button.setCursor(Qt.PointingHandCursor)
        self.ok_button.setDefault(True)
        self.ok_button.clicked.connect(self._on_ok_clicked)
        theme.apply_glow(self.ok_button, theme.ACCENT_GREEN, blur=16, alpha=130)
        button_row.addWidget(self.ok_button)

        self.card.addLayout(button_row)

        self.setTabOrder(self.ok_button, self.stop_button)
        self.setTabOrder(self.stop_button, self.review_button)
        self.setTabOrder(self.review_button, close_btn)

        # -- Auto-close (paused while hovered) --------------------------------
        self._auto_close_timer = QTimer(self)
        self._auto_close_timer.setSingleShot(True)
        self._auto_close_timer.timeout.connect(self.dismiss)
        self._hovering = False

        # -- Animations ----------------------------------------------------------
        self._opacity_anim = QPropertyAnimation(self, b"windowOpacity", self)
        self._pos_anim = QPropertyAnimation(self, b"pos", self)
        self._entrance_group = QParallelAnimationGroup(self)
        self._entrance_group.addAnimation(self._opacity_anim)
        self._entrance_group.addAnimation(self._pos_anim)

        self._fade_out_anim = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade_out_anim.setDuration(150)
        self._fade_out_anim.setStartValue(1.0)
        self._fade_out_anim.setEndValue(0.0)
        self._fade_out_anim.finished.connect(self._on_fade_out_finished)

        self.hide()

    # ------------------------------------------------------------------
    # Positioning + entrance/exit animation
    # ------------------------------------------------------------------
    def _target_screen_position(self):
        screen = QApplication.primaryScreen()
        geo = screen.availableGeometry() if screen else None
        if geo is None:
            return QPoint(100, 100)
        x = geo.right() - self.width() - SCREEN_MARGIN
        y = geo.bottom() - self.height() - SCREEN_MARGIN
        return QPoint(x, y)

    def _play_entrance_animation(self):
        self._final_pos = self._target_screen_position()
        start_pos = self._final_pos + QPoint(ENTRANCE_OFFSET, ENTRANCE_OFFSET)

        self._entrance_group.stop()
        self._fade_out_anim.stop()
        self.setWindowOpacity(0.0)
        self.move(start_pos)
        self.show()

        self._opacity_anim.setDuration(220)
        self._opacity_anim.setStartValue(0.0)
        self._opacity_anim.setEndValue(1.0)
        self._opacity_anim.setEasingCurve(QEasingCurve.OutCubic)

        self._pos_anim.setDuration(220)
        self._pos_anim.setStartValue(start_pos)
        self._pos_anim.setEndValue(self._final_pos)
        self._pos_anim.setEasingCurve(QEasingCurve.OutCubic)

        self._entrance_group.start()

    def dismiss(self):
        """Fade out and hide. Safe to call anytime - never touches the
        underlying finding/scan, only this notification surface."""
        self._auto_close_timer.stop()
        if not self.isVisible():
            return
        self._entrance_group.stop()
        self._fade_out_anim.stop()
        self._fade_out_anim.setStartValue(self.windowOpacity())
        self._fade_out_anim.start()

    def _on_fade_out_finished(self):
        self.hide()
        self.dismissed.emit()

    def _on_ok_clicked(self):
        self.ok_clicked.emit()
        self.dismiss()

    def _on_stop_clicked(self):
        # Don't dismiss immediately - wait for the controller to request
        # cancellation and call show_cancelled()/show_error(), so the user
        # sees the scan actually stopped rather than the popup just
        # vanishing. Disable to prevent a double-click re-requesting it.
        self.stop_button.setEnabled(False)
        self.stop_clicked.emit()

    def _on_review_clicked(self):
        self.review_clicked.emit()
        self.dismiss()

    # ------------------------------------------------------------------
    # Public API - driven by RealtimeScanController
    # ------------------------------------------------------------------
    def start_scan(self, target_label):
        """Reset to the scanning state and show (with the entrance animation)."""
        self._scanning = True
        self._auto_close_timer.stop()
        self._stable_target_label = target_label

        self.status_dot.set_state("inactive")
        self.status_label.setText("Detection → Scanning...")
        self.status_label.setStyleSheet(f"font-size: 14px; font-weight: 600; color: {theme.TEXT_PRIMARY};")
        self._set_target_text(target_label)

        self._stop_progress_animation()
        self.progress_bar.setValue(0)
        self.percent_label.setText("0%")

        self.stop_button.show()
        self.stop_button.setEnabled(True)
        self.review_button.hide()
        self.ok_button.setEnabled(True)

        self._play_entrance_animation()

    def update_progress(self, percent, detail=None):
        percent = max(0, min(100, int(percent)))
        self._stop_progress_animation()
        anim = QPropertyAnimation(self.progress_bar, b"value", self)
        anim.setDuration(160)
        anim.setStartValue(self.progress_bar.value())
        anim.setEndValue(percent)
        anim.setEasingCurve(QEasingCurve.OutQuad)
        anim.finished.connect(self._on_progress_animation_finished)
        self._progress_anim = anim
        anim.start(QPropertyAnimation.DeleteWhenStopped)
        if detail:
            self._set_target_text(detail)

    def _on_progress_animation_finished(self):
        # DeleteWhenStopped means the C++ object is gone the instant this
        # fires - drop the Python-side reference too so nothing later tries
        # to touch it (see _stop_progress_animation).
        self._progress_anim = None

    def _stop_progress_animation(self):
        # A still-running animation from the previous update_progress() call
        # keeps ticking on its own timer and can overwrite a later direct
        # progress_bar.setValue(100) a frame afterwards - confirmed live
        # (percent label briefly stuck reporting a stale value below 100%
        # right as a scan finished). Anything that force-sets the bar's
        # value directly must stop this first.
        anim = getattr(self, "_progress_anim", None)
        if anim is None:
            return
        self._progress_anim = None
        try:
            anim.stop()
        except RuntimeError:
            # DeleteWhenStopped already deleted the underlying C++ object
            # between this animation finishing naturally and us getting
            # here (confirmed live) - nothing to do, it's already gone.
            pass

    def show_clean_result(self, target_label=None):
        self._scanning = False
        self._set_target_text(target_label or self._stable_target_label)
        self._stop_progress_animation()
        self.progress_bar.setValue(100)
        self.percent_label.setText("100%")
        self._fade_status_to("active", "Detection → No Virus Detected", theme.TEXT_PRIMARY)
        self.stop_button.hide()
        self.review_button.hide()
        self._start_auto_close()

    def show_threat_result(self, target_label=None):
        self._scanning = False
        self._set_target_text(target_label or self._stable_target_label)
        self._stop_progress_animation()
        self.progress_bar.setValue(100)
        self.percent_label.setText("100%")
        self._fade_status_to("attention", "Detection → Threat Detected", theme.TEXT_PRIMARY)
        self.stop_button.hide()
        self.review_button.show()
        self._auto_close_timer.stop()

    def show_cancelled(self):
        self._scanning = False
        self.status_dot.set_state("inactive")
        self.status_label.setText("Scan cancelled")
        self.status_label.setStyleSheet(f"font-size: 14px; font-weight: 600; color: {theme.TEXT_SECONDARY};")
        self.stop_button.hide()
        self.review_button.hide()
        self._start_auto_close(1500)

    def show_error(self):
        self._scanning = False
        self.status_dot.set_state("inactive")
        self.status_label.setText("Scan could not complete")
        self.status_label.setStyleSheet(f"font-size: 14px; font-weight: 600; color: {theme.TEXT_SECONDARY};")
        self.stop_button.hide()
        self.review_button.hide()
        self._start_auto_close()

    def is_scanning(self):
        return self._scanning

    # ------------------------------------------------------------------
    def _set_target_text(self, text):
        prefix = "Scanning: "
        metrics = QFontMetrics(self.target_label.font())
        elided = metrics.elidedText(prefix + text, Qt.ElideMiddle, max(_CONTENT_WIDTH, 60))
        self.target_label.setText(elided)
        self.target_label.setToolTip(prefix + text)

    def _fade_status_to(self, dot_state, text, color):
        self.status_dot.set_state(dot_state)
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"font-size: 14px; font-weight: 600; color: {color};")
        # A brief, subtle opacity dip-and-recover on the status row only -
        # not the whole popup - so the clean/threat transition reads as a
        # deliberate state change without any flash/shake/color effect.
        effect = QGraphicsOpacityEffect(self.status_label)
        self.status_label.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(220)
        anim.setStartValue(0.35)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.finished.connect(lambda: self.status_label.setGraphicsEffect(None))
        anim.start(QPropertyAnimation.DeleteWhenStopped)
        self._status_fade_anim = anim  # keep a reference until it finishes

    def _start_auto_close(self, ms=AUTO_CLOSE_MS):
        self._auto_close_timer.stop()
        if not self._hovering:
            self._auto_close_timer.start(ms)
        self._pending_auto_close_ms = ms

    def _on_progress_value_changed(self, value):
        self.percent_label.setText(f"{value}%")

    def enterEvent(self, event):
        self.pause_auto_close()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.resume_auto_close()
        super().leaveEvent(event)

    def pause_auto_close(self):
        self._hovering = True
        if self._auto_close_timer.isActive():
            self._pending_auto_close_ms = max(self._auto_close_timer.remainingTime(), 0)
            self._auto_close_timer.stop()

    def resume_auto_close(self):
        self._hovering = False
        if not self._scanning and self.review_button.isHidden() and self.isVisible():
            # only a state that was actively counting down resumes - not
            # every non-scanning state (e.g. the threat state, which never
            # auto-closes at all).
            remaining = getattr(self, "_pending_auto_close_ms", None)
            if remaining is not None:
                self._auto_close_timer.start(remaining)
