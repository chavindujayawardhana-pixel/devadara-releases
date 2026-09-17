"""
scan_mini_popup.py

ScanMiniPopup - the "Minimize" state of the Scan page's own manual scan
(assets/scan_progress_reference.html's mini form), a small floating,
frameless, always-on-top corner window in the same technical/visual style
as devadara_gui.realtime_scan_popup.RealTimeScanPopup (Card "cardRaised",
bottom-right corner placement, entrance animation) - but this is a
deliberately SEPARATE widget/instance, not that same popup: RealTimeScanPopup
is reserved for the Downloads-watcher/USB auto-scan trigger paths (see that
module's own docstring for why there is exactly one shared instance for
those two), and this task's Scan page explicitly must not be wired into it.

Per the reference file's own behavior: the header's close ("X") button does
NOT dismiss/cancel the scan - it returns to the full screen, exactly like
"Detail >>" does. There is deliberately no way to make this popup (or the
scan it represents) disappear other than actually stopping the scan via
Stop (which raises the same Stop-scan confirmation used on the full
screen - see ScanPage._confirm_stop()).
"""

from PySide6.QtCore import QEasingCurve, QParallelAnimationGroup, QPoint, QPropertyAnimation, Qt, Signal
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import QApplication, QHBoxLayout, QProgressBar, QPushButton, QVBoxLayout, QWidget

from devadara_gui import theme
from devadara_gui.components import Card, hairline, make_label

POPUP_WIDTH = 320
SCREEN_MARGIN = 20
ENTRANCE_OFFSET = 18


class ScanMiniPopup(QWidget):
    detail_clicked = Signal()
    stop_clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent, Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedWidth(POPUP_WIDTH)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.card = Card(object_name="cardRaised", padding=0, glow=True)
        outer.addWidget(self.card)

        # -- Header: "Scanning >> <target>" + close -------------------------
        header_wrap = QWidget()
        header_wrap.setObjectName("transparentPanel")
        header = QHBoxLayout(header_wrap)
        header.setContentsMargins(12, 8, 12, 8)
        self.header_label = make_label("Scanning »", "bodyText")
        self.header_label.setStyleSheet(f"font-size: 12px; font-weight: 600; color: {theme.TEXT_PRIMARY};")
        header.addWidget(self.header_label, 1)
        close_btn = QPushButton("✕")
        close_btn.setObjectName("textButton")
        close_btn.setFixedSize(20, 20)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setToolTip("Back to full view")
        close_btn.clicked.connect(self.detail_clicked.emit)
        header.addWidget(close_btn)
        self.card.addWidget(header_wrap)
        self.card.addWidget(hairline())

        # -- Body -------------------------------------------------------------
        body_wrap = QWidget()
        body_wrap.setObjectName("transparentPanel")
        body = QVBoxLayout(body_wrap)
        body.setContentsMargins(14, 12, 14, 14)
        body.setSpacing(8)

        body.addWidget(make_label("FOLDER", "eyebrowLabel"))
        self.path_label = make_label("", "metadataText")
        self.path_label.setStyleSheet(f"font-family: Consolas, monospace; font-size: 11px; color: {theme.TEXT_SECONDARY};")
        body.addWidget(self.path_label)

        progress_row = QHBoxLayout()
        progress_row.setSpacing(8)
        self.percent_label = make_label("0%", "bodyText")
        self.percent_label.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {theme.TEXT_PRIMARY};")
        progress_row.addWidget(self.percent_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setTextVisible(False)
        progress_row.addWidget(self.progress_bar, 1)
        body.addLayout(progress_row)

        counts_row = QHBoxLayout()
        self.detected_label = make_label("Detected: 0", "bodyText")
        self.detected_label.setStyleSheet(f"font-size: 11px; color: {theme.TEXT_PRIMARY};")
        counts_row.addWidget(self.detected_label)
        counts_row.addStretch()
        self.hidden_label = make_label("Hidden: 0", "bodyText")
        self.hidden_label.setStyleSheet(f"font-size: 11px; color: {theme.KELLY_GREEN};")
        counts_row.addWidget(self.hidden_label)
        body.addLayout(counts_row)

        buttons_row = QHBoxLayout()
        buttons_row.setSpacing(8)
        detail_btn = QPushButton("Detail »")
        detail_btn.setObjectName("secondaryButton")
        detail_btn.setCursor(Qt.PointingHandCursor)
        detail_btn.clicked.connect(self.detail_clicked.emit)
        buttons_row.addWidget(detail_btn)
        stop_btn = QPushButton("Stop")
        stop_btn.setObjectName("secondaryButton")
        stop_btn.setCursor(Qt.PointingHandCursor)
        stop_btn.clicked.connect(self.stop_clicked.emit)
        buttons_row.addWidget(stop_btn)
        body.addLayout(buttons_row)

        self.card.addWidget(body_wrap)

        self._final_pos = QPoint(0, 0)
        self._opacity_anim = QPropertyAnimation(self, b"windowOpacity", self)
        self._pos_anim = QPropertyAnimation(self, b"pos", self)
        self._entrance_group = QParallelAnimationGroup(self)
        self._entrance_group.addAnimation(self._opacity_anim)
        self._entrance_group.addAnimation(self._pos_anim)

        self.hide()

    # ------------------------------------------------------------------
    def _target_screen_position(self):
        screen = QApplication.primaryScreen()
        geo = screen.availableGeometry() if screen else None
        if geo is None:
            return QPoint(100, 100)
        x = geo.right() - self.width() - SCREEN_MARGIN
        y = geo.bottom() - self.height() - SCREEN_MARGIN
        return QPoint(x, y)

    def show_popup(self, target_label):
        self.set_target(target_label)
        self._final_pos = self._target_screen_position()
        start_pos = self._final_pos + QPoint(ENTRANCE_OFFSET, ENTRANCE_OFFSET)

        self._entrance_group.stop()
        self.setWindowOpacity(0.0)
        self.move(start_pos)
        self.show()
        self.adjustSize()
        # Recompute now that adjustSize() may have changed the height.
        self._final_pos = self._target_screen_position()

        self._opacity_anim.setDuration(200)
        self._opacity_anim.setStartValue(0.0)
        self._opacity_anim.setEndValue(1.0)
        self._opacity_anim.setEasingCurve(QEasingCurve.OutCubic)

        self._pos_anim.setDuration(200)
        self._pos_anim.setStartValue(start_pos)
        self._pos_anim.setEndValue(self._final_pos)
        self._pos_anim.setEasingCurve(QEasingCurve.OutCubic)

        self._entrance_group.start()

    def set_target(self, target_label):
        self.header_label.setText(f"Scanning » {target_label}")

    def set_path(self, path_text):
        metrics = QFontMetrics(self.path_label.font())
        elided = metrics.elidedText(path_text or "-", Qt.ElideMiddle, POPUP_WIDTH - 40)
        self.path_label.setText(elided)
        self.path_label.setToolTip(path_text or "")

    def set_progress(self, percent):
        if percent is None:
            self.progress_bar.setRange(0, 0)
            self.percent_label.setText("")
        else:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(percent)
            self.percent_label.setText(f"{percent}%")

    def set_counts(self, detected, hidden):
        self.detected_label.setText(f"Detected: {detected}")
        self.hidden_label.setText(f"Hidden: {hidden}")

    def set_stop_enabled(self, enabled):
        for btn in self.findChildren(QPushButton):
            if btn.text() == "Stop":
                btn.setEnabled(enabled)
