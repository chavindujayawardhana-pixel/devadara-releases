"""
toast.py

Passive, non-decision event notifications (Section 2.3 of the design
spec) - "Scan completed", "Threat detected" (informational; clicking it
just navigates, it never itself offers Quarantine/Delete), "Protection
turned on/off". Stacks bottom-right over the main window, auto-dismisses
after 5s unless hovered.
"""

from PySide6.QtCore import QPoint, Qt, QTimer
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from devadara_gui import theme
from devadara_gui.components import body_secondary, body_text, section_title  # noqa: F401
from devadara_gui.icons import icon_label


class Toast(QWidget):
    def __init__(self, title, message, on_click=None, parent=None):
        super().__init__(parent)
        self.setObjectName("cardRaised")
        self.setFixedWidth(320)
        # A plain QWidget (not QFrame) only auto-fills a flat QSS
        # background-color without this attribute - the old solid
        # BG_PANEL_RAISED happened to render anyway, but the new gradient
        # brush needs the real styled-paint path to show at all (see
        # dashboard.py's QuickActionCard, which already carries this same
        # flag for the same reason).
        self.setAttribute(Qt.WA_StyledBackground, True)
        theme.apply_glow(self, theme.ACCENT_GREEN, blur=22, alpha=100)
        # ToastHost (this widget's parent) is WA_TransparentForMouseEvents so
        # the rest of the app stays clickable - but that attribute is
        # inherited by children too, so each actual toast bubble must opt
        # itself back in explicitly or its own close button stops working.
        self.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self._on_click = on_click
        self._hovered = False

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(10)

        layout.addWidget(icon_label("dot", size=10, color=theme.ACCENT_GREEN))

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        title_label = body_text(title)
        title_label.setStyleSheet(f"font-size: 13px; font-weight: 600; color: {theme.TEXT_PRIMARY};")
        title_label.setWordWrap(True)
        text_col.addWidget(title_label)
        msg_label = body_secondary(message, wrap=True)
        text_col.addWidget(msg_label)
        layout.addLayout(text_col, 1)

        close_btn = QPushButton("✕")
        close_btn.setObjectName("textButton")
        close_btn.setFixedSize(22, 22)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.clicked.connect(self._dismiss)
        layout.addWidget(close_btn)

        self.setCursor(Qt.PointingHandCursor if on_click else Qt.ArrowCursor)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._dismiss)
        self._timer.start(5000)

    def mousePressEvent(self, event):
        if self._on_click:
            self._on_click()
        super().mousePressEvent(event)

    def enterEvent(self, event):
        self._timer.stop()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._timer.start(5000)
        super().leaveEvent(event)

    def _dismiss(self):
        manager = self.parent()
        self.setParent(None)
        self.deleteLater()
        if isinstance(manager, ToastHost):
            manager.reflow()


class ToastHost(QWidget):
    """
    A transparent overlay sitting on top of the main window's content area.
    call show_toast(...) from anywhere in the app to raise one.
    """

    MARGIN = 20
    GAP = 10

    def __init__(self, parent=None):
        super().__init__(parent)
        # This overlay covers the ENTIRE window content area (see
        # main_window.py: toast_host.setGeometry(central.rect()), raised to
        # the top on every resize) and must be click-through wherever no
        # toast is actually showing, or it silently blocks every click in
        # the app - confirmed live via QWidget.childAt(): with this
        # attribute False, childAt() at a sidebar nav button's exact
        # position returned the (invisible, unpainted) ToastHost instead of
        # the button, and a real window-level synthetic click there
        # registered zero clicks. A child Toast widget positioned within
        # this overlay still receives its own clicks normally regardless of
        # this flag - only clicks landing on the overlay's own empty
        # background pass through.
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self._toasts = []

    def show_toast(self, title, message, on_click=None):
        toast = Toast(title, message, on_click=on_click, parent=self)
        toast.show()
        self._toasts.append(toast)
        self.reflow()
        self.raise_()
        toast.raise_()

    def reflow(self):
        self._toasts = [t for t in self._toasts if t.parent() is not None]
        y = self.height() - self.MARGIN
        for toast in reversed(self._toasts):
            toast.adjustSize()
            y -= toast.height()
            x = self.width() - self.MARGIN - toast.width()
            toast.move(QPoint(max(0, x), max(0, y)))
            toast.raise_()
            y -= self.GAP

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.reflow()
