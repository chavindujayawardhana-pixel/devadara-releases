"""
slide_over.py

SlideOverPanel - the right-side detail panel used for Threat Details,
Persistence entry details, and Process row details (Section 6.3 / 7.1 /
7.2). Implemented as a docked overlay widget (not a separate QDialog window)
so it reads as "sliding over the content" rather than navigating away, per
the spec's preference.
"""

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QScrollArea, QVBoxLayout, QWidget

from devadara_gui import theme
from devadara_gui.components import hairline, key_value_list, section_title  # noqa: F401

PANEL_WIDTH = 420


class SlideOverPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("cardRaised")
        self.setFixedWidth(PANEL_WIDTH)
        self.setStyleSheet(
            f"#cardRaised {{ background-color: {theme.GRADIENT_RAISED}; "
            f"border-left: 1px solid {theme.CYBER_BORDER_STRONG}; border-radius: 0px; }}"
        )

        self._outer = QVBoxLayout(self)
        self._outer.setContentsMargins(0, 0, 0, 0)
        self._outer.setSpacing(0)

        header = QHBoxLayout()
        header.setContentsMargins(20, 20, 20, 12)
        self._title_label = section_title("")
        self._title_label.setWordWrap(True)
        header.addWidget(self._title_label, 1)
        close_btn = QPushButton("✕")
        close_btn.setObjectName("textButton")
        close_btn.setFixedSize(28, 28)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.clicked.connect(self.hide)
        header.addWidget(close_btn)
        self._outer.addLayout(header)
        self._outer.addWidget(hairline())

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._body = QWidget()
        self._body.setObjectName("transparentPanel")
        self._body_layout = QVBoxLayout(self._body)
        self._body_layout.setContentsMargins(20, 16, 20, 20)
        self._body_layout.setSpacing(12)
        self._scroll.setWidget(self._body)
        self._outer.addWidget(self._scroll, 1)

        self.hide()

    def set_title(self, title):
        self._title_label.setText(title)

    def clear_body(self):
        while self._body_layout.count():
            item = self._body_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def add_widget(self, widget):
        self._body_layout.addWidget(widget)

    def open(self):
        self.show()
        self.raise_()

    def reposition(self, parent_size):
        self.setFixedHeight(parent_size.height())
        self.move(parent_size.width() - self.width(), 0)
        self.raise_()
