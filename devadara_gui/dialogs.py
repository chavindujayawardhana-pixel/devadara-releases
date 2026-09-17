"""
dialogs.py

ConfirmationDialog - the one modal shape used everywhere a destructive or
consequential action needs an explicit yes (Section 8 of the design spec).
Reversible/safe actions get a filled green confirm button; destructive/
irreversible ones get an outlined (never green) confirm button and default
focus stays on Cancel so pressing Enter can't fire the dangerous action by
accident.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QPushButton, QVBoxLayout

from devadara_gui import theme
from devadara_gui.components import body_secondary, section_title


class ConfirmationDialog(QDialog):
    def __init__(self, title, body, confirm_label="Confirm", destructive=False, parent=None, cancel_label="Cancel"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedWidth(440)
        self.setStyleSheet(
            f"QDialog {{ background-color: {theme.GRADIENT_RAISED}; "
            f"border: 1px solid {theme.BORDER_STRONG}; border-radius: {theme.RADIUS_CARD}px; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 20)
        layout.setSpacing(12)

        layout.addWidget(section_title(title))
        layout.addWidget(body_secondary(body, wrap=True))

        layout.addSpacing(8)
        button_row = QHBoxLayout()
        button_row.addStretch()

        self.cancel_button = QPushButton(cancel_label)
        self.cancel_button.setObjectName("secondaryButton")
        self.cancel_button.setCursor(Qt.PointingHandCursor)
        self.cancel_button.clicked.connect(self.reject)
        button_row.addWidget(self.cancel_button)

        self.confirm_button = QPushButton(confirm_label)
        self.confirm_button.setObjectName("secondaryButton" if destructive else "primaryButton")
        self.confirm_button.setCursor(Qt.PointingHandCursor)
        self.confirm_button.clicked.connect(self.accept)
        if not destructive:
            theme.apply_glow(self.confirm_button, theme.ACCENT_GREEN, blur=18, alpha=130)
        button_row.addWidget(self.confirm_button)

        layout.addLayout(button_row)

        # Destructive actions: Cancel keeps default focus so Enter never
        # fires the dangerous action by accident.
        self.setDefault_(destructive)

    def setDefault_(self, destructive):
        if destructive:
            self.cancel_button.setDefault(True)
            self.cancel_button.setFocus()
        else:
            self.confirm_button.setDefault(True)

    @staticmethod
    def confirm(parent, title, body, confirm_label="Confirm", destructive=False, cancel_label="Cancel"):
        dialog = ConfirmationDialog(title, body, confirm_label, destructive, parent, cancel_label=cancel_label)
        return dialog.exec() == QDialog.Accepted
