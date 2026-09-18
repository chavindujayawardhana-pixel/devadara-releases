"""
gui_app.py

Entry point for DEVADARA's GUI (Phase 1: color theme, reusable components,
and the app shell only - no page content or backend wiring yet, see
devadara_gui/ for the implementation). Run from the project root:

    python gui_app.py
"""

import sys

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from devadara_gui import theme
from devadara_gui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont(theme.FONT_FALLBACKS, 10))

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
