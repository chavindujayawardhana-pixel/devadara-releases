"""
gui_app.py

Entry point for the DEVADARA desktop GUI:

    python gui_app.py

Launches the PySide6 application shell (see devadara_gui/main_window.py).
All detection logic lives in devadara/ - this file and devadara_gui/ only
display and orchestrate it.
"""

import sys

from PySide6.QtWidgets import QApplication

from devadara_gui import theme
from devadara_gui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    # Pin to Fusion explicitly rather than letting Qt pick a native style
    # (windowsvista/windows11 on this platform) - every color/gradient/
    # checkbox-accent value in theme.py was authored and verified against
    # Fusion (the offscreen QT_QPA_PLATFORM used throughout this app's own
    # design/test process defaults to it), so pinning it here removes any
    # native-style/OS-theme-dependent rendering difference for controls
    # (QCheckBox/QRadioButton indicators, scrollbars, etc.) between what
    # was verified and what actually ships.
    app.setStyle("Fusion")
    app.setStyleSheet(theme.stylesheet())
    app.setApplicationName("DEVADARA")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
