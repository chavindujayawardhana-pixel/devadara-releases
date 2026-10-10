"""
gui_app.py

Entry point for DEVADARA's GUI. Run from the project root:

    python gui_app.py

Also what devadara.startup_registration registers to run at Windows
logon - the exact same code path, main window and all (see
startup_sync.sync_startup_registration below). A single-instance guard
(QLocalServer/QLocalSocket) makes sure a later manual launch never starts
a second process alongside an already-running one - instead it just
brings the running window to the front, the same as clicking the tray
icon's "Show DEVADARA" - so Downloads/USB watchers are never duplicated.

The logon launch passes --autostart (see startup_registration): the
window shows, then hides itself to the tray after AUTOSTART_HIDE_DELAY_MS
unless the user clicks/types in it first. A second launch never starts
its own timer (it exits above), and its SHOW cancels any pending one.
"""

import sys

from PySide6.QtGui import QFont
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import QApplication

from devadara.startup_registration import AUTOSTART_FLAG
from devadara_gui import theme
from devadara_gui.main_window import MainWindow
from devadara_gui.startup_sync import sync_startup_registration

SINGLE_INSTANCE_SERVER_NAME = "DevadaraVirusGuard-SingleInstance"

# How long a Windows-logon (--autostart) launch stays on screen before
# hiding itself to the tray - long enough to see it started, short enough
# not to sit in the way. A manual launch never auto-hides.
AUTOSTART_HIDE_DELAY_MS = 10_000


def _notify_running_instance():
    """Returns True if another instance is already running (and has been
    told to show its window), False if this process should become the
    one running instance."""
    socket = QLocalSocket()
    socket.connectToServer(SINGLE_INSTANCE_SERVER_NAME)
    if socket.waitForConnected(500):
        socket.write(b"SHOW")
        socket.waitForBytesWritten(500)
        socket.disconnectFromServer()
        return True
    return False


def _handle_incoming_connection(server, window):
    socket = server.nextPendingConnection()
    if socket is None:
        return
    socket.readyRead.connect(lambda: _consume_and_show(socket, window))


def _consume_and_show(socket, window):
    socket.readAll()
    socket.disconnectFromServer()
    window._restore_from_tray()


def main():
    autostart = AUTOSTART_FLAG in sys.argv[1:]
    app = QApplication(sys.argv)
    app.setFont(QFont(theme.FONT_FALLBACKS, 10))

    if _notify_running_instance():
        return

    server = QLocalServer()
    QLocalServer.removeServer(SINGLE_INSTANCE_SERVER_NAME)
    server.listen(SINGLE_INSTANCE_SERVER_NAME)

    window = MainWindow()
    server.newConnection.connect(lambda: _handle_incoming_connection(server, window))

    sync_startup_registration(window.auto_scan_controller.config_store)

    window.show()
    window.start_background_init()
    if autostart:
        window.schedule_auto_hide(AUTOSTART_HIDE_DELAY_MS)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
