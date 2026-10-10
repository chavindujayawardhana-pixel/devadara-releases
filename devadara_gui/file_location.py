"""
file_location.py

"Open in Explorer" for the Results page: shows a file's location in File
Explorer with the file highlighted - it NEVER opens or runs the file
itself. That's why this deliberately doesn't use os.startfile() or
QDesktopServices.openUrl() on the file: either would execute a flagged
.exe/.bat/.js exactly as a double-click would. Explorer is launched with
the path as its own argument (never built into a command string), and
visibly - it's a deliberate user-facing launch, so it does not use
devadara.hidden_process.

Only ever called after the user confirmed it (see results_page.py).
"""

import os
import subprocess


def explorer_command(path):
    """The Explorer command for path: highlight the file if it's still
    there, otherwise open the nearest existing folder above it. None if
    nothing on that path exists any more."""
    path = os.path.normpath(path)
    if os.path.isfile(path):
        return ["explorer", "/select,", path]
    folder = path if os.path.isdir(path) else os.path.dirname(path)
    while folder and not os.path.isdir(folder):
        parent = os.path.dirname(folder)
        if parent == folder:
            return None
        folder = parent
    return ["explorer", folder] if folder else None


def open_in_explorer(path):
    """Returns True if Explorer was started."""
    command = explorer_command(path)
    if command is None:
        return False
    try:
        subprocess.Popen(command)
    except OSError:
        return False
    return True
