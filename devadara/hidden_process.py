"""
hidden_process.py

Keyword arguments that make a subprocess.run() child invisible on Windows.

Every external tool devadara/ shells out to (powershell.exe for signature
checks and toasts, tools/yara64.exe, schtasks.exe) is a console program.
When the parent has no console of its own - the GUI and the logon
autostart both run under pythonw.exe - Windows gives each such child a
brand-new visible console window, so a scan flashes a black window per
signature-check chunk and per YARA scan. CREATE_NO_WINDOW stops that
console being created at all; STARTF_USESHOWWINDOW + SW_HIDE also hides
any window the child would otherwise show on startup.

Only how the child is shown changes - not what it runs, its arguments, its
stdout/stderr capture, its timeout, or its exit code. These constants only
exist on Windows, so anywhere else this returns {} and calls are unchanged.
"""

import subprocess


def hidden_window_kwargs():
    """Extra kwargs for subprocess.run()/Popen(); {} off Windows. Builds a
    fresh STARTUPINFO each call so concurrent calls never share one."""
    create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", None)
    startupinfo_cls = getattr(subprocess, "STARTUPINFO", None)
    if create_no_window is None or startupinfo_cls is None:
        return {}
    startupinfo = startupinfo_cls()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return {"creationflags": create_no_window, "startupinfo": startupinfo}
