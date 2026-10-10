"""
notifier.py

This is DEVADARA's "raise an alarm" layer - it's what actually tells you
something happened, as opposed to just writing it down (see scan_log.py).
That gap matters specifically because of how startup_protect.py runs: via
pythonw.exe with no console window, so without this module the only way
you'd ever learn about a finding is by remembering to run
`startup_cli.py review-log` yourself.

How it works:
1. Windows' native toast notifications are a WinRT API with no Python
   stdlib access, so - same approach as signature_scanner.py - we shell
   out to PowerShell, which can reach WinRT directly.
2. Both the title and message are bound to script parameters
   ($Title/$Message), never woven into the script text itself, so nothing
   in a message (a malicious filename, say) can be interpreted as
   PowerShell code - same injection-safe pattern as
   signature_scanner.check_digital_signature().
3. Toasts need an "AUMID" (app identity) that Windows already trusts to
   show notifications. DEVADARA doesn't have its own registered identity
   yet (that needs a Start Menu shortcut, which only exists once Step 7's
   installer creates one) - to notice this NOW while wiring it into
   startup_protect.py rather than discover it silently failing in
   production: calling CreateToastNotifier("Windows PowerShell") was
   tested on this machine and silently did nothing (no exception, no
   toast - a known Windows behavior when an app's notification
   permission isn't explicitly granted). Borrowing Explorer's AUMID
   ("Microsoft.Windows.Explorer") - already trusted by Windows - was
   tested and works. Once Step 7 registers a real "DEVADARA" AUMID via
   the installer's Start Menu shortcut, swap the identity string below.

A failed notification (PowerShell missing, timeout, Focus Assist
suppressing it, whatever) is swallowed, not raised - a notification is a
courtesy, and a scan should never fail because the courtesy failed.
"""

import os
import subprocess

from devadara.hidden_process import hidden_window_kwargs

# Same resolution as signature_scanner.py's _POWERSHELL_EXE: found via
# SystemRoot rather than a bare "powershell.exe" on PATH, since PATH isn't
# guaranteed intact in every context this might run under.
_POWERSHELL_EXE = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe",
)
if not os.path.exists(_POWERSHELL_EXE):
    _POWERSHELL_EXE = "powershell.exe"

# Borrowed AUMID - see module docstring for why. Swap for a real DEVADARA
# AUMID once Step 7's installer registers a Start Menu shortcut for one.
_NOTIFIER_AUMID = "Microsoft.Windows.Explorer"

# Title/Message are bound as script parameters, never interpolated into
# this text, so a crafted title/message can't inject PowerShell code.
# SecurityElement.Escape() XML-escapes them so special characters (&, <,
# >, quotes) can't break the toast's XML structure either.
_NOTIFY_SCRIPT = (
    "& { param($Title, $Message) "
    "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] > $null; "
    "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] > $null; "
    "$template = '<toast><visual><binding template=\"ToastGeneric\"><text>{0}</text><text>{1}</text></binding></visual></toast>' "
    "-f [System.Security.SecurityElement]::Escape($Title), [System.Security.SecurityElement]::Escape($Message); "
    "$xml = New-Object Windows.Data.Xml.Dom.XmlDocument; "
    "$xml.LoadXml($template); "
    "$toast = New-Object Windows.UI.Notifications.ToastNotification $xml; "
    f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{_NOTIFIER_AUMID}').Show($toast) "
    "}"
)


def notify(title, message, timeout_seconds=10):
    """
    Show a Windows toast notification. Never raises - returns True if the
    PowerShell call completed without error, False otherwise (which only
    means "we couldn't confirm it worked", not necessarily that nothing
    appeared - Windows can suppress toasts, e.g. via Focus Assist, without
    telling the caller).
    """
    try:
        completed = subprocess.run(
            [_POWERSHELL_EXE, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", _NOTIFY_SCRIPT, title, message],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            **hidden_window_kwargs(),
        )
    except (OSError, subprocess.SubprocessError):
        return False

    return completed.returncode == 0
