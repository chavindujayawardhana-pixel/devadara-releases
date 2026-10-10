"""
process_guard.py

The safety checks between a behavior alert's suspect list and the
existing devadara.behavior_monitor.suspend_process/resume_process/
kill_process (which are deliberately "dumb" - they act on whatever PID
they're given). Nothing in here ever decides to act: perform() is only
called after the user confirmed one specific program in a dialog (see
behavior_alert_popup.py), and even then it refuses:

  - Windows' own core processes (PID 0/4, csrss, lsass, svchost, explorer,
    ...) and anything installed under %SystemRoot% - killing or freezing
    one of those can hang or crash Windows itself.
  - DEVADARA's own process and its parent.
  - a program whose identity can't be verified (no access to its path or
    start time).
  - a PID that no longer belongs to the program from the alert. Windows
    reuses PIDs, so each suspect's process start time is recorded when the
    alert fires (describe_suspect()) and re-checked right before acting.

Every attempt - done, failed or refused - is logged via
scan_log.record_process_action(). No Qt here, so it's testable on its own.
"""

import os

import psutil

from devadara import behavior_monitor, scan_log

SYSTEM_PIDS = {0, 4}
CRITICAL_NAMES = {
    "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "smss.exe", "svchost.exe", "dwm.exe", "explorer.exe",
}
SYSTEM_ROOT = os.path.normcase(os.path.abspath(os.environ.get("SystemRoot", r"C:\Windows")))

_ACTIONS = {
    "suspend": behavior_monitor.suspend_process,
    "resume": behavior_monitor.resume_process,
    "kill": behavior_monitor.kill_process,
}
_DONE_TEXT = {"suspend": "Suspended", "resume": "Resumed", "kill": "Killed"}


def describe_suspect(suspect):
    """Snapshot a behavior_monitor suspect ({"pid", "name"}) at alert time,
    adding its program path and process start time - the identity later
    actions are checked against. exe/create_time are None if the process
    is already gone or access is denied."""
    info = {"pid": suspect["pid"], "name": suspect.get("name"), "exe": None, "create_time": None}
    try:
        proc = psutil.Process(suspect["pid"])
        info["create_time"] = proc.create_time()
        info["exe"] = proc.exe() or None
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        pass
    return info


def refusal_reason(suspect):
    """Why this suspect must never be acted on, or None if it may be (after
    the user confirms)."""
    pid = suspect["pid"]
    if pid in SYSTEM_PIDS:
        return "Windows system process"
    if pid in (os.getpid(), os.getppid()):
        return "DEVADARA itself"
    name = (suspect.get("name") or "").lower()
    if name in CRITICAL_NAMES or f"{name}.exe" in CRITICAL_NAMES:
        return "critical Windows process"
    exe = suspect.get("exe")
    if not exe or suspect.get("create_time") is None:
        return "can't verify this program"
    if os.path.normcase(os.path.abspath(exe)).startswith(SYSTEM_ROOT + os.sep):
        return "Windows component"
    return None


def still_same_process(suspect):
    """True only if the PID is alive AND is still the process recorded at
    alert time (same start time) - never a later process reusing the PID."""
    try:
        return psutil.Process(suspect["pid"]).create_time() == suspect["create_time"]
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False


class ProcessGuard:
    """Holds which processes DEVADARA itself suspended (only those can be
    resumed from here) - one instance for the app's lifetime, so that state
    survives a newer alert replacing the popup's content."""

    def __init__(self):
        self._suspended = set()  # (pid, create_time)

    @staticmethod
    def _key(suspect):
        return (suspect["pid"], suspect.get("create_time"))

    def is_suspended(self, suspect):
        return self._key(suspect) in self._suspended

    def any_suspended(self, suspects):
        return any(self.is_suspended(s) for s in suspects)

    def perform(self, action, suspect):
        """Run one user-confirmed action. Returns (ok, message for the UI)."""
        reason = refusal_reason(suspect)
        if reason is None and not still_same_process(suspect):
            reason = "it has exited or its PID was reused"
        if reason is None and action == "resume" and not self.is_suspended(suspect):
            reason = "it wasn't suspended by DEVADARA"
        if reason is not None:
            self._log(action, suspect, f"refused: {reason}")
            return False, f"Refused — {reason}"

        ok = _ACTIONS[action](suspect["pid"])
        if ok and action == "suspend":
            self._suspended.add(self._key(suspect))
        elif ok:
            self._suspended.discard(self._key(suspect))
        self._log(action, suspect, "ok" if ok else "failed")
        if ok:
            return True, _DONE_TEXT[action]
        return False, "Couldn't — it may have exited, or access was denied"

    @staticmethod
    def _log(action, suspect, result):
        scan_log.record_process_action(
            action, suspect["pid"], suspect.get("name"), suspect.get("exe"), result,
        )
