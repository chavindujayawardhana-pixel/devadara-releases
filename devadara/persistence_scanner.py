"""
persistence_scanner.py

This is DEVADARA's "habit check" layer - every other layer looks at a file
you (or a download, or a USB drive) brought to its attention right now.
This one instead asks Windows "what have you been TOLD to run automatically,
every time, without anyone choosing to run it again?" - the registry Run/
RunOnce keys, Scheduled Tasks, and auto-start Services malware relies on to
survive a reboot. A file sitting quietly in Downloads is only a threat if
something runs it; a persistence entry is Windows itself promising to run
it forever.

How it works:
1. Three enumerators (list_registry_run_entries, list_scheduled_tasks,
   list_autostart_services) each return the same shape: {"source",
   "location", "name"?, "command"}. None of them require Administrator
   rights - HKLM Run keys, `schtasks /query`, and enumerating (not
   modifying) services are all readable by an ordinary user.
2. _extract_executable_path() pulls the actual target executable out of
   each entry's raw command line - which is NOT simply "the whole string":
   real entries seen on a live machine include a plain quoted path
   ("C:\\...\\OneDrive.exe" /background), an environment-variable path with
   no quoting at all (%windir%\\system32\\SecurityHealthSystray.exe), and a
   path that ITSELF contains spaces followed by unquoted arguments
   (C:\\Program Files\\Proton\\VPN\\ProtonVPN.Launcher.exe "----ms-protocol:...").
   A dangling entry (target no longer exists on disk) is reported but never
   scanned - there is nothing to scan, and guessing why it's missing would
   be exactly the kind of unfounded heuristic the rest of this codebase
   deliberately avoids (see scan_engine.py's comments on concrete evidence
   vs. inference).
3. evaluate_persistence_entries() hands each entry's resolved path to
   scan_engine.evaluate_file() - the exact same Hash -> YARA -> Signature ->
   ML pipeline every other DEVADARA scanner uses, so a persistence entry is
   judged by identical rules to a downloaded file. This is also where the
   YARA layer earns its keep in a way nothing else here can: a malicious
   .vbs or .ps1 dropped into a Run key isn't a PE, so signature/ML never
   apply to it ("not_pe" in scan_engine.py) - YARA is the only layer that
   can still catch it.
4. Many entries point at the SAME executable (a dozen auto-start services
   are all really "svchost.exe -k <group>", several scheduled tasks can
   call the same updater, ...) and a full evaluate_file() can cost seconds
   per file (see scan_engine.py's own note on signature-check cost) - so
   this evaluates each unique resolved path exactly once and shares the
   result across every entry that referenced it, rather than re-scanning
   the same binary dozens of times.

This module only ever READS the registry, Task Scheduler, and service
list - it never creates, modifies, or deletes a persistence entry. If
something it finds turns out to be a real threat, quarantining the target
file (see devadara/quarantine.py, used the same way every other DEVADARA
CLI already does) neutralizes the payload; the now-dangling entry itself
is reported so you know where to clean it up by hand.
"""

import csv
import io
import os
import subprocess

import psutil
import winreg

from devadara import scan_engine
from devadara.hidden_process import hidden_window_kwargs
from devadara.signature_scanner import load_trusted_publishers

_SCHTASKS_EXE = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"), "System32", "schtasks.exe"
)
if not os.path.exists(_SCHTASKS_EXE):
    _SCHTASKS_EXE = "schtasks.exe"

# (root hive, "HKCU"/"HKLM" label) x (Run, RunOnce) x (native view, WOW6432Node
# for 32-bit apps on a 64-bit machine) - every one of these is readable by an
# ordinary, non-elevated user.
_RUN_KEY_ROOTS = [
    (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion"),
    (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion"),
    (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion"),
]
_RUN_SUBKEYS = ["Run", "RunOnce"]

# Only these start types actually make a service launch itself at boot/logon
# without anyone choosing to - "manual"/"disabled" services don't persist.
_AUTO_START_TYPES = {"automatic", "delayed-automatic"}


def list_registry_run_entries():
    """
    Every value under every HKCU/HKLM Run and RunOnce key (see
    _RUN_KEY_ROOTS/_RUN_SUBKEYS above).

    Returns a list of {"source": "registry", "location": str, "name": str,
    "command": str} dicts. A key that doesn't exist or can't be opened is
    silently skipped (same handling as startup_registration.is_in_startup())
    - not every one of these keys exists on every machine.
    """
    entries = []
    for root, root_label, base_path in _RUN_KEY_ROOTS:
        for subkey_name in _RUN_SUBKEYS:
            key_path = f"{base_path}\\{subkey_name}"
            try:
                with winreg.OpenKey(root, key_path, 0, winreg.KEY_READ) as key:
                    index = 0
                    while True:
                        try:
                            name, value, _value_type = winreg.EnumValue(key, index)
                        except OSError:
                            break  # no more values in this key
                        entries.append({
                            "source": "registry",
                            "location": f"{root_label}\\{key_path}",
                            "name": name,
                            "command": str(value),
                        })
                        index += 1
            except (FileNotFoundError, PermissionError):
                continue
    return entries


def list_scheduled_tasks(timeout_seconds=30):
    """
    Every entry in Windows Task Scheduler, via `schtasks /query /fo CSV /v`
    (verbose CSV is the only schtasks output mode that includes the actual
    command - "Task To Run").

    Returns a list of {"source": "scheduled_task", "location": task_name,
    "command": str} dicts, or [] if schtasks couldn't be run at all or
    produced no parseable output - same "never raise, just contribute
    nothing" convention as yara_scanner.scan_file() and
    signature_scanner.check_digital_signature().
    """
    try:
        completed = subprocess.run(
            [_SCHTASKS_EXE, "/query", "/fo", "CSV", "/v"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            **hidden_window_kwargs(),
        )
    except (OSError, subprocess.SubprocessError):
        return []

    if completed.returncode != 0 or not completed.stdout.strip():
        return []

    try:
        rows = list(csv.DictReader(io.StringIO(completed.stdout)))
    except csv.Error:
        return []

    entries = []
    for row in rows:
        task_name = row.get("TaskName")
        command = row.get("Task To Run")
        if not task_name or not command:
            continue
        entries.append({
            "source": "scheduled_task",
            "location": task_name,
            "command": command,
        })
    return entries


def list_autostart_services():
    """
    Every Windows service whose start type is "automatic" or
    "delayed-automatic" (i.e. actually launches itself at boot/logon,
    unlike a "manual" or "disabled" service).

    Returns a list of {"source": "service", "location": service_name,
    "command": bin_path} dicts. Each service is inspected independently -
    confirmed live on a real machine that a single unusual service can
    raise from inside psutil's own Windows API call, and that must not
    abort enumeration of the other 300+.
    """
    entries = []
    for service in psutil.win_service_iter():
        try:
            info = service.as_dict()
        except Exception:
            continue

        if info.get("start_type") not in _AUTO_START_TYPES:
            continue

        bin_path = info.get("binpath")
        if not bin_path:
            continue

        entries.append({
            "source": "service",
            "location": info.get("name") or service.name(),
            "command": bin_path,
        })
    return entries


def _extract_executable_path(raw_command):
    """
    Pull the target executable out of a raw Run-key value / Task-to-Run /
    service bin_path string, and resolve it to an existing file.

    Returns the resolved absolute path, or None if nothing in raw_command
    points at a file that actually exists on disk right now.
    """
    if not raw_command:
        return None

    expanded = os.path.expandvars(raw_command.strip())
    if not expanded:
        return None

    if expanded.startswith('"'):
        # Take everything up to the matching closing quote - a second
        # quoted token after it (e.g. "pythonw.exe" "some_script.py") is an
        # argument, not part of the target.
        closing = expanded.find('"', 1)
        candidate = expanded[1:closing] if closing != -1 else expanded[1:]
        return candidate if os.path.isfile(candidate) else None

    # Unquoted: the target itself may or may not contain spaces, and may
    # have trailing arguments with no delimiter marking where they start
    # (e.g. "svchost.exe -k netsvcs -p" vs. "Program Files\thing.exe /flag"
    # where the path itself has a space). Strip one trailing
    # whitespace-delimited token at a time until what's left is a real
    # file - this is the only approach that works for both shapes without
    # knowing up front which one a given entry is.
    candidate = expanded
    while candidate:
        if os.path.isfile(candidate):
            return candidate
        last_space = candidate.rfind(" ")
        if last_space == -1:
            break
        candidate = candidate[:last_space].rstrip()
    return None


def list_persistence_entries():
    """
    All registry Run/RunOnce + Scheduled Task + auto-start Service entries,
    each with a "resolved_path" (see _extract_executable_path) attached.
    """
    entries = list_registry_run_entries() + list_scheduled_tasks() + list_autostart_services()
    for entry in entries:
        entry["resolved_path"] = _extract_executable_path(entry["command"])
    return entries


def evaluate_persistence_entries(entries, known_bad_hashes, model, feature_columns, trusted_publishers=None):
    """
    Run scan_engine.evaluate_file() against every entry's resolved target,
    evaluating each UNIQUE path only once and sharing that result across
    every entry that references it (see module docstring - many entries
    legitimately point at the same executable, and a full evaluation isn't
    free).

    Mutates and returns entries, with a "scan" key added to each: the
    evaluate_file() result dict, or None if resolved_path is None (nothing
    to scan).
    """
    if trusted_publishers is None:
        trusted_publishers = load_trusted_publishers()

    cache = {}
    for entry in entries:
        path = entry["resolved_path"]
        if path is None:
            entry["scan"] = None
            continue
        if path not in cache:
            cache[path] = scan_engine.evaluate_file(
                path, known_bad_hashes, model, feature_columns, trusted_publishers=trusted_publishers
            )
        entry["scan"] = cache[path]
    return entries
