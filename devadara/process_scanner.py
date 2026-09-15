"""
process_scanner.py

Every other DEVADARA layer judges a file: one sitting on disk, or one a
persistence entry points at (see devadara/persistence_scanner.py). None of
them can catch a process that's already running and was compromised
entirely IN MEMORY - classic process injection, process hollowing, or a
reflectively-loaded DLL - where the .exe on disk is completely clean and
every file-based check would come back "safe". This is DEVADARA's "does
this running process actually belong here?" layer, closing that gap.

How it works:
1. `psutil` cannot read a process's memory CONTENT (no ReadProcessMemory
   equivalent - only size/region metadata). What it IS good at is process
   METADATA and RELATIONSHIPS, which is what this module actually uses:
   four cheap, well-known behavioral tells a legitimate process shouldn't
   trip - a process named like a core Windows service but running from
   the wrong folder, a process running from a user-writable "drop"
   location, a document/browser process that spawned a shell or script
   interpreter, or a process whose backing .exe has vanished since launch.
   None of these alone PROVES anything (a legitimate installer can run
   from Temp too) - they exist to pick out a small handful of processes
   worth a closer look, out of the couple hundred normally running.
2. For every process that trips at least one check, its .exe (if it still
   exists) is run through scan_engine.evaluate_file() - the exact same
   Hash -> YARA -> Signature -> ML pipeline every other DEVADARA scanner
   uses. That's the only thing here backed by concrete evidence rather
   than a behavioral guess; the four checks above only decide WHICH few
   processes are worth spending that evaluation on.

Deliberately NOT done here, and why: an earlier attempt at this module
tried pointing tools/yara64.exe directly at a live process's memory (it
supports this - `yara64.exe RULES... <pid>` - the same binary already used
for file scanning). Verified live that this is both too slow to run
against every process (0.8s for a small process, 21s for explorer.exe,
and a real machine easily has 200+ running processes) AND, for the rule
that matters most here, non-discriminating: Process_Injection_API_Combo
(data/yara_rules/process_injection_indicators.yar) matched a completely
inert, freshly-spawned bare python.exe, because a process's full mapped
memory includes every loaded DLL's own export/debug tables, which
trivially contain the same handful of API name strings that rule looks
for - unlike a single file's own import table, which is what that rule
was actually written against. So this module stays psutil-metadata-only;
live-memory YARA scanning is a possible future addition, not this one.
"""

import os
import tempfile

import psutil

from devadara import scan_engine
from devadara.signature_scanner import load_trusted_publishers

# Core Windows processes malware commonly impersonates by name to blend
# into a process list at a glance - genuinely legitimate copies of these
# only ever run from System32/SysWOW64.
_SYSTEM_PROCESS_NAMES = {
    "svchost.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "smss.exe", "spoolsv.exe",
}

# Document/browser processes that have no legitimate reason to directly
# launch a shell or script interpreter - the classic macro-malware /
# phishing-attachment pattern.
_PARENT_NAMES = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrobat.exe", "acrord32.exe", "chrome.exe", "msedge.exe", "firefox.exe",
}
_CHILD_NAMES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "certutil.exe", "regsvr32.exe",
}


def _system_dirs():
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return {
        os.path.join(system_root, "System32").lower(),
        os.path.join(system_root, "SysWOW64").lower(),
    }


def _drop_locations():
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return [
        tempfile.gettempdir(),
        os.path.join(system_root, "Temp"),
        os.path.join(os.path.expanduser("~"), "Downloads"),
    ]


def list_suspicious_processes():
    """
    Sweep every running process for four cheap, well-known behavioral
    tells (see module docstring). A process can trip more than one.

    Returns [{"pid", "ppid", "name", "exe", "reasons": [str, ...]}, ...] -
    only processes that tripped at least one check.
    """
    system_dirs = _system_dirs()
    drop_locations = [loc.lower() for loc in _drop_locations()]
    own_pid = os.getpid()

    processes = list(psutil.process_iter(["pid", "ppid", "name", "exe"]))
    pid_to_name = {p.info["pid"]: p.info["name"] for p in processes if p.info.get("name")}

    flagged = []
    for proc in processes:
        try:
            info = proc.info
            pid = info["pid"]
            if pid in (0, 4, own_pid):
                continue

            name = info.get("name") or ""
            exe = info.get("exe") or None
            ppid = info.get("ppid")
            reasons = []

            if exe and name.lower() in _SYSTEM_PROCESS_NAMES:
                exe_dir = os.path.dirname(exe).lower()
                if exe_dir not in system_dirs:
                    reasons.append(
                        f"named like a core Windows process ('{name}') but running from "
                        f"'{os.path.dirname(exe)}', not System32/SysWOW64"
                    )

            if exe and any(exe.lower().startswith(loc) for loc in drop_locations if loc):
                reasons.append(f"running from a user-writable location: '{exe}'")

            parent_name = pid_to_name.get(ppid)
            if parent_name and parent_name.lower() in _PARENT_NAMES and name.lower() in _CHILD_NAMES:
                reasons.append(
                    f"launched by '{parent_name}' (pid {ppid}) - a document/browser process "
                    "spawning a shell/script interpreter"
                )

            # A handful of Windows pseudo-processes (e.g. "Registry",
            # "Memory Compression") have no real backing executable at all -
            # confirmed live that psutil's exe() for these just returns the
            # process's own name, not a path. Only flag this when exe()
            # actually looks like a real path that used to resolve and now
            # doesn't, not whenever exe() is merely truthy.
            if exe and os.path.isabs(exe) and not os.path.isfile(exe):
                reasons.append(f"backing file no longer exists on disk: '{exe}'")

            if reasons:
                flagged.append({"pid": pid, "ppid": ppid, "name": name, "exe": exe, "reasons": reasons})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue  # process vanished or is protected - skip, don't abort the sweep

    return flagged


def evaluate_suspicious_processes(entries, known_bad_hashes, model, feature_columns, trusted_publishers=None):
    """
    Run scan_engine.evaluate_file() against each flagged process's exe -
    the only concrete evidence this module can produce, on top of the
    behavioral reasons that picked these few processes out. Several
    processes can share one exe (several svchost.exe instances, for
    example), so - same as persistence_scanner.evaluate_persistence_entries -
    each unique path is only evaluated once and the result shared across
    every process that references it.

    Mutates and returns entries, with a "scan" key added to each: the
    evaluate_file() result dict, or None if exe is missing/no longer exists.
    """
    if trusted_publishers is None:
        trusted_publishers = load_trusted_publishers()

    cache = {}
    for entry in entries:
        exe = entry["exe"]
        if not exe or not os.path.isfile(exe):
            entry["scan"] = None
            continue
        if exe not in cache:
            cache[exe] = scan_engine.evaluate_file(
                exe, known_bad_hashes, model, feature_columns, trusted_publishers=trusted_publishers
            )
        entry["scan"] = cache[exe]
    return entries
