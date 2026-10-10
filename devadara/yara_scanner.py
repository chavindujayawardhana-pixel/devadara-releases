"""
yara_scanner.py

This is DEVADARA's "known-pattern" layer - it sits between the hash check
and the digital signature check (see devadara/scan_engine.py) and catches
things hash matching can't: not an exact-byte match to a specific known-bad
file, but a recognizable PATTERN - a ransom note's phrasing, an obfuscated
PowerShell one-liner, a combination of API names associated with process
injection. Unlike the ML layer (which only judges Windows PE files and can
be wrong about structurally-unusual-but-legitimate ones), YARA matches on
concrete evidence actually present in the file, which is why a YARA match
is treated as outranking a trusted signature rather than being overridden
by one - see scan_engine.py for exactly how.

How it works:
1. `yara-python` (the usual way to use YARA from Python) has no prebuilt
   wheel for this project's Python version (3.14 - too new; yara-python
   4.5.4's wheels cover 3.9-3.13), and building it from source needs MSVC
   Build Tools. So instead this shells out to the official standalone
   yara64.exe CLI (bundled at tools/yara64.exe, see tools/NOTICE.txt for
   provenance) - same "shell out to a proven external tool" approach
   already used for signature_scanner.py (PowerShell) and notifier.py
   (PowerShell), and measured at ~48ms per file, far cheaper than either
   of those.
2. Every .yar/.yara file in data/yara_rules/ is passed to yara64.exe
   together against the target file. Rules are tagged with a
   `severity = "high"` or `severity = "suspicious"` meta field (see the
   rule files themselves) - that's what scan_engine.py uses to decide how
   much weight to give a match. A rule with no severity meta defaults to
   "suspicious" (the more cautious of the two), never silently ignored.
3. yara64.exe's --print-meta --print-tags output is one line per match:
   RuleName [tags] [key="value",...] filepath - parsed with a couple of
   regexes rather than JSON, since this YARA CLI version has no JSON
   output mode.

A failure anywhere in this chain (missing binary, no rule files, a locked/
unreadable target file, a timeout) returns an empty match list rather than
raising - this layer should never be the reason a scan crashes.
"""

import os
import re
import subprocess

from devadara.hidden_process import hidden_window_kwargs

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
YARA_EXE = os.path.join(PROJECT_ROOT, "tools", "yara64.exe")
RULES_DIR = os.path.join(PROJECT_ROOT, "data", "yara_rules")

_MATCH_LINE_RE = re.compile(r"^(\S+)\s+\[(.*?)\]\s+\[(.*?)\]\s+(.+)$")
_META_PAIR_RE = re.compile(r'(\w+)="([^"]*)"')


def is_available():
    return os.path.exists(YARA_EXE)


def _rule_files():
    if not os.path.isdir(RULES_DIR):
        return []
    return [
        os.path.join(RULES_DIR, name)
        for name in sorted(os.listdir(RULES_DIR))
        if name.lower().endswith((".yar", ".yara"))
    ]


def scan_file(file_path, timeout_seconds=15):
    """
    Scan file_path against every rule in data/yara_rules/.

    Returns a list of matches:
        [{"rule": str, "description": str, "severity": "high" | "suspicious"}, ...]
    Empty list if there were no matches, yara64.exe isn't available, there
    are no rule files, or the scan itself failed for any reason (locked
    file, timeout, ...) - callers can't distinguish "definitely clean" from
    "couldn't check" here, same as how a missing ML model just means this
    layer contributes nothing rather than blocking the rest of the pipeline.
    """
    if not is_available():
        return []

    rule_files = _rule_files()
    if not rule_files:
        return []

    try:
        completed = subprocess.run(
            [YARA_EXE, "--print-meta", "--print-tags", *rule_files, file_path],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            **hidden_window_kwargs(),
        )
    except (OSError, subprocess.SubprocessError):
        return []

    if completed.returncode != 0:
        # Non-zero means yara64.exe couldn't complete the scan (e.g. the
        # file was locked or vanished) - not "definitely no match".
        return []

    matches = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        match = _MATCH_LINE_RE.match(line)
        if not match:
            continue
        rule_name, _tags, meta_text, _matched_path = match.groups()
        meta = dict(_META_PAIR_RE.findall(meta_text))
        matches.append({
            "rule": rule_name,
            "description": meta.get("description", ""),
            "severity": meta.get("severity", "suspicious"),
        })

    return matches


def highest_severity_tier(matches):
    """
    Reduce a list of matches (from scan_file()) to a single tier:
    "malware" if any match is severity="high", "suspicious" if there's at
    least one match but none are "high", or None if there were no matches
    at all. See scan_engine.py for how this tier is combined with the rest
    of the pipeline's verdict.
    """
    if any(m["severity"] == "high" for m in matches):
        return "malware"
    if matches:
        return "suspicious"
    return None
