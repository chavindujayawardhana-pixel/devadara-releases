"""
signature_scanner.py

This is DEVADARA's "ID check" layer - it asks Windows itself whether a file
carries a valid digital signature from a real software publisher, the way
you'd check someone's ID instead of just their face (the ML layer) or a
mugshot database (the hash layer). A file signed and chain-verified by
Windows is extremely unlikely to be malware, since forging a signature that
Windows itself will call "Valid" requires a private key from a Certificate
Authority Windows already trusts.

How it works:
1. We ask PowerShell's built-in `Get-AuthenticodeSignature` cmdlet to check
   the file (Python has no native Authenticode support, so we shell out to
   the one thing on every Windows machine that does).
2. The file path is NEVER concatenated into the PowerShell command text -
   it's passed as a separate process argument and bound to a script
   parameter ($TargetPath). PowerShell only ever sees it as a plain string
   value, never as code to execute, so a maliciously-named file (with
   backticks, `$(...)`, semicolons, etc. in its name) can't inject commands.
3. `Status -eq 'Valid'` already means Windows verified the signature AND
   built a chain to a trusted root - that's what makes Authenticode
   trustworthy in the first place, not something we need to re-implement.
   We additionally require the certificate to not be expired, since an
   expired-but-still-"Valid"-via-timestamp signature is a case we'd rather
   route to the ML layer than blindly trust.
4. For files whose chain does NOT validate (self-signed, untrusted root,
   etc.) but whose certificate claims a publisher name in our local
   whitelist, we report that separately as `trusted_publisher_match`. This
   is a WEAK signal by design (a forged certificate can claim any name) -
   see scan_engine.py for how it's used (it can only downgrade an ML
   "malware" verdict to "suspicious" for manual review, never grant an
   outright "safe").

This module never scans file content itself and never touches ML - it only
answers "does Windows trust this file's signature, and if not, does its
claimed publisher match our whitelist?".
"""

import json
import os
import re
import subprocess
from datetime import datetime, timezone

from devadara.hidden_process import hidden_window_kwargs
from devadara.app_paths import app_file

TRUSTED_PUBLISHERS_PATH = app_file("data", "trusted_publishers.json")

# Resolved via SystemRoot rather than left as a bare "powershell.exe" looked
# up on PATH - a scanner shouldn't depend on PATH being intact/uncorrupted
# to find a core OS binary. Falls back to the bare name if, for some reason,
# the well-known path doesn't exist (e.g. a non-standard Windows install).
_POWERSHELL_EXE = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe",
)
if not os.path.exists(_POWERSHELL_EXE):
    _POWERSHELL_EXE = "powershell.exe"

# One powershell.exe process checks any number of files (one, or many - see
# check_digital_signature() and check_digital_signatures_batch()). This is a
# bundled .ps1 file (like tools/yara64.exe) rather than an inline -Command
# string: PowerShell's -Command only forwards the FIRST trailing CLI
# argument into a script block's parameters, silently dropping the rest -
# confirmed by direct testing, not assumed. -File properly forwards all of
# them, but only when the target parameter is declared
# ValueFromRemainingArguments (also confirmed by testing - plain positional
# binding of several bare args to one array parameter does NOT auto-collect
# them otherwise). Each path is still its own separate process argument,
# never woven into script text, preserving the same injection-safety
# guarantee the old inline script made.
_BATCH_SIGNATURE_SCRIPT_PATH = app_file("tools", "batch_signature_check.ps1")

_DOTNET_DATE_RE = re.compile(r"/Date\((-?\d+)\)/")
_CN_RE = re.compile(r"CN=([^,]+)")


def _parse_dotnet_date(value):
    """
    Windows PowerShell 5.1's ConvertTo-Json renders DateTime as
    "/Date(1234567890000)/" (milliseconds since Unix epoch). Returns a
    timezone-aware datetime, or None if value isn't in that shape.
    """
    if not value:
        return None
    match = _DOTNET_DATE_RE.match(value)
    if not match:
        return None
    millis = int(match.group(1))
    return datetime.fromtimestamp(millis / 1000, tz=timezone.utc)


def _extract_cn(subject):
    """
    Pull the CN (publisher name) out of a certificate Subject string like
    "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, ...".
    Returns None if there's no CN component.
    """
    if not subject:
        return None
    match = _CN_RE.search(subject)
    return match.group(1).strip() if match else None


def load_trusted_publishers():
    """
    Load our local list of trusted publisher names from
    data/trusted_publishers.json.

    Returns a list of strings. If the file is missing or broken, returns an
    empty list rather than crashing - a scan should still run, it just
    won't have the fallback whitelist available.
    """
    if not os.path.exists(TRUSTED_PUBLISHERS_PATH):
        print(f"[WARNING] Trusted publishers file not found at: {TRUSTED_PUBLISHERS_PATH}")
        return []

    try:
        with open(TRUSTED_PUBLISHERS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"[WARNING] Could not parse JSON in: {TRUSTED_PUBLISHERS_PATH}")
        return []


def is_trusted_publisher_name(publisher_cn, trusted_publishers):
    """
    Case-insensitive check of whether publisher_cn matches an entry in
    trusted_publishers. Returns False if publisher_cn is None/empty.
    """
    if not publisher_cn:
        return False
    normalized = publisher_cn.strip().lower()
    return any(normalized == name.strip().lower() for name in trusted_publishers)


def _build_signature_result(status, publisher_subject, not_after_raw, trusted_publishers):
    """
    Turn one raw Get-AuthenticodeSignature record (already parsed out of
    PowerShell's JSON) into the result dict shape documented on
    check_digital_signature() below. Shared by the single-file and batch
    paths so they can never silently diverge in how a record is
    interpreted.
    """
    status = status or "Unknown"
    publisher = _extract_cn(publisher_subject)
    not_after = _parse_dotnet_date(not_after_raw)

    signed = publisher is not None
    is_expired = not_after is not None and not_after < datetime.now(timezone.utc)
    valid_and_trusted = status == "Valid" and not is_expired

    return {
        "signed": signed,
        "status": status,
        "publisher": publisher,
        "valid_and_trusted": valid_and_trusted,
        "trusted_publisher_match": is_trusted_publisher_name(publisher, trusted_publishers),
        "error": None,
    }


def _default_signature_result(error=None):
    return {
        "signed": False,
        "status": "Error",
        "publisher": None,
        "valid_and_trusted": False,
        "trusted_publisher_match": False,
        "error": error,
    }


def check_digital_signature(file_path, trusted_publishers=None, timeout_seconds=15):
    """
    Ask Windows (via PowerShell's Get-AuthenticodeSignature) whether
    file_path has a valid digital signature.

    trusted_publishers: list of publisher names for the fallback whitelist
                         check. If None, loads from disk each call - pass
                         it explicitly when checking many files so it's
                         only loaded once.

    Returns a dictionary:
        {
            "signed": bool,                  # a signer certificate is present at all
            "status": str,                   # raw Authenticode status (e.g. "Valid", "NotSigned")
            "publisher": str | None,         # certificate's CN, if any
            "valid_and_trusted": bool,       # Status == Valid AND certificate not expired
            "trusted_publisher_match": bool, # publisher CN is in our local whitelist
            "error": str | None,             # set if the check itself failed to run
        }

    A failure to run the check at all (powershell missing, timeout, file
    vanished) is reported as an unsigned/untrusted result with "error" set,
    rather than raising - callers should treat that the same as "couldn't
    verify, fall through to the next layer".

    Delegates to check_digital_signatures_batch() with a single-element
    list rather than its own inline -Command invocation (which this
    function used until this session): -Command only forwards the first
    trailing CLI argument to a script block's own parameters, and separately,
    passing a path containing literal parentheses (e.g. any real path under
    "Program Files (x86)") through that -Command form makes PowerShell
    itself mis-tokenize the path and misreport a legitimate signed
    executable as an unverifiable error - confirmed directly against a real
    file on this machine, not assumed. -File (what the batch path already
    uses) doesn't have either problem, so routing every signature check
    through it, one path or many, both fixes this pre-existing correctness
    bug and removes a second, now-redundant subprocess-invocation
    mechanism.
    """
    results = check_digital_signatures_batch(
        [file_path], trusted_publishers=trusted_publishers, timeout_seconds=timeout_seconds, chunk_size=1
    )
    return results[file_path]


def check_digital_signatures_batch(file_paths, trusted_publishers=None, timeout_seconds=None,
                                    chunk_size=40, should_stop=None):
    """
    Batch variant of check_digital_signature() for scanning MANY files at
    once (a drive walk, hundreds of persistence/process entries) - each
    call to check_digital_signature() spawns its own powershell.exe process
    (~1-4s each, see scan_engine.py's docstring), which dominates real scan
    time on anything with more than a handful of executables. This
    collapses that into one powershell.exe launch per chunk of up to
    chunk_size files instead of one per file.

    file_paths: any iterable of file paths to check. Each path is still
                bound as its own separate subprocess argument (inside a
                PowerShell array parameter), never woven into script text -
                the same injection-safety guarantee check_digital_signature()
                makes, just for many paths in one process instead of one.
    should_stop: optional zero-arg callable checked between chunks, so a
                 caller with a Stop button stays responsive during a
                 multi-chunk batch instead of blocking until every chunk
                 finishes.

    Returns a dict {file_path: result} with exactly one entry per path in
    file_paths, in the same shape check_digital_signature() returns. A
    chunk that fails outright (subprocess error/timeout/bad output) fills
    in an error result for every path in that chunk only - other chunks
    and the rest of the scan are unaffected, matching the project's rule
    that one layer's failure degrades rather than aborts a scan.
    """
    if trusted_publishers is None:
        trusted_publishers = load_trusted_publishers()

    paths = list(file_paths)
    results = {}

    for start in range(0, len(paths), chunk_size):
        if should_stop and should_stop():
            break

        chunk = paths[start:start + chunk_size]
        chunk_timeout = timeout_seconds if timeout_seconds is not None else max(15, 2 * len(chunk))

        try:
            completed = subprocess.run(
                [
                    _POWERSHELL_EXE,
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy", "Bypass",
                    "-File", _BATCH_SIGNATURE_SCRIPT_PATH,
                    *chunk,
                ],
                capture_output=True,
                text=True,
                timeout=chunk_timeout,
                **hidden_window_kwargs(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            error = f"Could not run batch signature check: {exc}"
            for path in chunk:
                results[path] = _default_signature_result(error)
            continue

        if completed.returncode != 0 or not completed.stdout.strip():
            error = completed.stderr.strip() or "Batch signature check produced no output."
            for path in chunk:
                results[path] = _default_signature_result(error)
            continue

        try:
            data = json.loads(completed.stdout)
        except json.JSONDecodeError:
            error = "Could not parse batch signature check output."
            for path in chunk:
                results[path] = _default_signature_result(error)
            continue

        if isinstance(data, dict):
            data = [data]

        by_path = {}
        for record in data:
            path = record.get("Path")
            if path:
                by_path[path] = _build_signature_result(
                    record.get("Status"), record.get("Publisher"), record.get("NotAfter"),
                    trusted_publishers,
                )

        for path in chunk:
            results[path] = by_path.get(
                path, _default_signature_result("Path missing from batch signature check output.")
            )

    for path in paths:
        results.setdefault(path, _default_signature_result("Signature check interrupted."))

    return results
