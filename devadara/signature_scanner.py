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

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRUSTED_PUBLISHERS_PATH = os.path.join(PROJECT_ROOT, "data", "trusted_publishers.json")

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

# The file path is bound to $TargetPath as a plain parameter value - it is
# never woven into this script text, so nothing in a filename can be
# interpreted as PowerShell code.
_SIGNATURE_CHECK_SCRIPT = (
    "& { param($TargetPath) "
    "$sig = Get-AuthenticodeSignature -LiteralPath $TargetPath; "
    "[PSCustomObject]@{"
    "Status=$sig.Status.ToString(); "
    "Publisher=$sig.SignerCertificate.Subject; "
    "NotAfter=$sig.SignerCertificate.NotAfter; "
    "NotBefore=$sig.SignerCertificate.NotBefore"
    "} | ConvertTo-Json -Compress }"
)

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
    """
    if trusted_publishers is None:
        trusted_publishers = load_trusted_publishers()

    default_result = {
        "signed": False,
        "status": "Error",
        "publisher": None,
        "valid_and_trusted": False,
        "trusted_publisher_match": False,
        "error": None,
    }

    try:
        completed = subprocess.run(
            [
                _POWERSHELL_EXE,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-Command", _SIGNATURE_CHECK_SCRIPT,
                file_path,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        default_result["error"] = f"Could not run signature check: {exc}"
        return default_result

    if completed.returncode != 0 or not completed.stdout.strip():
        default_result["error"] = completed.stderr.strip() or "Signature check produced no output."
        return default_result

    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError:
        default_result["error"] = "Could not parse signature check output."
        return default_result

    status = data.get("Status") or "Unknown"
    publisher = _extract_cn(data.get("Publisher"))
    not_after = _parse_dotnet_date(data.get("NotAfter"))

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
