"""
verdict_labels.py

The plain-words label shown next to a scan result - DISPLAY ONLY. It never
changes a verdict: scan_engine.evaluate_file()'s tier is still what every
decision (logging, alerts, which list a file lands in) is based on, and
the raw tier is always shown alongside the label.

    Known Good   - the file is a genuine DEVADARA file (matches the signed
                   integrity manifest, see self_integrity.py), or the user
                   chose Ignore for exactly this content (tier "ignored")
    High Risk    - tier "known_bad" or "malware"
    Suspicious   - tier "suspicious"
    Not flagged  - anything else ("safe", "trusted_signed", "not_pe",
                   "unreadable"): nothing was found, which is not the same
                   as verified. A valid digital signature alone NEVER makes
                   a file Known Good.

Colours are named by their devadara_gui/theme.py token so this module
needs no GUI import; no new colours.
"""

from devadara import self_integrity

KNOWN_GOOD = "Known Good"
HIGH_RISK = "High Risk"
SUSPICIOUS = "Suspicious"
NOT_FLAGGED = "Not flagged"

COLOR_TOKENS = {
    KNOWN_GOOD: "NEON",
    HIGH_RISK: "DANGER",
    SUSPICIOUS: "WARN",
    NOT_FLAGGED: "TEXT_DIM",
}

HIGH_RISK_TIERS = ("known_bad", "malware")


def is_verified_self(result):
    """True if the result's file is, right now, a genuine DEVADARA file.
    Re-hashes the file on disk (only when its path is listed in the signed
    manifest) - a hash recorded at scan time could be stale."""
    path = result.get("file_path") if result else None
    return bool(path) and self_integrity.is_verified_self_file(path)


def label_for(result, check_self=True):
    """The label for a scan_engine result / scan_log entry (anything with a
    "tier" and, for the self check, a "file_path"). check_self=False for
    entries whose file isn't at its path any more (quarantined)."""
    tier = (result or {}).get("tier")
    if check_self and is_verified_self(result):
        return KNOWN_GOOD
    if tier == "ignored":
        return KNOWN_GOOD
    if tier in HIGH_RISK_TIERS:
        return HIGH_RISK
    if tier == "suspicious":
        return SUSPICIOUS
    return NOT_FLAGGED


def verdict_text(result, check_self=True):
    """(text, colour token): the label plus the raw tier, so nothing the
    scan recorded is hidden - e.g. "High Risk · malware",
    "Known Good · DEVADARA file (scan said: suspicious)"."""
    tier = (result or {}).get("tier")
    label = label_for(result, check_self)
    if label == KNOWN_GOOD and tier != "ignored":
        text = f"{KNOWN_GOOD} · DEVADARA file" + (f" (scan said: {tier})" if tier else "")
    elif not tier or tier.lower() == label.lower():
        text = label
    else:
        text = f"{label} · {tier}"
    return text, COLOR_TOKENS[label]
