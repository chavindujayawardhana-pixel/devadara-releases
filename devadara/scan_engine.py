"""
scan_engine.py

This ties DEVADARA's four detection layers together into one pipeline, in
a fixed order: Hash Check -> YARA Rules Check -> Digital Signature Check ->
ML Model Check. Each layer only runs if the previous one didn't already
reach a verdict - that order matters:

1. Hash check is exact and free of false positives (it's only ever wrong
   if our own known-bad list is wrong), so it goes first and is decisive -
   and it's the only OTHER check that runs against every file regardless
   of type, alongside YARA, so a known threat is still caught no matter
   what extension it's wearing.
2. YARA rules check goes next, against every file regardless of type (see
   devadara/yara_scanner.py) - it's the only layer here that inspects
   non-executable files at all (scripts, documents, ransom notes), since
   the signature check and ML model both only apply to executable-shaped
   files. A rule tagged severity="high" is decisive, same as a hash match.
   A rule tagged severity="suspicious" sets a FLOOR: the verdict can still
   be pushed higher by what comes next (a trusted-publisher-name match
   downgrading a malware verdict, or the ML model finding it outright
   malicious), but nothing downstream - not even a fully valid, chain-
   trusted signature - can erase it back down to "safe"/"trusted_signed".
   That's deliberate: a YARA match is concrete evidence actually present
   in the file, unlike ML's structural heuristics or a signature's trust
   inference, and concrete evidence shouldn't be silently overridden by a
   trust signal - only downgraded from an even stronger verdict, the same
   principle already applied to the trusted-publisher-name fallback below.
3. Digital signature check goes next, BEFORE the ML model, so that a file
   Windows itself vouches for (a full, chain-verified, non-expired
   Authenticode signature) never gets a chance to be misjudged by the ML
   layer's structural heuristics - this is what fixes the SmadAV-style
   false positive, where a legitimate but structurally-unusual executable
   was flagged as malware by the ML layer alone. This check is skipped
   for files whose extension isn't executable-shaped (see
   EXECUTABLE_EXTENSIONS below) - measured on a real Downloads folder,
   each signature check spawns a full powershell.exe process and costs
   ~1-4 seconds, which is fine for the handful of .exe/.dll files you
   actually care about but is a real problem when it's spent identically
   on every .jpg and .pdf a browser ever downloaded.
4. ML model check runs last, only for files that reached this point
   unresolved, and reports one of three tiers (see ml_scanner.py) instead
   of a binary verdict.

usb_scan_cli.py and downloads_scan_cli.py both call evaluate_file() so this
pipeline is implemented exactly once.
"""

import os

from devadara import yara_scanner
from devadara.hash_scanner import compute_sha256
from devadara.ml_scanner import predict_file
from devadara.signature_scanner import check_digital_signature, load_trusted_publishers

# Authenticode signatures - and DEVADARA's ML layer - are only meaningful
# for executable-shaped files. Everything else (images, documents,
# archives, ...) skips straight to "not_pe" without ever spawning
# powershell.exe for a signature check it couldn't act on anyway.
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ".com",
    ".msi", ".msix", ".appx",
}


def _looks_executable(file_path):
    return os.path.splitext(file_path)[1].lower() in EXECUTABLE_EXTENSIONS


def evaluate_file(file_path, known_bad_hashes, model, feature_columns, trusted_publishers=None):
    """
    Run the full Hash -> Signature -> ML pipeline against one file.

    trusted_publishers: list of trusted publisher names (see
                         signature_scanner.load_trusted_publishers()). Pass
                         this in explicitly when scanning many files so the
                         whitelist is only loaded from disk once; if
                         omitted, it's loaded fresh for this one file.

    Returns a dictionary:
        {
            "file_path": file_path,
            "hash": str | None,       # None if the file couldn't be read
            "tier": str,              # see below
            "threat_name": str | None,     # set when tier == "known_bad", or
                                            # when a "high" severity YARA rule matched
            "yara": list,                  # yara_scanner.scan_file() matches - always
                                            # populated (possibly empty), since YARA runs
                                            # against every file regardless of type
            "signature": dict | None,      # check_digital_signature() result, or None if never reached
            "ml": dict | None,             # predict_file() result, or None if never reached
            "downgraded_from_malware": bool,
        }

    tier is one of:
        "unreadable"     - couldn't hash the file (locked, permissions, etc.)
        "known_bad"      - exact hash match against known threats
        "trusted_signed" - valid, non-expired, chain-trusted Authenticode signature; ML skipped
        "not_pe"         - not an executable-shaped file (see EXECUTABLE_EXTENSIONS),
                            or a PE-shaped file pefile still couldn't parse;
                            signature/ML checks don't apply to these
        "malware"        - ML confidence >= 85%, OR a "high" severity YARA
                            rule matched (see "yara" above and "threat_name")
        "suspicious"     - ML confidence 60-85% (needs manual review), a
                            "malware" verdict downgraded because the file's
                            (chain-unverified) publisher name matched our
                            local whitelist (see signature_scanner.py for why
                            that match alone can't grant "safe"), or a
                            "suspicious" severity YARA rule matched - note
                            this last case can leave "signature"/"ml" as
                            None, since a YARA match on a non-executable file
                            (a ransom note, a malicious script) never reaches
                            those checks at all
        "safe"           - ML confidence < 60%
    """
    result = {
        "file_path": file_path,
        "hash": None,
        "tier": "unreadable",
        "threat_name": None,
        "yara": [],
        "signature": None,
        "ml": None,
        "downgraded_from_malware": False,
    }

    file_hash = compute_sha256(file_path)
    if file_hash is None:
        return result
    result["hash"] = file_hash

    if file_hash in known_bad_hashes:
        result["tier"] = "known_bad"
        result["threat_name"] = known_bad_hashes[file_hash]
        return result

    yara_matches = yara_scanner.scan_file(file_path)
    result["yara"] = yara_matches
    yara_tier = yara_scanner.highest_severity_tier(yara_matches)

    if yara_tier == "malware":
        result["tier"] = "malware"
        result["threat_name"] = "YARA: " + ", ".join(
            m["rule"] for m in yara_matches if m["severity"] == "high"
        )
        return result

    # yara_tier is now None or "suspicious" - a "suspicious" match is a
    # FLOOR (see the module docstring above): the checks below can still
    # push the verdict higher, but none of them can bring it back down past
    # "suspicious", so every remaining return in this function routes
    # through this instead of hardcoding its usual tier.
    def _tier_or_floor(usual_tier):
        return "suspicious" if yara_tier == "suspicious" else usual_tier

    if not _looks_executable(file_path):
        result["tier"] = _tier_or_floor("not_pe")
        return result

    if trusted_publishers is None:
        trusted_publishers = load_trusted_publishers()

    signature = check_digital_signature(file_path, trusted_publishers=trusted_publishers)
    result["signature"] = signature

    if signature["valid_and_trusted"]:
        result["tier"] = _tier_or_floor("trusted_signed")
        return result

    if model is None:
        result["tier"] = _tier_or_floor("not_pe")  # no model loaded - can't say more than "not a known threat"
        return result

    ml_result = predict_file(file_path, model, feature_columns)
    result["ml"] = ml_result

    if not ml_result["is_pe"]:
        result["tier"] = _tier_or_floor("not_pe")
        return result

    tier = ml_result["tier"]
    if tier == "malware" and signature["trusted_publisher_match"]:
        tier = "suspicious"
        result["downgraded_from_malware"] = True

    result["tier"] = tier if tier == "malware" else _tier_or_floor(tier)
    return result
