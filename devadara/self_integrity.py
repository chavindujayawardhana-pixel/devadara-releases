"""
self_integrity.py

Lets DEVADARA tell whether its own program files are the genuine, unchanged
files that were shipped - so it can show them as Known Good and refuse to
quarantine them - WITHOUT ever excluding its own folder from scanning.

How it works:
- At build time (tools/sign_manifest.py, run AFTER PyInstaller has
  finished the --onedir folder) every covered file of the finished package
  is hashed into integrity_manifest.json, and the exact bytes of that file
  are signed with the owner's Ed25519 private key into
  integrity_manifest.sig. Both sit next to the exe and are not themselves
  covered. The private key never ships; only the public key does
  (devadara/integrity_pubkey.py).
- At runtime check_install() verifies the signature, then compares every
  file on disk against the manifest: changed, missing, unreadable, and
  extra (covered but not listed) files are reported. It only reads - it
  never deletes, moves or quarantines anything.
- is_verified_self_file() answers "is this exact file a genuine DEVADARA
  file?" for one path + hash: only if the signature is valid, the path is
  under the install folder and listed, and the hash matches.

Nothing here changes a scan verdict - scan_engine.evaluate_file() still
runs on every DEVADARA file like any other. A changed or unlisted file is
just an ordinary file.

What this cannot do: whoever replaces the exe (or the code holding this
check or the public key) controls the check itself. See CLAUDE.md.

Every public function here degrades to a status / False instead of
raising - an integrity problem must never crash the app.
"""

import json
import os
import re
from datetime import datetime
from pathlib import PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from devadara import app_paths, integrity_pubkey
from devadara.hash_scanner import compute_sha256

MANIFEST_NAME = "integrity_manifest.json"
SIGNATURE_NAME = "integrity_manifest.sig"
MANIFEST_FORMAT = 1
SIGNATURE_BYTES = 64                      # Ed25519 signatures are always 64 bytes
MAX_MANIFEST_BYTES = 32 * 1024 * 1024     # far above any real manifest; refuse anything bigger

# Statuses check_install() can return.
VERIFIED = "verified"                  # signature valid, every covered file matches
PROBLEMS = "problems"                  # signature valid, but files changed/missing/extra/unreadable
BAD_SIGNATURE = "bad_signature"        # manifest/signature missing, invalid or malformed
NOT_SIGNED_BUILD = "not_signed_build"  # running from source, or no public key built in
ERROR = "error"                        # the check itself couldn't run

# ─── MANIFEST_RULES: which files the manifest covers ───
# One rule set, shared by the signing tool (what goes in) and the checker
# (what counts as an "extra" file). Paths are relative to the install
# folder, with forward slashes.

# Never covered, at any depth: Python's own bytecode caches.
EXCLUDED_DIR_NAMES = {"__pycache__"}
# Never covered at the top of the install folder: dev-only folders and
# nothing a build ships. Top level only - a bundled library may well have
# its own "tests" or "build" package, and that's program code like any other.
EXCLUDED_TOP_DIRS = {"venv", ".venv", ".git", ".claude", "tests", "logs", "build", "dist"}
# Where DEVADARA's data/ folder sits: the project root from source,
# _internal/ in a PyInstaller --onedir build.
DATA_DIR_PREFIXES = (("data",), ("_internal", "data"))
# data/ subfolders that are runtime state or never shipped.
EXCLUDED_DATA_DIRS = {"quarantine", "raw"}
# The only data/*.json(l) files covered: shipped with the app, never
# written at runtime. Every other data/*.json / *.jsonl is runtime state
# (scan_log, ignored_files, memory_hashes, gui_state, quarantine_index, ...).
STATIC_DATA_FILES = {"known_bad_hashes.json", "trusted_publishers.json"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".log", ".tmp"}
EXCLUDED_FILE_PATTERNS = [re.compile(p) for p in (r".*_dump\.txt$", r"^dump_.*\.txt$")]


def is_covered(rel_path):
    """True if the file at this install-relative path (forward slashes)
    belongs in the manifest."""
    parts = PurePosixPath(rel_path).parts
    if not parts:
        return False
    name = parts[-1]
    if len(parts) == 1 and name in (MANIFEST_NAME, SIGNATURE_NAME):
        return False
    if any(p in EXCLUDED_DIR_NAMES for p in parts[:-1]):
        return False
    if len(parts) > 1 and parts[0] in EXCLUDED_TOP_DIRS:
        return False
    suffix = os.path.splitext(name)[1].lower()
    if suffix in EXCLUDED_SUFFIXES:
        return False
    if any(p.match(name) for p in EXCLUDED_FILE_PATTERNS):
        return False
    for prefix in DATA_DIR_PREFIXES:
        if parts[:len(prefix)] != prefix:
            continue
        below = parts[len(prefix):]
        if len(below) > 1 and below[0] in EXCLUDED_DATA_DIRS:
            return False
        if len(below) == 1 and suffix in (".json", ".jsonl") and name not in STATIC_DATA_FILES:
            return False
    return True


def iter_covered_files(root):
    """Every covered file under root, as sorted install-relative paths."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        at_top = os.path.normcase(dirpath) == os.path.normcase(root)
        dirnames[:] = [d for d in dirnames
                       if d not in EXCLUDED_DIR_NAMES
                       and not (at_top and d in EXCLUDED_TOP_DIRS)
                       and not os.path.islink(os.path.join(dirpath, d))]
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if is_covered(rel):
                found.append(rel)
    return sorted(found)


class ManifestError(Exception):
    pass


def hash_tree(root):
    """[{"path", "sha256", "size"}] for every covered file under root.
    Build-time only: raises ManifestError if any file can't be read,
    because a manifest with a gap in it is worse than no manifest."""
    entries = []
    for rel in iter_covered_files(root):
        full = os.path.join(root, *rel.split("/"))
        digest = compute_sha256(full)
        if digest is None:
            raise ManifestError(f"could not read {rel}")
        entries.append({"path": rel, "sha256": digest, "size": os.path.getsize(full)})
    return entries


def build_manifest_bytes(root, app_version=None, created_at=None):
    """The exact bytes of integrity_manifest.json for the folder at root.
    These bytes are what gets signed - they're never re-serialised."""
    manifest = {
        "format": MANIFEST_FORMAT,
        "app_version": app_version,
        "created_at": created_at or datetime.now().isoformat(timespec="seconds"),
        "files": hash_tree(root),
    }
    return (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode("utf-8")


# ─── signature ───

def public_key_from_hex(hex_key):
    """An Ed25519PublicKey from a 64-character hex string, or None."""
    try:
        raw = bytes.fromhex(hex_key)
        if len(raw) != 32:
            return None
        return Ed25519PublicKey.from_public_bytes(raw)
    except (TypeError, ValueError):
        return None


def embedded_public_key():
    """The public key built into this copy of DEVADARA, or None."""
    key = integrity_pubkey.PUBLIC_KEY
    return public_key_from_hex(key) if key else None


def verify_signature(manifest_bytes, signature_bytes, public_key):
    """True only if signature_bytes is a valid Ed25519 signature of exactly
    manifest_bytes under public_key. Never raises."""
    if public_key is None or not isinstance(signature_bytes, bytes) \
            or len(signature_bytes) != SIGNATURE_BYTES:
        return False
    try:
        public_key.verify(signature_bytes, manifest_bytes)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _safe_rel_path(path):
    """A manifest entry's path is only accepted if it's a plain relative,
    forward-slash path that can't climb out of the install folder."""
    if not isinstance(path, str) or not path or "\\" in path or ":" in path or "\x00" in path:
        return False
    parts = PurePosixPath(path)
    if parts.is_absolute():
        return False
    return all(part not in ("", ".", "..") for part in path.split("/"))


def parse_manifest(manifest_bytes):
    """{rel_path: (sha256, size)} from verified manifest bytes. Raises
    ManifestError on anything malformed or unsafe - checked even though
    the signature already passed, so a mistake in the signing tool can't
    turn into a path outside the install folder."""
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ManifestError(f"manifest isn't valid JSON: {exc}")
    if not isinstance(manifest, dict) or manifest.get("format") != MANIFEST_FORMAT:
        raise ManifestError("unknown manifest format")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ManifestError("manifest has no file list")
    entries = {}
    for entry in files:
        if not isinstance(entry, dict):
            raise ManifestError("malformed manifest entry")
        path, digest, size = entry.get("path"), entry.get("sha256"), entry.get("size")
        if not _safe_rel_path(path):
            raise ManifestError(f"unsafe path in manifest: {path!r}")
        if not isinstance(digest, str) or not _HEX64.match(digest):
            raise ManifestError(f"bad hash for {path}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ManifestError(f"bad size for {path}")
        key = path.lower()  # Windows paths are case-insensitive
        if key in entries:
            raise ManifestError(f"duplicate entry: {path}")
        entries[key] = (path, digest, size)
    return entries


def _read_limited(path, limit):
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ManifestError(f"{os.path.basename(path)} is unexpectedly large")
    return data


def load_verified_manifest(root=None, public_key=None):
    """(status, entries, message). entries is parse_manifest()'s dict when
    status is VERIFIED (meaning only: the signature is valid), else None."""
    root = root or app_paths.INSTALL_ROOT
    public_key = public_key or embedded_public_key()
    if public_key is None:
        return NOT_SIGNED_BUILD, None, "no integrity key is built into this copy"
    manifest_path = os.path.join(root, MANIFEST_NAME)
    signature_path = os.path.join(root, SIGNATURE_NAME)
    have_manifest, have_signature = os.path.isfile(manifest_path), os.path.isfile(signature_path)
    if not have_manifest and not have_signature and not app_paths.FROZEN:
        return NOT_SIGNED_BUILD, None, "running from source - no signed manifest"
    if not have_manifest or not have_signature:
        missing = MANIFEST_NAME if not have_manifest else SIGNATURE_NAME
        return BAD_SIGNATURE, None, f"{missing} is missing"
    try:
        manifest_bytes = _read_limited(manifest_path, MAX_MANIFEST_BYTES)
        signature_bytes = _read_limited(signature_path, SIGNATURE_BYTES)
    except ManifestError as exc:  # oversized manifest/signature: malformed, not a read failure
        return BAD_SIGNATURE, None, str(exc)
    except OSError as exc:
        return ERROR, None, f"couldn't read the manifest: {exc}"
    if not verify_signature(manifest_bytes, signature_bytes, public_key):
        return BAD_SIGNATURE, None, "the manifest's signature doesn't match - it was changed or not signed by the DEVADARA key"
    try:
        return VERIFIED, parse_manifest(manifest_bytes), "signature valid"
    except ManifestError as exc:
        return BAD_SIGNATURE, None, str(exc)


def _result(status, root, message, **lists):
    result = {"status": status, "root": root, "message": message, "checked": 0,
              "changed": [], "missing": [], "extra": [], "unreadable": [],
              "checked_at": datetime.now().isoformat(timespec="seconds")}
    result.update(lists)
    return result


def check_install(root=None, public_key=None):
    """Compare the install folder with its signed manifest. Never raises.

    Returns {"status", "root", "message", "checked", "changed", "missing",
    "extra", "unreadable", "checked_at"} - the four lists hold
    install-relative paths. Only reads files."""
    root = root or app_paths.INSTALL_ROOT
    try:
        status, entries, message = load_verified_manifest(root, public_key)
        if status != VERIFIED:
            return _result(status, root, message)
        changed, missing, unreadable = [], [], []
        for path, digest, size in entries.values():
            full = os.path.join(root, *path.split("/"))
            if not os.path.isfile(full):
                missing.append(path)
                continue
            try:
                if os.path.getsize(full) != size:  # cheap check before hashing
                    changed.append(path)
                    continue
            except OSError:
                unreadable.append(path)
                continue
            actual = compute_sha256(full)
            if actual is None:
                unreadable.append(path)
            elif actual != digest:
                changed.append(path)
        extra = [rel for rel in iter_covered_files(root) if rel.lower() not in entries]
        problems = bool(changed or missing or extra or unreadable)
        if problems:
            parts = [f"{len(lst)} {name}" for name, lst in
                     (("changed", changed), ("missing", missing), ("extra", extra),
                      ("unreadable", unreadable)) if lst]
            message = "problems found: " + ", ".join(parts)
        else:
            message = f"all {len(entries)} files match the signed manifest"
        return _result(PROBLEMS if problems else VERIFIED, root, message, checked=len(entries),
                       changed=changed, missing=missing, extra=extra, unreadable=unreadable)
    except Exception as exc:  # never let the self-check crash the app
        return _result(ERROR, root, f"the check couldn't run: {exc}")


# ─── per-file: is this a genuine DEVADARA file? ───

# The verified manifest, re-read only when the manifest/signature files
# change on disk - is_verified_self_file() may be asked about many files.
_cache = {"key": None, "entries": None}


def _stamp(path):
    try:
        st = os.stat(path)
        return st.st_mtime_ns, st.st_size
    except OSError:
        return None


def _verified_entries(root, public_key):
    key = (os.path.normcase(os.path.abspath(root)), id(public_key) if public_key else None,
           integrity_pubkey.PUBLIC_KEY,
           _stamp(os.path.join(root, MANIFEST_NAME)), _stamp(os.path.join(root, SIGNATURE_NAME)))
    if _cache["key"] != key:
        status, entries, _ = load_verified_manifest(root, public_key)
        _cache["key"], _cache["entries"] = key, (entries if status == VERIFIED else None)
    return _cache["entries"]


def is_verified_self_file(file_path, sha256=None, root=None, public_key=None):
    """True only if file_path is inside the install folder, listed in a
    manifest whose signature is valid, and its content hash matches.
    sha256: the file's CURRENT hash if the caller just computed it; if
    omitted it's computed here. Never raises; any doubt means False."""
    try:
        root = root or app_paths.INSTALL_ROOT
        if not file_path:
            return False
        root_abs = os.path.normcase(os.path.abspath(root))
        file_abs = os.path.normcase(os.path.abspath(file_path))
        if os.path.commonpath([root_abs, file_abs]) != root_abs or file_abs == root_abs:
            return False
        rel = os.path.relpath(file_abs, root_abs).replace(os.sep, "/")
        entries = _verified_entries(root, public_key)
        if not entries:
            return False
        entry = entries.get(rel.lower())
        if entry is None:
            return False
        if sha256 is None:
            sha256 = compute_sha256(file_path)
        return sha256 is not None and sha256.lower() == entry[1]
    except Exception:
        return False
