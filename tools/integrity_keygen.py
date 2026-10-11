"""
integrity_keygen.py - OWNER ONLY, run once.

Creates the Ed25519 key pair that signs DEVADARA's integrity manifest
(see devadara/self_integrity.py):

    venv\\Scripts\\python.exe tools\\integrity_keygen.py <private key path OUTSIDE the repo>

e.g.  tools\\integrity_keygen.py E:\\devadara-keys\\integrity_private.pem

- The PRIVATE key is written encrypted with a passphrase you type (asked
  twice, never echoed, never stored). The tool refuses a path inside this
  repo, inside a build/dist folder or a signed install, and never
  overwrites an existing file.
- The PUBLIC key is printed as hex: paste it into
  devadara/integrity_pubkey.py (PUBLIC_KEY = "...") and commit that.
  Only the public key ever goes into the app.

KEY BACKUP - do this right after creating the key:
  1. Keep TWO offline copies of the encrypted .pem, in different places
     (e.g. a USB stick stored away from the PC + an attachment in an
     encrypted password manager).
  2. Store the passphrase separately from the .pem (e.g. in the password
     manager, not on the USB stick).
  3. Write down the public-key fingerprint printed below - it identifies
     the right key later.
  4. Test the backup once: sign a dummy folder with the backup copy
     (tools/sign_manifest.py) before you rely on it.
  5. If the key or passphrase is ever lost: run this tool again, put the
     new public key in integrity_pubkey.py and ship a new build. Builds
     signed with the old key keep checking against the old key; there is
     no way to recover a lost private key.
  If the private key may have been stolen: same as lost - new key, new
  build - since anyone holding it can sign a tampered build.

100% local: no network, nothing else is created or changed.
"""

import getpass
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from devadara import app_paths, self_integrity

MIN_PASSPHRASE_LENGTH = 12
FORBIDDEN_DIR_NAMES = {"dist", "build"}


class KeygenError(Exception):
    pass


def _norm(path):
    return os.path.normcase(os.path.abspath(path))


def _is_inside(path, folder):
    try:
        return os.path.commonpath([_norm(path), _norm(folder)]) == _norm(folder)
    except ValueError:  # different drives
        return False


def refusal_reason(key_path, repo_root=None):
    """Why the private key must not be written to key_path, or None."""
    repo_root = repo_root or app_paths.INSTALL_ROOT
    if _is_inside(key_path, repo_root):
        return "that's inside the DEVADARA project folder - keep the private key outside the repo"
    folder = os.path.dirname(_norm(key_path))
    while True:
        if os.path.basename(folder) in FORBIDDEN_DIR_NAMES:
            return f"that's inside a '{os.path.basename(folder)}' folder - never put the key in a build"
        if os.path.isfile(os.path.join(folder, self_integrity.MANIFEST_NAME)):
            return "that's inside a signed DEVADARA install - never ship the private key"
        parent = os.path.dirname(folder)
        if parent == folder:
            break
        folder = parent
    if os.path.exists(key_path):
        return "a file already exists there - this tool never overwrites a key"
    return None


def public_key_hex(public_key):
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw.hex()


def fingerprint(public_key):
    """SHA256 of the raw public key - to recognise the right key later."""
    return hashlib.sha256(bytes.fromhex(public_key_hex(public_key))).hexdigest()


def generate_keypair(key_path, passphrase, repo_root=None):
    """Write a new passphrase-encrypted private key to key_path and return
    its public key. Raises KeygenError instead of writing anywhere unsafe."""
    reason = refusal_reason(key_path, repo_root)
    if reason:
        raise KeygenError(reason)
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise KeygenError(f"the passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters")
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode("utf-8")))
    parent = os.path.dirname(os.path.abspath(key_path))
    if not os.path.isdir(parent):
        raise KeygenError(f"the folder {parent} doesn't exist")
    with open(key_path, "xb") as f:  # "x": never overwrite
        f.write(pem)
    return private_key.public_key()


def main(argv):
    if len(argv) != 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 2
    key_path = argv[1]
    reason = refusal_reason(key_path)
    if reason:
        print(f"[REFUSED] {key_path}: {reason}")
        return 1
    passphrase = getpass.getpass("Passphrase for the private key (min 12 characters): ")
    if getpass.getpass("Type it again: ") != passphrase:
        print("[REFUSED] The two passphrases don't match. Nothing was written.")
        return 1
    try:
        public_key = generate_keypair(key_path, passphrase)
    except (KeygenError, OSError) as exc:
        print(f"[REFUSED] {exc}. Nothing was written.")
        return 1
    print(f"\nPrivate key written (encrypted): {os.path.abspath(key_path)}")
    print("\nPaste this into devadara/integrity_pubkey.py:")
    print(f'    PUBLIC_KEY = "{public_key_hex(public_key)}"')
    print(f"\nPublic-key fingerprint (write it down): {fingerprint(public_key)}")
    print("\nNow back up the .pem - see the KEY BACKUP steps at the top of this file.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
