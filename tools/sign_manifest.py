"""
sign_manifest.py - OWNER ONLY, the last step of every release build.

Run AFTER PyInstaller has finished the --onedir folder (never before -
any later change to the folder breaks the manifest):

    venv\\Scripts\\python.exe tools\\sign_manifest.py --dist dist\\DEVADARA --key E:\\devadara-keys\\integrity_private.pem

It hashes every covered file of the finished folder
(self_integrity.MANIFEST_RULES), writes integrity_manifest.json + its
Ed25519 signature integrity_manifest.sig next to the exe, then re-checks
the folder with the public key built into the app
(devadara/integrity_pubkey.py) and fails loudly if anything doesn't
match. The passphrase is asked for, never stored.

Why --onedir and why afterwards: a --onefile exe would have to contain the
manifest, but the manifest contains the exe's hash, which changes as soon
as the manifest is put inside it - a circular dependency. A --onedir build
keeps the manifest beside the exe, and the files on disk are exactly the
files that run.

100% local: no network. It only writes the two manifest files.
"""

import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from devadara import self_integrity


class SignError(Exception):
    pass


def _norm(path):
    return os.path.normcase(os.path.abspath(path))


def load_private_key(key_path, passphrase):
    try:
        with open(key_path, "rb") as f:
            pem = f.read()
    except OSError as exc:
        raise SignError(f"can't read the key file: {exc}")
    try:
        key = serialization.load_pem_private_key(pem, password=passphrase.encode("utf-8"))
    except (ValueError, TypeError):
        raise SignError("wrong passphrase, or not a DEVADARA private key")
    if not isinstance(key, Ed25519PrivateKey):
        raise SignError("that key isn't an Ed25519 key")
    return key


def _write_atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def sign_folder(dist, key_path, passphrase, expected_public_key=None, app_version=None):
    """Sign the finished build folder. expected_public_key: the key the
    app will verify with - the one in integrity_pubkey.py unless a test
    passes its own. Returns check_install()'s result for the signed folder."""
    if not os.path.isdir(dist):
        raise SignError(f"{dist} isn't a folder")
    try:
        if os.path.commonpath([_norm(key_path), _norm(dist)]) == _norm(dist):
            raise SignError("the private key is inside the build folder - move it out first")
    except ValueError:
        pass  # different drives: fine
    expected = expected_public_key or self_integrity.embedded_public_key()
    if expected is None:
        raise SignError("no public key in devadara/integrity_pubkey.py yet - "
                        "run tools/integrity_keygen.py and paste it in, then rebuild")
    private_key = load_private_key(key_path, passphrase)
    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    if private_key.public_key().public_bytes(*raw) != expected.public_bytes(*raw):
        raise SignError("this private key doesn't match the public key built into the app")

    try:
        manifest_bytes = self_integrity.build_manifest_bytes(dist, app_version=app_version)
    except self_integrity.ManifestError as exc:
        raise SignError(f"couldn't hash the build: {exc}")
    signature = private_key.sign(manifest_bytes)
    _write_atomic(os.path.join(dist, self_integrity.MANIFEST_NAME), manifest_bytes)
    _write_atomic(os.path.join(dist, self_integrity.SIGNATURE_NAME), signature)

    result = self_integrity.check_install(dist, expected)
    if result["status"] != self_integrity.VERIFIED:
        raise SignError(f"the signed folder doesn't verify: {result['message']}")
    return result


def main(argv):
    parser = argparse.ArgumentParser(description="Sign a finished DEVADARA --onedir build.")
    parser.add_argument("--dist", required=True, help=r"the finished build folder, e.g. dist\DEVADARA")
    parser.add_argument("--key", required=True, help="the encrypted private key (.pem), outside the repo")
    parser.add_argument("--app-version", default=None)
    args = parser.parse_args(argv[1:])
    passphrase = getpass.getpass("Passphrase for the private key: ")
    try:
        result = sign_folder(args.dist, args.key, passphrase, app_version=args.app_version)
    except (SignError, OSError) as exc:
        print(f"[FAILED] {exc}")
        return 1
    print(f"[SIGNED] {result['checked']} files - {result['message']}")
    print(f"Wrote {self_integrity.MANIFEST_NAME} and {self_integrity.SIGNATURE_NAME} in {os.path.abspath(args.dist)}")
    print("Don't change anything in that folder now - any change breaks the check. Rebuild -> sign again.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
