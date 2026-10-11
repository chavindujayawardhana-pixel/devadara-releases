"""
integrity_pubkey.py

The Ed25519 PUBLIC key that DEVADARA's integrity manifest must be signed
with (see devadara/self_integrity.py). Only the public half ever lives in
the app or the repo - the private key stays with the owner, outside the
repo and outside every build (see tools/integrity_keygen.py).

None until the owner generates a key pair: the self-check then reports
"not a signed build" and no file is treated as a verified DEVADARA file.
Paste the 64-character hex string tools/integrity_keygen.py prints, e.g.

    PUBLIC_KEY = "3f1c...a9"   # SHA256 fingerprint: ...
"""

PUBLIC_KEY = None
