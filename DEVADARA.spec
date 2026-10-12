# -*- mode: python ; coding: utf-8 -*-
r"""
DEVADARA.spec - PyInstaller build of the desktop app (Step 7).

    venv\Scripts\pyinstaller.exe DEVADARA.spec --clean --noconfirm

--onedir (never --onefile - see tools/sign_manifest.py), no console window,
no UPX (DEVADARA's own packers.yar flags UPX-packed files, and UPX raises
antivirus false positives). Output: dist\DEVADARA\DEVADARA.exe + _internal\.

Bundled = only the read-only program files the app opens via
app_paths.app_file(); they land in _internal\ at the same relative path.
Never bundled: runtime state (gui_state, scan_log, memory_hashes, ignore
list, quarantine...), data\raw\ (training data), the HTML mockups,
dumps, tests\, and the owner-only tools (integrity_keygen, sign_manifest).

After every build: sign it, untouched -
    venv\Scripts\python.exe tools\sign_manifest.py --dist dist\DEVADARA --key <private key outside the repo>
"""

import os

ROOT = SPECPATH  # the folder holding this spec = the project root


def src(*parts):
    return os.path.join(ROOT, *parts)


datas = [
    (src("data", "known_bad_hashes.json"), "data"),       # hash layer (memory.py)
    (src("data", "trusted_publishers.json"), "data"),     # signature trust list
    (src("data", "yara_rules", "*.yar"), "data/yara_rules"),
    (src("models", "malware_model.joblib"), "models"),    # ML layer
    (src("models", "feature_columns.json"), "models"),
    (src("tools", "yara64.exe"), "tools"),                # YARA layer
    (src("tools", "batch_signature_check.ps1"), "tools"), # signature layer
    (src("tools", "NOTICE.txt"), "tools"),                # YARA licence notice
    (src("assets", "app_icon.png"), "assets"),            # window / tray icon
    (src("assets", "app_icon_base.png"), "assets"),       # scan orbit animation
    (src("assets", "app_icon_orbit.png"), "assets"),
]

a = Analysis(
    [src("gui_app.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="DEVADARA",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=src("assets", "app_icon.ico"),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="DEVADARA",
)
