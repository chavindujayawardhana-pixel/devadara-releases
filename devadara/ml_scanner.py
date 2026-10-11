"""
ml_scanner.py

This is DEVADARA's "instinct" layer - it flags suspicious files based on
their structure, even if we've never seen that exact file before (unlike
the hash scanner, which only catches EXACT matches to known threats).

How it works:
1. We open a real Windows executable (.exe/.dll) with the `pefile` library,
   which understands the "PE" (Portable Executable) file format that all
   Windows programs use.
2. We read out the same 52 header fields that our model was trained on
   (see train_model.py for why we picked exactly these fields).
3. We feed those numbers into our already-trained model and ask: "does the
   structure of this file look more like malware or a legitimate program?"

This module NEVER trains or modifies the model - it only loads the file
that train_model.py already produced, and uses it to make predictions.
"""

import json
import os

import pefile

from devadara.app_paths import app_file

# joblib and pandas are imported inside the functions that use them, not
# here: together they cost ~2.8s to import, and this module is pulled in
# at GUI startup (via auto_scan_controller/scan_engine) long before any
# model load or prediction happens - importing them lazily keeps that
# cost off the path to the main window appearing. Python caches modules,
# so every call after the first pays nothing extra.

MODEL_PATH = app_file("models", "malware_model.joblib")
FEATURE_LIST_PATH = app_file("models", "feature_columns.json")


def load_model_and_features():
    """
    Load the pre-trained model and the exact list (and order) of feature
    columns it expects. Both files are produced once by train_model.py and
    bundled with the app - this function never trains anything.

    Returns (model, feature_columns) or (None, None) if the model files
    are missing (e.g. you haven't run train_model.py yet).
    """
    if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURE_LIST_PATH):
        print("[WARNING] ML model not found. Run 'python -m devadara.train_model' first.")
        return None, None

    import joblib

    model = joblib.load(MODEL_PATH)
    with open(FEATURE_LIST_PATH, "r", encoding="utf-8") as f:
        feature_columns = json.load(f)

    return model, feature_columns


def extract_pe_features(file_path):
    """
    Open a file with `pefile` and pull out the 52 raw header fields our
    model expects, as a dictionary of {column_name: number}.

    Returns None if the file isn't a valid Windows PE executable (e.g. it's
    a text file, image, or corrupted/truncated .exe) - those files simply
    aren't something this model can judge, and get skipped by this layer.
    """
    try:
        # fast_load=True skips parsing extra data (imports/exports/etc.)
        # we don't need any of that for our chosen feature set, so this
        # keeps scanning quick and avoids errors in rarely-used PE sections.
        pe = pefile.PE(file_path, fast_load=True)
    except pefile.PEFormatError:
        return None  # not a valid PE file - not something this layer judges
    except Exception:
        # Any other read problem (locked file, permissions, etc.) - skip it
        # rather than crashing the whole scan.
        return None

    try:
        dos = pe.DOS_HEADER
        file_hdr = pe.FILE_HEADER
        opt = pe.OPTIONAL_HEADER

        features = {
            "e_magic": dos.e_magic, "e_cblp": dos.e_cblp, "e_cp": dos.e_cp,
            "e_crlc": dos.e_crlc, "e_cparhdr": dos.e_cparhdr,
            "e_minalloc": dos.e_minalloc, "e_maxalloc": dos.e_maxalloc,
            "e_ss": dos.e_ss, "e_sp": dos.e_sp, "e_csum": dos.e_csum,
            "e_ip": dos.e_ip, "e_cs": dos.e_cs, "e_lfarlc": dos.e_lfarlc,
            "e_ovno": dos.e_ovno, "e_oemid": dos.e_oemid,
            "e_oeminfo": dos.e_oeminfo, "e_lfanew": dos.e_lfanew,

            "Machine": file_hdr.Machine,
            "NumberOfSections": file_hdr.NumberOfSections,
            "TimeDateStamp": file_hdr.TimeDateStamp,
            "PointerToSymbolTable": file_hdr.PointerToSymbolTable,
            "NumberOfSymbols": file_hdr.NumberOfSymbols,
            "SizeOfOptionalHeader": file_hdr.SizeOfOptionalHeader,
            "Characteristics": file_hdr.Characteristics,

            "Magic": opt.Magic,
            "MajorLinkerVersion": opt.MajorLinkerVersion,
            "MinorLinkerVersion": opt.MinorLinkerVersion,
            "SizeOfCode": opt.SizeOfCode,
            "SizeOfInitializedData": opt.SizeOfInitializedData,
            "SizeOfUninitializedData": opt.SizeOfUninitializedData,
            "AddressOfEntryPoint": opt.AddressOfEntryPoint,
            # BaseOfCode is missing on some 64-bit (PE32+) optional headers,
            # so we fall back to 0 rather than crashing.
            "BaseOfCode": getattr(opt, "BaseOfCode", 0),
            "ImageBase": opt.ImageBase,
            "SectionAlignment": opt.SectionAlignment,
            "FileAlignment": opt.FileAlignment,
            "MajorOperatingSystemVersion": opt.MajorOperatingSystemVersion,
            "MinorOperatingSystemVersion": opt.MinorOperatingSystemVersion,
            "MajorImageVersion": opt.MajorImageVersion,
            "MinorImageVersion": opt.MinorImageVersion,
            "MajorSubsystemVersion": opt.MajorSubsystemVersion,
            "MinorSubsystemVersion": opt.MinorSubsystemVersion,
            "SizeOfHeaders": opt.SizeOfHeaders,
            "CheckSum": opt.CheckSum,
            "SizeOfImage": opt.SizeOfImage,
            "Subsystem": opt.Subsystem,
            "DllCharacteristics": opt.DllCharacteristics,
            "SizeOfStackReserve": opt.SizeOfStackReserve,
            "SizeOfStackCommit": opt.SizeOfStackCommit,
            "SizeOfHeapReserve": opt.SizeOfHeapReserve,
            "SizeOfHeapCommit": opt.SizeOfHeapCommit,
            "LoaderFlags": opt.LoaderFlags,
            "NumberOfRvaAndSizes": opt.NumberOfRvaAndSizes,
        }
    finally:
        pe.close()

    return features


# Tiered confidence thresholds, replacing a binary malware/safe split.
# A single hard cutoff (e.g. >=50%) treats a 51%-confident guess the same
# as a 99%-confident one, and gives no room for "this looks odd, a human
# should look at it" - which is exactly the gap that let a merely-unusual
# but legitimate file (e.g. an unsigned SmadAV component) get flagged as
# outright malware instead of routed for review.
MALWARE_THRESHOLD = 0.85
SUSPICIOUS_THRESHOLD = 0.60


def _tier_for_probability(probability_malware):
    if probability_malware >= MALWARE_THRESHOLD:
        return "malware"
    if probability_malware >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "safe"


def predict_file(file_path, model, feature_columns):
    """
    Run the ML model on a single file.

    Returns a dictionary:
        {
            "is_pe": True/False,     # was this even a Windows executable?
            "tier": str,             # only meaningful if is_pe is True:
                                      #   "malware"    confidence >= 85%
                                      #   "suspicious" confidence 60-85% (needs manual review)
                                      #   "safe"       confidence < 60%
            "confidence": 0.0-1.0,   # model's raw probability of malware
        }

    If the file isn't a valid PE executable, "is_pe" is False and the model
    is never consulted - this layer only judges .exe/.dll-style files.
    """
    features = extract_pe_features(file_path)

    if features is None:
        return {"is_pe": False, "tier": "safe", "confidence": 0.0}

    import pandas as pd

    # Build a single-row table with columns in the exact order the model
    # was trained on - scikit-learn matches columns by position, so order
    # matters here.
    row = pd.DataFrame([features], columns=feature_columns)

    # predict_proba gives us [probability_legitimate, probability_malware]
    # because the model's classes are [0, 1] in that order.
    probabilities = model.predict_proba(row)[0]
    probability_malware = probabilities[1]

    return {
        "is_pe": True,
        "tier": _tier_for_probability(probability_malware),
        "confidence": float(probability_malware),
    }
