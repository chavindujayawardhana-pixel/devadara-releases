"""devadara_gui - the PySide6 desktop interface for DEVADARA.

This package only ever displays and orchestrates the real detection engines
that already live under devadara/ (hash/YARA/signature/ML scanning, behavior
monitoring, persistence/process checks, quarantine, ...). No detection logic
is duplicated or re-implemented here - see devadara_gui/services/app_state.py
for how the GUI wires itself to those existing modules.
"""
