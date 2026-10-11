"""
protection_modules.py

The ONE list of DEVADARA's real-time protection modules, and the one rule
that turns their state into the protection status the Dashboard and the
sidebar show. Everything that counts or lists modules reads
PROTECTION_MODULES - the Protection page builds its toggle cards from it,
AutoScanController starts/stops/counts from it - so a module added here is
counted and shown everywhere automatically. Nothing hardcodes how many
there are.

Windows Startup is deliberately NOT a protection module: it only decides
whether DEVADARA launches at sign-in, it doesn't watch anything.

The status never shows numbers - only a label and a colour:
    every module running  -> SECURED              (theme.NEON)
    some running          -> PARTIALLY PROTECTED  (theme.WARN)
    none running          -> NOT PROTECTED        (theme.DANGER)
"Running" means the watcher is actually running, not just switched on -
e.g. Downloads Auto-Scan switched on with no Downloads folder isn't running.
"""

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class ProtectionModule:
    key: str
    title: str
    description: str
    config_key: str           # on/off saved in gui_state.json (config_store)
    start: Callable           # start(controller)
    stop: Callable            # stop(controller)
    is_running: Callable      # is_running(controller) -> bool
    default_on: bool = True


PROTECTION_MODULES = [
    ProtectionModule(
        key="downloads",
        title="Downloads Auto-Scan",
        description="Automatically scans every new file that finishes arriving in your Downloads folder.",
        config_key="downloads_autoscan_enabled",
        start=lambda c: c.start_downloads_watch(),
        stop=lambda c: c.stop_downloads_watch(),
        is_running=lambda c: c.is_downloads_watch_running(),
    ),
    ProtectionModule(
        key="usb",
        title="USB Auto-Scan",
        description="Automatically scans a removable drive the moment it's connected.",
        config_key="usb_autoscan_enabled",
        start=lambda c: c.start_usb_watch(),
        stop=lambda c: c.stop_usb_watch(),
        is_running=lambda c: c.is_usb_watch_running(),
    ),
    ProtectionModule(
        key="behavior",
        title="Behavior Monitoring",
        description="Warns when many files in Downloads change very fast — a possible sign of "
                    "ransomware. Never acts on its own.",
        config_key="behavior_monitor_enabled",
        start=lambda c: c.start_behavior_watch(),
        stop=lambda c: c.stop_behavior_watch(),
        is_running=lambda c: c.is_behavior_watch_running(),
    ),
]

SECURED = "secured"
PARTIAL = "partial"
NOT_PROTECTED = "off"
STARTING = "starting"  # before the watchers have been started at all

# level -> (label, theme colour token). STARTING is shown dim and never
# claims protection before the watchers really run.
LEVEL_VIEW = {
    SECURED: ("SECURED", "NEON"),
    PARTIAL: ("PARTIALLY PROTECTED", "WARN"),
    NOT_PROTECTED: ("NOT PROTECTED", "DANGER"),
    STARTING: ("STARTING…", "TEXT_DIM"),
}


def protection_level(running_flags):
    """SECURED if every module is running, PARTIAL if some are,
    NOT_PROTECTED if none are (or there are no modules at all)."""
    flags = [bool(f) for f in running_flags]
    if flags and all(flags):
        return SECURED
    if any(flags):
        return PARTIAL
    return NOT_PROTECTED
