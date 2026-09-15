"""
usb_monitor.py

This is DEVADARA's "skin and gut" layer - it watches the boundary where
something from OUTSIDE the machine gets plugged in, the way your body pays
extra attention to anything crossing in through a cut or something you
swallow. A USB stick is exactly that: unknown content, physically
introduced, that hasn't been through any of our other checks yet.

How it works:
1. Windows already knows the "type" of every drive letter - fixed internal
   disk, removable (USB flash drive / SD card), CD-ROM, network share, etc.
   `psutil.disk_partitions()` exposes that as a comma-separated `opts`
   string (e.g. "rw,fixed" or "rw,removable").
2. We poll the list of removable drives every few seconds on a background
   thread, and remember which ones we've already seen.
3. Any removable drive that wasn't there last time we checked is "new" -
   we call your on_drive_connected callback with its path (e.g. "E:\\"),
   so the rest of the app can scan it.

Honest limitation: this only catches drives Windows reports as
DRIVE_REMOVABLE. Some external USB hard drives identify themselves as
"fixed" depending on their enclosure, and won't be caught here - the same
"best-effort, not a certainty" spirit as behavior_monitor.py.

This module never scans or touches files itself - it only tells you when
a removable drive shows up. Scanning it is someone else's job (see
usb_scan_cli.py).
"""

import threading

import psutil


def list_removable_drives():
    """
    Return the set of mountpoints (e.g. {"E:\\"}) that Windows currently
    reports as removable drives.
    """
    removable = set()
    for partition in psutil.disk_partitions(all=False):
        if "removable" in partition.opts.split(","):
            removable.add(partition.mountpoint)
    return removable


class UsbMonitor:
    """
    Handle returned by start_usb_monitoring(). Mirrors the .stop()/.join()
    shape of watchdog's Observer (see behavior_monitor.py) so both
    monitors are used the same way.
    """

    def __init__(self, thread, stop_event):
        self._thread = thread
        self._stop_event = stop_event

    def stop(self):
        self._stop_event.set()

    def join(self):
        self._thread.join()


def start_usb_monitoring(on_drive_connected, poll_interval_seconds=2.0):
    """
    Start polling for newly-connected removable drives in the background.

    on_drive_connected: called with a mountpoint string (e.g. "E:\\") each
                         time a removable drive appears that wasn't there
                         on the previous check. Drives already plugged in
                         when monitoring starts do NOT trigger a call -
                         only ones that show up afterwards.
    poll_interval_seconds: how often to check for changes.

    Returns a UsbMonitor - call .stop() then .join() when you want the
    polling to end (e.g. when the app closes).
    """
    stop_event = threading.Event()

    def poll_loop():
        known_drives = list_removable_drives()
        while not stop_event.wait(poll_interval_seconds):
            current_drives = list_removable_drives()
            for drive in current_drives - known_drives:
                on_drive_connected(drive)
            known_drives = current_drives

    thread = threading.Thread(target=poll_loop, daemon=True)
    thread.start()
    return UsbMonitor(thread, stop_event)
