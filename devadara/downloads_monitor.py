"""
downloads_monitor.py

This is DEVADARA's "mouth" layer - it watches the folder where things
arrive from OUTSIDE the machine over the network (almost everything a
browser saves lands in Downloads first), the way your body pays close
attention to anything you actually swallow. Unlike behavior_monitor.py
(which watches for a PATTERN of activity over time), this one reacts to
each new file individually, the instant it finishes arriving.

How it works:
1. `watchdog` notifies us whenever a file is created or renamed inside the
   folder we're watching.
2. Browsers don't write the final file directly - they write to a
   temporary name (Chrome/Edge: "thing.crdownload", Firefox: "thing.part")
   while downloading, then rename it to the real name once the download
   completes. We ignore the temporary name entirely and only react to the
   rename INTO a final-looking name - that's the moment a download is
   actually done. A file that instead appears already at its final name in
   one shot (e.g. a direct save, or a small file some tools write without
   a temp step) is caught too, via plain creation.
3. A file can still be mid-write for a brief moment right after it shows
   up. Before scanning, we wait until its size stops changing across a few
   checks, so we scan the finished file rather than a half-written one.
4. Once a file looks finished and stable, we hand its path to your
   on_new_file callback. This module never scans, deletes, or touches
   file content itself - it only tells you "this file just finished
   arriving."
"""

import os
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Extensions browsers/download tools use for a download that isn't
# finished yet. A file with one of these is deliberately ignored - it's
# not real content yet, just a placeholder that will be renamed or
# deleted once the download finishes (or is cancelled).
IN_PROGRESS_EXTENSIONS = {".crdownload", ".part", ".partial", ".tmp", ".download"}


def _looks_finished(file_path):
    return os.path.splitext(file_path)[1].lower() not in IN_PROGRESS_EXTENSIONS


def _wait_until_file_is_stable(file_path, required_stable_checks=3, interval_seconds=0.5, max_checks=20):
    """
    Poll the file's size until it stops changing for required_stable_checks
    checks in a row, or we give up after max_checks (better to scan a file
    that's still technically growing than to wait forever and never scan
    it at all).

    Returns False if the file disappears while we're waiting (e.g. a
    cancelled download cleaning up after itself) - there's nothing to scan
    in that case.
    """
    last_size = -1
    stable_count = 0

    for _ in range(max_checks):
        try:
            size = os.path.getsize(file_path)
        except OSError:
            return False

        if size == last_size:
            stable_count += 1
            if stable_count >= required_stable_checks:
                return True
        else:
            stable_count = 0
            last_size = size

        time.sleep(interval_seconds)

    return os.path.exists(file_path)


class NewDownloadHandler(FileSystemEventHandler):
    """
    Watches one folder and calls on_new_file(path) for every file that
    finishes arriving in it (see module docstring for what "finishes"
    means).
    """

    def __init__(self, on_new_file):
        self.on_new_file = on_new_file

    def _handle_candidate(self, file_path):
        if not _looks_finished(file_path):
            return  # still a browser's in-progress placeholder, ignore it

        if not _wait_until_file_is_stable(file_path):
            return  # vanished while we waited (e.g. a cancelled download)

        self.on_new_file(file_path)

    def on_created(self, event):
        if not event.is_directory:
            self._handle_candidate(event.src_path)

    def on_moved(self, event):
        # This is how a completed browser download actually shows up:
        # "thing.crdownload" -> "thing.pdf".
        if not event.is_directory:
            self._handle_candidate(event.dest_path)


def start_monitoring_downloads(folder_path, on_new_file):
    """
    Start watching folder_path (and all subfolders) in the background.

    Returns the watchdog Observer object - call .stop() then .join() on it
    when you want monitoring to end (e.g. when the app closes).
    """
    handler = NewDownloadHandler(on_new_file)
    observer = Observer()
    observer.schedule(handler, folder_path, recursive=True)
    observer.start()
    return observer
