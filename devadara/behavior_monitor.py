"""
behavior_monitor.py

This is DEVADARA's "inflammatory response" layer - it doesn't look at
individual files at all, it watches for a suspicious PATTERN of activity
over time, the way your body notices "something is attacking many cells
at once" even before it identifies the exact germ.

Ransomware's telltale sign is speed and volume: it reads, encrypts, and
renames a large number of files in a very short time. One file changing is
normal. Twenty files changing in two seconds is not.

How it works:
1. `watchdog` notifies us every time a file is created, modified, renamed,
   or deleted inside a folder we're watching.
2. We keep a rolling window of "how many of these events happened in the
   last N seconds?" If that count crosses a threshold, we treat it as
   ransomware-like behavior.
3. When that happens, we ask `psutil` which currently-running processes
   have files open inside that folder, as a best-effort guess at "who did
   this." This is a HEURISTIC, not a certainty - see the notes below.
4. We report the alert (and suspects) via a callback function you provide.
   This module NEVER kills a process automatically - see kill_process(),
   which only runs when something else (a human, via the CLI or GUI)
   explicitly calls it.

Honest limitation: matching "which process touched this file" via psutil's
open_files() only catches processes that still have the file open at the
exact moment we check. A process that already closed the file and moved on
may be missed. Some system processes may also require the app to run "as
Administrator" to be inspectable at all. Treat suspect processes as leads
to investigate, not proven verdicts - which is exactly why killing one
always requires your explicit confirmation.
"""

import multiprocessing
import os
import threading
import time
from collections import deque

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class RansomwareLikeActivityHandler(FileSystemEventHandler):
    """
    Watches file system events in one folder and raises an alert when the
    rate of activity looks ransomware-like (many changes, very fast).
    """

    def __init__(
        self,
        folder_path,
        on_alert,
        event_threshold=20,
        window_seconds=5,
        cooldown_seconds=15,
    ):
        """
        folder_path: the folder being watched (used later to find suspect
                     processes that have files open inside it)
        on_alert: a function we call with an "alert_info" dictionary when
                  suspicious activity is detected
        event_threshold: how many file events within window_seconds counts
                          as suspicious (default: 20 events in 5 seconds)
        window_seconds: the size of the rolling time window we check
        cooldown_seconds: after raising an alert, wait this long before
                           raising another one for the same burst of
                           activity, so you don't get spammed with repeats
        """
        self.folder_path = folder_path
        self.on_alert = on_alert
        self.event_threshold = event_threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

        self.event_timestamps = deque()  # when recent events happened
        self.recent_files = deque(maxlen=15)  # sample of affected file paths
        self.last_alert_time = 0.0

    def _record_event(self, file_path):
        now = time.time()
        self.event_timestamps.append(now)
        self.recent_files.append(file_path)

        # Drop timestamps that have fallen outside our rolling window.
        while self.event_timestamps and self.event_timestamps[0] < now - self.window_seconds:
            self.event_timestamps.popleft()

        if len(self.event_timestamps) >= self.event_threshold:
            if now - self.last_alert_time >= self.cooldown_seconds:
                self.last_alert_time = now
                self._trigger_alert()

    def _trigger_alert(self):
        suspect_processes = find_processes_with_open_files_in_folder(self.folder_path)

        alert_info = {
            "folder": self.folder_path,
            "event_count": len(self.event_timestamps),
            "window_seconds": self.window_seconds,
            "sample_files": list(self.recent_files),
            "suspect_processes": suspect_processes,
        }
        self.on_alert(alert_info)

    # watchdog calls these automatically as file events happen.
    def on_created(self, event):
        if not event.is_directory:
            self._record_event(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._record_event(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._record_event(event.src_path)

    def on_moved(self, event):
        # Renaming a file (e.g. "photo.jpg" -> "photo.jpg.locked") fires this.
        if not event.is_directory:
            self._record_event(event.dest_path)


def _scan_open_files_in_folder(folder_path, internal_timeout_seconds, result_queue):
    """
    The actual scan, run inside its own OS process (see
    find_processes_with_open_files_in_folder for why). Still fans out one
    thread per process for a speed-up on the common case where most calls
    return quickly - that just no longer needs to be bulletproof on its
    own, since the parent process is the real safety net now.
    """
    normalized_folder = os.path.normcase(os.path.abspath(folder_path))
    suspects = []
    suspects_lock = threading.Lock()

    def check_process(proc):
        try:
            for open_file in proc.open_files():
                if os.path.normcase(open_file.path).startswith(normalized_folder):
                    with suspects_lock:
                        suspects.append({"pid": proc.pid, "name": proc.info.get("name")})
                    return
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return

    threads = []
    for proc in psutil.process_iter(["pid", "name"]):
        t = threading.Thread(target=check_process, args=(proc,), daemon=True)
        t.start()
        threads.append(t)

    deadline = time.time() + internal_timeout_seconds
    for t in threads:
        remaining = max(0.0, deadline - time.time())
        t.join(timeout=remaining)

    result_queue.put(suspects)


def find_processes_with_open_files_in_folder(folder_path, overall_timeout_seconds=2.0):
    """
    Best-effort check: which running processes currently have a file open
    inside folder_path? Returns a list of {"pid": ..., "name": ...}.

    IMPORTANT Windows quirk discovered while testing this: psutil's
    proc.open_files() can hang indefinitely on certain processes/handles -
    this is a known OS-level issue, not something we can simply catch with
    try/except. Worse, measured on real Windows machines: that hang can
    hold the Python GIL for its whole duration (the underlying call
    apparently doesn't release it), which means a THREAD timeout is not
    reliable - the main thread can't even check the clock until the GIL is
    free again, so a stuck thread can silently make every other "timed"
    thread wait right alongside it. The only thing that reliably cuts off
    a stuck call no matter what it's doing is killing the whole OS process
    it's running in.

    So the scan itself runs in a separate child process (_scan_open_files_
    in_folder). We give that child a hard wall-clock budget and simply
    terminate it if it's not done in time - a killed process can't corrupt
    shared state or leave anything running, unlike a killed thread. If we
    have to kill it, we return no suspects for this alert; we'd rather
    miss an occasional suspect than ever freeze the monitor.
    """
    ctx = multiprocessing.get_context("spawn")
    result_queue = ctx.Queue()
    worker = ctx.Process(
        target=_scan_open_files_in_folder,
        args=(folder_path, overall_timeout_seconds, result_queue),
        daemon=True,
    )
    worker.start()
    worker.join(timeout=overall_timeout_seconds)

    if worker.is_alive():
        worker.terminate()
        worker.join()
        print("[WARNING] Process scan took too long and was aborted.")
        return []

    try:
        return result_queue.get_nowait()
    except Exception:
        return []


def start_monitoring(folder_path, on_alert, event_threshold=20, window_seconds=5, cooldown_seconds=15):
    """
    Start watching folder_path (and all subfolders) in the background.

    Returns the watchdog Observer object - call .stop() then .join() on it
    when you want monitoring to end (e.g. when the app closes).
    """
    handler = RansomwareLikeActivityHandler(
        folder_path, on_alert, event_threshold, window_seconds, cooldown_seconds
    )
    observer = Observer()
    observer.schedule(handler, folder_path, recursive=True)
    observer.start()
    return observer


def kill_process(pid):
    """
    Terminate a process by its process ID (PID).

    This function is intentionally "dumb" - it does not decide whether a
    process SHOULD be killed. That decision must always be made by a human
    (via the CLI prompt or GUI confirmation dialog) before this is called.

    Returns True if the process was killed, False if it had already exited
    or couldn't be killed (e.g. a protected system process).
    """
    try:
        process = psutil.Process(pid)
        process.kill()
        return True
    except psutil.NoSuchProcess:
        print(f"[INFO] Process {pid} had already exited.")
        return False
    except psutil.AccessDenied:
        print(f"[ERROR] Not allowed to kill process {pid} (try running as Administrator).")
        return False


def suspend_process(pid):
    """
    Pause a process by its PID without killing it (all of its threads are
    frozen in place; nothing is lost, it just stops running).

    This exists as a safer middle ground than an immediate kill: suspending
    buys time to review a suspect process (in Task Manager, or however you
    investigate) before committing to kill it or letting it resume. Like
    kill_process(), this function is intentionally "dumb" - it does not
    decide whether a process SHOULD be suspended, a human does.

    Returns True if the process was suspended, False if it had already
    exited or couldn't be suspended (e.g. a protected system process).
    """
    try:
        process = psutil.Process(pid)
        process.suspend()
        return True
    except psutil.NoSuchProcess:
        print(f"[INFO] Process {pid} had already exited.")
        return False
    except psutil.AccessDenied:
        print(f"[ERROR] Not allowed to suspend process {pid} (try running as Administrator).")
        return False


def resume_process(pid):
    """
    Resume a process that was previously paused with suspend_process().

    Returns True if the process was resumed, False if it had already
    exited or couldn't be resumed.
    """
    try:
        process = psutil.Process(pid)
        process.resume()
        return True
    except psutil.NoSuchProcess:
        print(f"[INFO] Process {pid} had already exited.")
        return False
    except psutil.AccessDenied:
        print(f"[ERROR] Not allowed to resume process {pid} (try running as Administrator).")
        return False
