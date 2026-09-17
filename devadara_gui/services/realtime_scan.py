"""
realtime_scan.py

RealtimeScanController - the small GUI-thread orchestrator sitting between
AppState's downloads/USB watcher callbacks (which fire on background
threads and can never touch Qt widgets directly) and the ONE shared
devadara_gui.realtime_scan_popup.RealTimeScanPopup instance. See that
module's docstring for why there is exactly one popup class, used by both
trigger sources.

This file is GUI orchestration only, exactly the same separation the rest
of devadara_gui keeps: it starts/cancels a StoppableWorker around the job
callables AppState already builds (the real scan_engine.evaluate_file /
drive_scanner.walk_and_scan pipelines, completely unmodified), and drives
the popup's public API. No detection logic lives here.

Queueing: only one real-time scan is ever active (one StoppableWorker) and
one popup is ever visible at a time - see _maybe_advance() for exactly
when the next queued request is allowed to start. A threat result must
stay on screen until the user acts on it (OK/Review) - it is NOT enough to
advance the queue just because the background worker finished; the queue
only advances once the popup itself has actually been dismissed (or, if
the user dismissed it early while the scan was still running, once that
now-unwatched worker also finishes).
"""

from dataclasses import dataclass
from typing import Callable, Optional

from PySide6.QtCore import QObject

from devadara_gui.services.workers import StoppableWorker


@dataclass
class RealtimeScanRequest:
    kind: str                      # "downloads" | "usb" - informational only
    target_label: str              # what the popup shows as "Scanning: ..."
    job: Callable                  # (should_stop, report_progress) -> result
    on_result: Callable            # (result) -> {"is_threat", "cancelled", ...}
    review_target: Optional[str] = None  # file_path AppState can look up on Review


class RealtimeScanController(QObject):
    def __init__(self, app_state, popup, on_review=None, parent=None):
        super().__init__(parent)
        self.app_state = app_state
        self.popup = popup
        self._on_review = on_review

        self._queue = []
        self._worker = None
        self._active_request = None
        self._popup_dismissed_early = False

        app_state.realtime_scan_requested.connect(self._on_scan_requested)
        popup.ok_clicked.connect(self._on_ok_clicked)
        popup.stop_clicked.connect(self._on_stop_clicked)
        popup.review_clicked.connect(self._on_review_clicked)
        popup.dismissed.connect(self._on_popup_dismissed)

    # ------------------------------------------------------------------
    def _on_scan_requested(self, request):
        if self._worker is not None:
            self._queue.append(request)
            return
        self._start(request)

    def _start(self, request):
        self._active_request = request
        self._popup_dismissed_early = False
        self.popup.start_scan(request.target_label)

        self._worker = StoppableWorker(request.job)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished_ok.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_progress(self, info):
        if self._popup_dismissed_early:
            return
        if isinstance(info, dict):
            percent = info.get("percent", 0)
            detail = info.get("detail")
        else:
            percent, detail = info, None
        self.popup.update_progress(percent, detail)

    def _on_finished(self, result):
        request = self._active_request
        self._worker = None
        outcome = request.on_result(result)

        if not self._popup_dismissed_early:
            if outcome.get("cancelled"):
                self.popup.show_cancelled()
            elif outcome.get("is_threat"):
                self.popup.show_threat_result()
            else:
                self.popup.show_clean_result()
            # self._active_request stays set (NOT cleared here) - a threat
            # result can sit on screen for a long time waiting for the user,
            # and _on_review_clicked() needs request.review_target to still
            # be there whenever that click actually happens. It's only ever
            # read (by _on_review_clicked) or overwritten (by the next
            # _start()), so leaving it set here is safe.
        else:
            self._active_request = None

        self._maybe_advance()

    def _on_failed(self, _error):
        self._worker = None
        if not self._popup_dismissed_early:
            self.popup.show_error()
        self._active_request = None
        self._maybe_advance()

    def _maybe_advance(self):
        if self._worker is not None:
            return  # a scan is still actively running (popup may have been dismissed early) - wait for it
        if self.popup.isVisible():
            return  # popup still showing a result the user hasn't acted on yet (e.g. a threat)
        if self._queue:
            self._start(self._queue.pop(0))

    # ------------------------------------------------------------------
    def _on_ok_clicked(self):
        # The popup dismisses its own UI immediately on OK. If a scan is
        # still running underneath, remember not to re-surface its result -
        # the underlying scan keeps running and still gets logged normally,
        # the user just opted out of watching this one notification.
        if self._worker is not None:
            self._popup_dismissed_early = True

    def _on_stop_clicked(self):
        if self._worker is not None:
            self._worker.request_stop()

    def _on_review_clicked(self):
        request = self._active_request
        if request is not None and self._on_review is not None:
            self._on_review(request.review_target)

    def _on_popup_dismissed(self):
        self._maybe_advance()
