"""
behavior_alert_popup.py

The popup for a behavior-monitor alert: a ransomware-like burst of file
changes in Downloads (devadara.behavior_monitor, via
AutoScanController.behavior_alert). Same floating, frameless, always-on-top
panel style as the Mini-Form scan popup, but centred on screen and never
auto-closing - it waits for the user.

Wording is deliberately "possible", never "detected": a burst can just as
well be unzipping an archive or a browser saving many files, and the
suspected-programs list is only "which programs had files open in that
folder" (best-effort - often empty on a busy PC, see behavior_monitor.py).

Each suspected program gets Suspend / Resume / Kill. Every one of them
goes through dialogs.confirm_process_action() first (Cancel is the default, Enter
and Escape both cancel) and then process_guard.ProcessGuard.perform(),
which refuses Windows' own processes, DEVADARA itself, unverifiable
programs, and recycled PIDs. Nothing here ever acts on its own.
"""

import os

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from devadara_gui import dialogs, theme
from devadara_gui.components import Button, Card
from devadara_gui.process_guard import ProcessGuard, refusal_reason

MAX_SAMPLE_FILES = 5

def _center_on_screen(widget, anchor=None):
    screen = ((anchor.screen() if anchor is not None else None)
              or QApplication.primaryScreen())
    if screen is None:
        return
    geo = screen.availableGeometry()
    widget.adjustSize()
    widget.move(geo.center().x() - widget.width() // 2,
                geo.center().y() - widget.height() // 2)


class _SuspectRow(QWidget):
    """One suspected program: name + PID, a status/reason line, and the
    three action buttons."""

    def __init__(self, suspect, popup, parent=None):
        super().__init__(parent)
        self.suspect = suspect
        self._popup = popup

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(3)

        top = QHBoxLayout()
        top.setSpacing(6)
        name = QLabel(f"{suspect.get('name') or 'unknown'}  (PID {suspect['pid']})")
        name.setFont(theme.letter_spaced_font(size=8, bold=True, spacing=0.3))
        name.setStyleSheet(f"color: {theme.TEXT};")
        top.addWidget(name, 1)

        self.buttons = {}
        for action in ("suspend", "resume", "kill"):
            button = Button(dialogs.PROCESS_ACTION_TEXT[action][0])
            button.clicked.connect(lambda _=False, a=action: self._popup._on_action(a, self))
            top.addWidget(button)
            self.buttons[action] = button
        layout.addLayout(top)

        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setFont(theme.letter_spaced_font(size=7, spacing=0.2))
        layout.addWidget(self.status)

        self.refusal = refusal_reason(suspect)
        self.refresh()

    def refresh(self, message=None):
        guard = self._popup.guard
        if self.refusal is not None:
            for button in self.buttons.values():
                button.setEnabled(False)
            self._set_status(f"// actions disabled — {self.refusal}", theme.TEXT_MUTE)
            return
        suspended = guard.is_suspended(self.suspect)
        killed = message == "Killed"
        self.buttons["suspend"].setEnabled(not suspended and not killed)
        self.buttons["resume"].setEnabled(suspended and not killed)
        self.buttons["kill"].setEnabled(not killed)
        if message is not None:
            color = theme.TEXT_DIM if message in ("Suspended", "Resumed", "Killed") else theme.WARN
            self._set_status(f"// {message}", color)
        else:
            self._set_status(f"// {self.suspect.get('exe') or ''}", theme.TEXT_DIM)

    def _set_status(self, text, color):
        self.status.setText(text)
        self.status.setStyleSheet(f"color: {color};")


class BehaviorAlertPopup(QWidget):
    _WIDTH = 520

    def __init__(self, guard=None, confirm=None, parent=None):
        """guard: the app-lifetime ProcessGuard (remembers what we
        suspended). confirm: callable(parent, action, suspect) -> bool -
        injectable for tests; defaults to dialogs.confirm_process_action."""
        super().__init__(parent)
        self.guard = guard or ProcessGuard()
        self._confirm = confirm  # None = the shared dialogs.confirm_process_action
        self._rows = []

        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        card = Card(title="")
        card.setObjectName("miniWindowPanel")
        card.setFixedWidth(self._WIDTH)
        card.layout().setContentsMargins(14, 12, 14, 14)
        outer.addWidget(card)

        content = card.content_layout
        content.setSpacing(6)

        title = QLabel("⚠  POSSIBLE RANSOMWARE-LIKE ACTIVITY")
        title.setFont(theme.letter_spaced_font(size=9, black=True, spacing=1))
        title.setStyleSheet(f"color: {theme.WARN};")
        content.addWidget(title)

        divider = QFrame()
        divider.setObjectName("miniHeaderDivider")
        divider.setFixedHeight(1)
        divider.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        content.addWidget(divider)

        self._folder = self._text_label(content, theme.CYAN)
        self._rate = self._text_label(content, theme.TEXT)
        self._samples = self._text_label(content, theme.TEXT_DIM)

        section = QLabel("// SUSPECTED PROGRAMS")
        section.setFont(theme.letter_spaced_font(size=7, bold=True, spacing=2))
        section.setStyleSheet(f"color: {theme.TEXT_DIM};")
        content.addWidget(section)

        self._rows_layout = QVBoxLayout()
        self._rows_layout.setSpacing(0)
        content.addLayout(self._rows_layout)

        note = QLabel("These are programs that had files open in this folder — not proof "
                      "that any of them is the cause. Nothing is done unless you choose it.")
        note.setWordWrap(True)
        note.setFont(theme.letter_spaced_font(size=7, spacing=0.2))
        note.setStyleSheet(f"color: {theme.TEXT_DIM};")
        content.addWidget(note)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self._dismiss = Button("Dismiss")
        self._dismiss.clicked.connect(self._on_dismiss)
        buttons.addWidget(self._dismiss)
        content.addLayout(buttons)

    @staticmethod
    def _text_label(layout, color):
        label = QLabel()
        label.setWordWrap(True)
        label.setFont(theme.letter_spaced_font(size=8, spacing=0.2))
        label.setStyleSheet(f"color: {color};")
        layout.addWidget(label)
        return label

    def show_alert(self, alert):
        """Fill in (or replace, for a newer alert) and show centred."""
        self._folder.setText(f"Folder:  {alert['folder']}")
        self._rate.setText(f"{alert['event_count']} file changes in {alert['window_seconds']} s")
        samples = [os.path.basename(p) for p in alert.get("sample_files", [])][-MAX_SAMPLE_FILES:]
        self._samples.setText("Recent files:  " + (",  ".join(samples) if samples else "—"))

        for row in self._rows:
            self._rows_layout.removeWidget(row)
            row.hide()  # deleteLater() alone leaves it painted until the next event-loop pass
            row.deleteLater()
        self._rows = []
        suspects = alert.get("suspect_processes") or []
        if not suspects:
            empty = QLabel("No program could be identified.")
            empty.setFont(theme.letter_spaced_font(size=8, spacing=0.2))
            empty.setStyleSheet(f"color: {theme.TEXT_DIM};")
            self._rows_layout.addWidget(empty)
            self._rows.append(empty)
        for suspect in suspects:
            row = _SuspectRow(suspect, self)
            self._rows_layout.addWidget(row)
            self._rows.append(row)

        _center_on_screen(self, self.parentWidget())
        self.show()
        self.raise_()
        self.activateWindow()
        # When a newer alert swaps the rows, the first adjustSize() can still
        # see a stale (minimum) height and squash the buttons - fit again once
        # the swap's pending layout events have been processed.
        QTimer.singleShot(0, lambda: _center_on_screen(self, self.parentWidget()))

    def _suspect_rows(self):
        return [r for r in self._rows if isinstance(r, _SuspectRow)]

    def _on_action(self, action, row):
        confirm = self._confirm or dialogs.confirm_process_action
        if not confirm(self, action, row.suspect):
            return  # cancelled - nothing happens
        _ok, message = self.guard.perform(action, row.suspect)
        row.refresh(message)

    def _on_dismiss(self):
        suspects = [r.suspect for r in self._suspect_rows()]
        if self.guard.any_suspended(suspects):
            box = QMessageBox(self)
            box.setWindowTitle("A program is still suspended")
            box.setText("A program you suspended is still frozen. If you close this, it stays "
                        "frozen until you resume or end it (for example in Task Manager).")
            keep = box.addButton("Keep Open", QMessageBox.ButtonRole.RejectRole)
            box.addButton("Close Anyway", QMessageBox.ButtonRole.AcceptRole)
            box.setDefaultButton(keep)
            box.setEscapeButton(keep)
            box.exec()
            if box.clickedButton() is keep:
                return
        self.hide()
