"""
dialogs.py

The ONE confirmation helper every consequential GUI action goes through
(owner rule: no action on the Results page - or the behavior-alert popup -
may run without it, not even small reversible ones like Unhide or Open in
Explorer). confirm() shows a warning that says in plain words what will
happen and names the file(s) or program, and returns True only after an
explicit click on the action button:

  - Cancel is the default button: Enter cancels, Escape cancels, closing
    the window cancels.
  - typed_word="DELETE": the action button stays disabled until exactly
    that word is typed (Delete Permanently).
  - tick_label="...": the action button stays disabled until the box is
    ticked (bulk actions such as Unhide All).

Callers never act on their own: they call confirm() and only then do the
work. Tests replace dialogs.confirm to answer for the user, which is why
callers must always reach it as dialogs.confirm(...) (module attribute),
never via a from-import.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)

from devadara_gui import theme
from devadara_gui.components import Button

MAX_LISTED_ITEMS = 10
DIALOG_WIDTH = 600      # px - fixed, so wrapped text gets its real height
ITEM_LINE_WIDTH = 500   # px; longer paths are shortened in the middle


class ConfirmDialog(QDialog):
    def __init__(self, parent, title, message, action_label, items=(), details="",
                 typed_word=None, tick_label=None):
        super().__init__(parent)
        self.setObjectName("confirmDialog")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedWidth(DIALOG_WIDTH)
        self._typed_word = typed_word

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(10)

        heading = QLabel(f"⚠  {title}")
        heading.setObjectName("confirmHeading")
        heading.setFont(theme.letter_spaced_font(size=10, black=True, spacing=1))
        heading.setWordWrap(True)
        layout.addWidget(heading)

        body = QLabel(message)
        body.setWordWrap(True)
        body.setFont(theme.letter_spaced_font(size=9, spacing=0.3))
        layout.addWidget(body)

        items = [str(i) for i in items]
        if items:
            shown = items[:MAX_LISTED_ITEMS]
            if len(items) > MAX_LISTED_ITEMS:
                shown.append(f"… and {len(items) - MAX_LISTED_ITEMS} more")
            listing = QLabel()
            listing.setObjectName("confirmItems")
            listing.setFont(theme.letter_spaced_font(size=8, spacing=0.2))
            metrics = QFontMetrics(listing.font())
            # One line per item (a path never wraps mid-way); the full
            # list is in the tooltip.
            listing.setText("\n".join(
                metrics.elidedText(line, Qt.TextElideMode.ElideMiddle, ITEM_LINE_WIDTH) for line in shown))
            listing.setToolTip("\n".join(items))
            listing.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(listing)

        if details:
            extra = QLabel(details)
            extra.setObjectName("confirmDetails")
            extra.setWordWrap(True)
            extra.setFont(theme.letter_spaced_font(size=8, spacing=0.2))
            layout.addWidget(extra)

        self.tick_box = None
        if tick_label:
            self.tick_box = QCheckBox(tick_label)
            self.tick_box.toggled.connect(self._update_enabled)
            layout.addWidget(self.tick_box)

        self.typed_edit = None
        if typed_word:
            prompt = QLabel(f"Type {typed_word} to confirm:")
            prompt.setFont(theme.letter_spaced_font(size=8, bold=True, spacing=1))
            layout.addWidget(prompt)
            self.typed_edit = QLineEdit()
            self.typed_edit.setObjectName("confirmTyped")
            self.typed_edit.textChanged.connect(self._update_enabled)
            layout.addWidget(self.typed_edit)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.cancel_button = Button("Cancel")
        self.action_button = Button(action_label.replace("&", "&&"))
        # Cancel is the default: Enter (and Escape, QDialog's own reject)
        # never runs the action - only a click on the action button does.
        self.action_button.setAutoDefault(False)
        self.action_button.setDefault(False)
        self.cancel_button.setAutoDefault(True)
        self.cancel_button.setDefault(True)
        self.cancel_button.clicked.connect(self.reject)
        self.action_button.clicked.connect(self.accept)
        buttons.addWidget(self.cancel_button)
        buttons.addWidget(self.action_button)
        layout.addLayout(buttons)

        self._update_enabled()
        self.cancel_button.setFocus()

    def _update_enabled(self, *_):
        ok = True
        if self.tick_box is not None:
            ok = ok and self.tick_box.isChecked()
        if self.typed_edit is not None:
            ok = ok and self.typed_edit.text() == self._typed_word
        self.action_button.setEnabled(ok)

    def center_on_screen(self):
        anchor = self.parentWidget()
        screen = (anchor.screen() if anchor is not None else None) or QApplication.primaryScreen()
        if screen is None:
            return
        geo = screen.availableGeometry()
        # Height for the fixed width - adjustSize() alone undersizes
        # word-wrapped labels and cuts the last lines off.
        layout = self.layout()
        layout.activate()
        height = (layout.totalHeightForWidth(DIALOG_WIDTH) if layout.hasHeightForWidth()
                  else self.sizeHint().height())
        self.resize(DIALOG_WIDTH, max(height, self.sizeHint().height()))
        self.move(geo.center().x() - self.width() // 2, geo.center().y() - self.height() // 2)


def build_confirm_dialog(parent, title, message, action_label, items=(), details="",
                         typed_word=None, tick_label=None):
    """The dialog confirm() runs - returned unexecuted for tests/previews."""
    dialog = ConfirmDialog(parent, title, message, action_label, items=items, details=details,
                           typed_word=typed_word, tick_label=tick_label)
    dialog.center_on_screen()
    return dialog


def confirm(parent, title, message, action_label, items=(), details="",
            typed_word=None, tick_label=None):
    """Show the warning; True only if the user clicked the action button."""
    dialog = build_confirm_dialog(parent, title, message, action_label, items=items,
                                  details=details, typed_word=typed_word, tick_label=tick_label)
    return dialog.exec() == QDialog.DialogCode.Accepted


# ─── shared wording for process actions (behavior popup + Results page) ───

PROCESS_ACTION_TEXT = {
    "suspend": ("Suspend", "This freezes the program. Nothing is lost, and Resume undoes it."),
    "resume": ("Resume", "This lets the suspended program continue running."),
    "kill": ("Kill", "This ends the program immediately. Any unsaved work in it is lost. "
                     "This cannot be undone."),
}


def confirm_process_action(parent, action, suspect):
    verb, consequence = PROCESS_ACTION_TEXT[action]
    name = suspect.get("name") or "unknown program"
    return confirm(
        parent,
        title=f"{verb} {name}?",
        message=consequence,
        action_label=verb,
        items=[f"Program:  {name}", f"PID:  {suspect['pid']}",
               f"Path:  {suspect.get('exe') or 'unknown'}"],
    )
