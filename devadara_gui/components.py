"""
components.py

DEVADARA's reusable widget primitives (see the design spec's "Component
Inventory" section) - built once here, used across every page so the app
reads as one consistent system rather than a pile of one-off screens.
"""

from datetime import datetime

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from devadara_gui import theme


def format_timestamp(iso_string):
    """
    Render a stored ISO timestamp ("2026-09-16T12:52:34", the format every
    backend module writes via datetime.isoformat()) as the ONE readable
    display format used everywhere in the GUI - "Sep 16, 2026, 12:52 PM".

    Display-only: the underlying stored value is untouched everywhere else
    (scan_log.py, activity_log.py, quarantine.py, ...) - this only changes
    how a timestamp string is shown once it reaches a page. Returns the
    input unchanged if it isn't a parseable ISO timestamp (e.g. "", "Never"),
    so a page never crashes over a missing/placeholder value.
    """
    if not iso_string:
        return iso_string
    try:
        dt = datetime.fromisoformat(iso_string)
    except ValueError:
        return iso_string
    # Avoid strftime's non-portable no-leading-zero flags (%-d/%#d differ
    # between Linux and Windows) - build the pieces that need no padding
    # directly instead.
    time_part = dt.strftime("%I:%M %p").lstrip("0") or "12:00 AM"
    return f"{dt.strftime('%b')} {dt.day}, {dt.year}, {time_part}"


# ---------------------------------------------------------------------
# Typography helpers - plain QLabels pre-wired to the right objectName so
# every screen gets identical type styling without repeating stylesheets.
# ---------------------------------------------------------------------
def make_label(text, object_name, wrap=False):
    label = QLabel(text)
    label.setObjectName(object_name)
    label.setWordWrap(wrap)
    return label


def page_title(text):
    return make_label(text, "pageTitle")


def page_subtitle(text):
    return make_label(text, "pageSubtitle", wrap=True)


def section_title(text):
    return make_label(text, "sectionTitle")


def body_text(text, wrap=False):
    return make_label(text, "bodyText", wrap=wrap)


def body_secondary(text, wrap=False):
    return make_label(text, "bodySecondary", wrap=wrap)


def metadata_text(text, disabled=False):
    return make_label(text, "metadataDisabled" if disabled else "metadataText")


def hairline():
    # QFrame.HLine paints its own native sunken/raised bevel using the
    # widget's palette (Light/Dark shades) UNDERNEATH whatever the QSS
    # background-color says - confirmed live via pixel sampling: with
    # HLine shape, the rendered line measured RGB(146,146,146), nowhere
    # near the intended #262626 border-default. NoFrame + a fixed 1px
    # height sidesteps native frame painting entirely, so the QSS
    # background-color in #hairline (theme.py) is the only thing drawn.
    line = QFrame()
    line.setObjectName("hairline")
    line.setFrameShape(QFrame.NoFrame)
    line.setFixedHeight(1)
    return line


# ---------------------------------------------------------------------
# Card - the base container used everywhere (dashboard hero, module rows,
# threat cards, tool cards, ...).
# ---------------------------------------------------------------------
class Card(QFrame):
    def __init__(self, object_name="card", padding=theme.CARD_PADDING, parent=None, glow=False,
                 glow_color=None, glow_blur=30):
        super().__init__(parent)
        self.setObjectName(object_name)
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(padding, padding, padding, padding)
        self.layout_.setSpacing(12)
        # Glow is opt-in (see theme.apply_glow's docstring) - only the
        # hero/primary/active cards get the soft emerald halo, never every
        # plain card, so a page full of cards doesn't turn into a wall of
        # glowing boxes and stays cheap to repaint. glow_color/glow_blur let
        # a call site match a specific reference box-shadow exactly (e.g.
        # the hero card's own rgba(40,200,120,0.15) at 30px) rather than
        # falling back to the generic accent.
        if glow:
            theme.apply_glow(self, glow_color or theme.HERO_GLOW, blur=glow_blur)

    def addWidget(self, widget):
        self.layout_.addWidget(widget)

    def addLayout(self, layout):
        self.layout_.addLayout(layout)


# ---------------------------------------------------------------------
# Status dot + StatusRow
# ---------------------------------------------------------------------
STATUS_ACTIVE = "active"      # green dot
STATUS_INACTIVE = "inactive"  # gray dot
STATUS_ATTENTION = "attention"  # white, slightly larger dot


class StatusDot(QLabel):
    def __init__(self, state=STATUS_INACTIVE, parent=None, size_override=None, pulse=False, glow=False):
        super().__init__(parent)
        self._pulse_anim = None
        # Glow is opt-in (default False) - a QGraphicsDropShadowEffect per
        # dot is cheap for the couple of marquee "is protection on" dots
        # (Dashboard hero, sidebar) but would add up across Process Scan's
        # 100+ table rows or a long Persistence Check list, so every other
        # StatusDot in the app stays glow-free unless it explicitly opts in.
        self._glow = glow
        self.set_state(state, size_override=size_override)
        # pulse is opt-in too, and (like glow) only meaningful for
        # STATUS_ACTIVE; since QWidget allows only one QGraphicsEffect at a
        # time, requesting both together lets the pulse's opacity effect
        # simply take over from the glow set in set_state() above - an
        # acceptable trade-off for the one dot that ever asks for pulse.
        if pulse and state == STATUS_ACTIVE:
            self._start_pulse()

    def set_state(self, state, size_override=None):
        size = size_override if size_override is not None else (10 if state == STATUS_ATTENTION else 8)
        # Active/attention dots get the glossy radial fill (white-green-
        # specular center fading to kelly-green) described in the new
        # visual language; a quiet/off dot stays a flat muted sage - no
        # gradient needed for something that isn't meant to catch the eye.
        fill = {
            STATUS_ACTIVE: theme.GRADIENT_STATUS_DOT_ACTIVE,
            STATUS_ATTENTION: theme.GRADIENT_STATUS_DOT_ATTENTION,
        }.get(state, theme.TEXT_SECONDARY)
        self.setFixedSize(size, size)
        self.setStyleSheet(
            f"background: {fill}; border-radius: {size // 2}px;"
        )
        if self._glow and state in (STATUS_ACTIVE, STATUS_ATTENTION):
            glow_color = theme.KELLY_GREEN if state == STATUS_ACTIVE else theme.TEXT_PRIMARY
            theme.apply_glow(self, glow_color, blur=max(12, size * 2), alpha=170)
        elif self._glow:
            theme.clear_glow(self)

    def _start_pulse(self):
        # A slow, gentle opacity breathe - not a flash/blink - to read as
        # "quietly alive" rather than an alert. Kept subtle per the app's
        # own no-excessive-animation rule: ~1.8s cycle, floor of 55%
        # opacity (never fully disappears), smooth sine easing.
        effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(1800)
        anim.setStartValue(1.0)
        anim.setKeyValueAt(0.5, 0.55)
        anim.setEndValue(1.0)
        anim.setLoopCount(-1)
        anim.setEasingCurve(QEasingCurve.InOutSine)
        anim.start()
        self._pulse_anim = anim  # keep a reference alive for the widget's lifetime


def status_row(label_text, state, value_text, compact=False):
    """
    One row: label (left) + dot & value (right). Returns a QWidget.

    compact: a smaller, quieter variant for a sub-item nested under a
    parent row (see Dashboard's Security Overview grouping) - smaller
    text/dot, tighter vertical margins, and no pulse animation (reserved
    for the one main "is protection on" dot, not every sub-module).
    """
    row = QWidget()
    row.setObjectName("transparentPanel")
    layout = QHBoxLayout(row)
    v_margin = 8 if compact else 11
    layout.setContentsMargins(0, v_margin, 0, v_margin)

    # Exact reference values: row label 12px / #F2FFF7 / normal weight
    # (the reference's row-label <span> carries no font-weight at all).
    label = body_text(label_text)
    font_size = 11 if compact else 12
    font_weight = 400 if compact else 500
    label.setStyleSheet(f"font-size: {font_size}px; font-weight: {font_weight}; color: {theme.ROW_LABEL_COLOR};")
    layout.addWidget(label)
    layout.addStretch()

    active = state == STATUS_ACTIVE
    dot = StatusDot(state, size_override=8 if compact else 10, pulse=(active and not compact))
    layout.addWidget(dot)

    # Exact reference value: "Active" status text is #7CFFB2 at 11px.
    value_color = theme.ROW_ACTIVE_VALUE_COLOR if active else theme.TEXT_SECONDARY
    value = make_label(value_text, "metadataText")
    value_font_size = 10 if compact else 11
    value.setStyleSheet(f"font-size: {value_font_size}px; font-weight: 600; color: {value_color};")
    layout.addWidget(value)
    return row


# ---------------------------------------------------------------------
# StatBlock - label-above-value columns, hairline divided
# ---------------------------------------------------------------------
def stat_block(items):
    """items: list of (label, value) tuples. Returns a QWidget row."""
    row = QWidget()
    row.setObjectName("statBlockRow")
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 6, 0, 6)
    layout.setSpacing(32)
    for label_text, value_text in items:
        col = QVBoxLayout()
        col.setSpacing(2)
        # Exact reference values: stat label 10px / #8FBFA3 / letter-
        # spacing 0.5px; stat value 12px / #F2FFF7.
        label = metadata_text(label_text)
        label.setStyleSheet(
            f"font-size: 10px; font-weight: 500; color: {theme.STAT_LABEL_COLOR}; letter-spacing: 0.5px;"
        )
        col.addWidget(label)
        value_label = body_text(value_text)
        value_label.setStyleSheet(f"font-size: 12px; font-weight: 500; color: {theme.STAT_VALUE_COLOR};")
        col.addWidget(value_label)
        wrap = QWidget()
        wrap.setObjectName("statBlockItem")
        wrap.setLayout(col)
        layout.addWidget(wrap)
    layout.addStretch()
    return row


def key_value_list(rows):
    """
    rows: list of (label, value, [gloss]) tuples -> hairline-divided list,
    used for stat blocks / detail panels (Section Title list primitive).
    """
    container = QWidget()
    container.setObjectName("transparentPanel")
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(0)
    for index, entry in enumerate(rows):
        label_text, value_text = entry[0], entry[1]
        gloss = entry[2] if len(entry) > 2 else None

        row_widget = QWidget()
        row_widget.setObjectName("transparentPanel")
        row_layout = QVBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 10, 0, 10)
        row_layout.setSpacing(4)

        row_layout.addWidget(metadata_text(label_text))
        value_label = body_text(value_text, wrap=True)
        row_layout.addWidget(value_label)

        if gloss:
            row_layout.addWidget(metadata_text(gloss, disabled=True))

        layout.addWidget(row_widget)
        if index < len(rows) - 1:
            layout.addWidget(hairline())
    return container


# ---------------------------------------------------------------------
# ToggleRow - module card with name / description / toggle / status
# ---------------------------------------------------------------------
class ToggleSwitch(QCheckBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("toggleSwitch")
        self.setCursor(Qt.PointingHandCursor)
        self.setText("")


class ModuleCard(Card):
    toggled = Signal(bool)

    def __init__(self, name, description, initial_state=True, show_status=True, parent=None):
        super().__init__(parent=parent)
        header = QHBoxLayout()
        header.addWidget(section_title(name))
        header.addStretch()
        self.switch = ToggleSwitch()
        self.switch.setChecked(initial_state)
        self.switch.toggled.connect(self._on_toggle)
        header.addWidget(self.switch)
        self.addLayout(header)

        self.addWidget(body_secondary(description, wrap=True))

        self.show_status = show_status
        if show_status:
            status_line = QHBoxLayout()
            self.dot = StatusDot(STATUS_ACTIVE if initial_state else STATUS_INACTIVE)
            status_line.addWidget(self.dot)
            self.status_label = metadata_text("Active" if initial_state else "Off")
            status_line.addWidget(self.status_label)
            status_line.addStretch()
            self.addLayout(status_line)

    def _on_toggle(self, checked):
        if self.show_status:
            self.dot.set_state(STATUS_ACTIVE if checked else STATUS_INACTIVE)
            self.status_label.setText("Active" if checked else "Off")
        self.toggled.emit(checked)

    def set_checked_silently(self, checked):
        self.switch.blockSignals(True)
        self.switch.setChecked(checked)
        self.switch.blockSignals(False)
        if self.show_status:
            self.dot.set_state(STATUS_ACTIVE if checked else STATUS_INACTIVE)
            self.status_label.setText("Active" if checked else "Off")


def toggle_row(label_text):
    """A single-line settings toggle row (no description). Returns (widget, switch)."""
    row = QWidget()
    row.setObjectName("transparentPanel")
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 10, 0, 10)
    layout.addWidget(body_text(label_text))
    layout.addStretch()
    switch = ToggleSwitch()
    layout.addWidget(switch)
    return row, switch


# ---------------------------------------------------------------------
# EmptyState - master pattern, Section 10
# ---------------------------------------------------------------------
class EmptyState(QWidget):
    action_triggered = Signal()

    def __init__(self, title, body, button_label=None, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.addStretch()

        inner = QVBoxLayout()
        inner.setSpacing(8)
        inner.setAlignment(Qt.AlignCenter)

        title_label = body_text(title)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet(f"font-size: 15px; font-weight: 600; color: {theme.TEXT_PRIMARY};")
        inner.addWidget(title_label)

        body_label = body_secondary(body, wrap=True)
        body_label.setAlignment(Qt.AlignCenter)
        body_label.setMaximumWidth(360)
        inner.addWidget(body_label, alignment=Qt.AlignHCenter)

        if button_label:
            inner.addSpacing(8)
            button = QPushButton(button_label)
            button.setObjectName("primaryButton")
            button.setCursor(Qt.PointingHandCursor)
            button.clicked.connect(self.action_triggered.emit)
            theme.apply_glow(button, theme.ACCENT_GREEN, blur=20, alpha=130)
            inner.addWidget(button, alignment=Qt.AlignHCenter)

        centered = QHBoxLayout()
        centered.addStretch()
        centered.addLayout(inner)
        centered.addStretch()
        outer.addLayout(centered)
        outer.addStretch()


# ---------------------------------------------------------------------
# ThreatCard - used for Detected Threats and Memory Scan findings
# ---------------------------------------------------------------------
class ThreatCard(Card):
    quarantine_clicked = Signal()
    delete_clicked = Signal()
    ignore_clicked = Signal()
    details_clicked = Signal()

    def __init__(self, file_name, file_path, timestamp_text, parent=None):
        # Own object name (still styled identically to #card in theme.py)
        # so it can carry a permanent glow - a small, bounded list of real
        # findings, unlike the large repeated rows this effect is kept off
        # of elsewhere.
        super().__init__(object_name="threatCard", glow=True, parent=parent)

        eyebrow = QHBoxLayout()
        eyebrow.setSpacing(6)
        eyebrow.addWidget(StatusDot(STATUS_ATTENTION))
        eyebrow.addWidget(metadata_text("Threat detected"))
        eyebrow.addStretch()
        self.addLayout(eyebrow)

        name_label = body_text(file_name)
        name_label.setStyleSheet(f"font-size: 14px; font-weight: 600; color: {theme.TEXT_PRIMARY};")
        self.addWidget(name_label)

        path_label = metadata_text(_elide_left(file_path, 70))
        path_label.setToolTip(file_path)
        self.addWidget(path_label)

        self.addWidget(metadata_text(f"Detected: {timestamp_text}"))

        actions = QHBoxLayout()
        actions.setSpacing(8)

        quarantine_btn = QPushButton("Quarantine")
        quarantine_btn.setObjectName("primaryButton")
        quarantine_btn.setCursor(Qt.PointingHandCursor)
        quarantine_btn.clicked.connect(self.quarantine_clicked.emit)
        theme.apply_glow(quarantine_btn, theme.ACCENT_GREEN, blur=18, alpha=130)
        actions.addWidget(quarantine_btn)

        delete_btn = QPushButton("Delete")
        delete_btn.setObjectName("secondaryButton")
        delete_btn.setCursor(Qt.PointingHandCursor)
        delete_btn.clicked.connect(self.delete_clicked.emit)
        actions.addWidget(delete_btn)

        ignore_btn = QPushButton("Ignore")
        ignore_btn.setObjectName("secondaryButton")
        ignore_btn.setCursor(Qt.PointingHandCursor)
        ignore_btn.clicked.connect(self.ignore_clicked.emit)
        actions.addWidget(ignore_btn)

        actions.addStretch()

        details_btn = QPushButton("View Details")
        details_btn.setObjectName("textButton")
        details_btn.setCursor(Qt.PointingHandCursor)
        details_btn.clicked.connect(self.details_clicked.emit)
        actions.addWidget(details_btn)

        self.addLayout(actions)


def _elide_left(text, max_len):
    if len(text) <= max_len:
        return text
    return "..." + text[-(max_len - 3):]


# ---------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------
def spacer_widget():
    w = QWidget()
    w.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
    return w
