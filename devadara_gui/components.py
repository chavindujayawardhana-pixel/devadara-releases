"""
components.py

Reusable widgets styled to match the reference mockup
(assets/deepseek_html_20260917_f4ed9f.html), built once here so later GUI
phases (Dashboard/Scan/Protection/Results/Settings content) reuse them
instead of duplicating styling inline.

  Card         - panel with corner-bracket decoration (.panel)
  Button       - primary/secondary variant button (.btn / .btn.primary)
  ToggleSwitch - animated on/off switch (.toggle / .toggle-slider)
  NavItem      - sidebar nav button, active-state highlight (.nav-item)
"""

from PySide6.QtCore import Property, QEasingCurve, QPropertyAnimation, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from devadara_gui import theme


class Card(QFrame):
    """A bordered panel with an optional title/badge header and neon
    corner brackets, matching the mockup's .panel."""

    def __init__(self, title="", badge="", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 16, 20, 20)
        outer.setSpacing(12)

        if title:
            header = QHBoxLayout()
            header.setSpacing(8)

            title_label = QLabel(title.upper())
            title_label.setObjectName("cardTitle")
            title_label.setFont(theme.letter_spaced_font(size=8, bold=True, spacing=2))
            header.addWidget(title_label)
            header.addStretch(1)

            if badge:
                badge_label = QLabel(badge)
                badge_label.setObjectName("cardBadge")
                badge_label.setFont(theme.letter_spaced_font(size=8, bold=True, spacing=1))
                header.addWidget(badge_label)

            outer.addLayout(header)

            divider = QFrame()
            divider.setObjectName("divider")
            divider.setFixedHeight(1)
            outer.addWidget(divider)

        self.content_layout = QVBoxLayout()
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(10)
        outer.addLayout(self.content_layout)

    def paintEvent(self, event):
        super().paintEvent(event)  # draws the QSS background/border first

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor(theme.NEON))
        pen.setWidthF(2)
        painter.setPen(pen)
        painter.setOpacity(0.7)

        size = 12
        w, h = self.width(), self.height()
        # top-left bracket (top + left edges only)
        painter.drawLine(0, 0, size, 0)
        painter.drawLine(0, 0, 0, size)
        # bottom-right bracket (bottom + right edges only)
        painter.drawLine(w - 1 - size, h - 1, w - 1, h - 1)
        painter.drawLine(w - 1, h - 1 - size, w - 1, h - 1)
        painter.end()


class Button(QPushButton):
    """A themed button. variant="primary" for the filled/glowing call-to-
    action style, "secondary" (default) for the outlined style."""

    def __init__(self, text="", variant="secondary", parent=None):
        super().__init__(text.upper(), parent)
        self.setObjectName("themedButton")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFont(theme.letter_spaced_font(size=10, bold=True, spacing=1.5))
        self._variant = None
        self.set_variant(variant)

    def set_variant(self, variant):
        self._variant = variant
        self.setProperty("variant", variant)
        self.style().unpolish(self)
        self.style().polish(self)
        self.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=20) if variant == "primary" else None)


class ToggleSwitch(QWidget):
    """An animated on/off switch matching the mockup's .toggle."""

    toggled = Signal(bool)

    def __init__(self, checked=False, parent=None):
        super().__init__(parent)
        self.setFixedSize(44, 24)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self._checked = checked
        self._knob_pos = 1.0 if checked else 0.0

        self._anim = QPropertyAnimation(self, b"knobPosition", self)
        self._anim.setDuration(150)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

        self._apply_glow()

    def isChecked(self):
        return self._checked

    def setChecked(self, checked, animate=True):
        checked = bool(checked)
        if checked == self._checked:
            return
        self._checked = checked
        self._apply_glow()

        self._anim.stop()
        self._anim.setStartValue(self._knob_pos)
        self._anim.setEndValue(1.0 if checked else 0.0)
        if animate:
            self._anim.start()
        else:
            self.setKnobPosition(1.0 if checked else 0.0)

        self.toggled.emit(checked)

    def _apply_glow(self):
        self.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=12) if self._checked else None)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.setChecked(not self._checked)
        super().mousePressEvent(event)

    def getKnobPosition(self):
        return self._knob_pos

    def setKnobPosition(self, pos):
        self._knob_pos = pos
        self.update()

    knobPosition = Property(float, getKnobPosition, setKnobPosition)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        track_rect = QRectF(self.rect().adjusted(0, 0, -1, -1))
        radius = track_rect.height() / 2

        if self._checked:
            painter.setBrush(QColor(0, 255, 170, 38))
            painter.setPen(QPen(QColor(theme.NEON), 1))
        else:
            painter.setBrush(QColor(0, 0, 0, 128))
            painter.setPen(QPen(QColor(theme.TEXT_MUTE), 1))
        painter.drawRoundedRect(track_rect, radius, radius)

        knob_diameter = 16
        margin = 3
        travel = track_rect.width() - knob_diameter - margin * 2
        knob_x = margin + travel * self._knob_pos
        knob_y = (track_rect.height() - knob_diameter) / 2

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(theme.NEON) if self._checked else QColor(theme.TEXT_MUTE))
        painter.drawEllipse(QRectF(knob_x, knob_y, knob_diameter, knob_diameter))
        painter.end()


class NavItem(QPushButton):
    """A sidebar nav button - checkable, icon + label, with the mockup's
    active-state highlight (border glow + a leading arrow).

    Icon and label are painted manually (not via QPushButton's native
    setText()) so both are driven by exactly one color variable. Native text
    drawing let one glyph slip through inconsistently: Windows' automatic
    font-fallback resolves the settings gear (U+2699) to a color-glyph font
    that ignores QPainter/QSS color entirely, while the other 4 icon glyphs
    happen to fall back to a monochrome font that does respect it. Explicitly
    requesting "Segoe UI Symbol" for the icon sidesteps that per-glyph
    fallback quirk for all 5 icons alike.
    """

    ICON_FONT_FAMILY = "Segoe UI Symbol"

    def __init__(self, icon, text, parent=None):
        super().__init__(parent)
        self.setObjectName("navItem")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setProperty("active", False)
        self.setMinimumHeight(38)
        self.setText("")  # painted manually below - see class docstring

        self._icon_char = icon
        self._label_text = text.upper()

        self._icon_font = QFont(self.ICON_FONT_FAMILY)
        self._icon_font.setPointSize(11)
        self._label_font = theme.letter_spaced_font(size=10, spacing=1)
        self._arrow_font = theme.letter_spaced_font(size=7)

        self.toggled.connect(self._on_toggled)

    def _on_toggled(self, checked):
        self.setProperty("active", checked)
        self.style().unpolish(self)
        self.style().polish(self)
        self.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=14) if checked else None)
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)  # background/border only - text() is empty

        active = bool(self.property("active"))
        color = QColor(theme.NEON) if (active or self.underMouse()) else QColor(theme.TEXT_DIM)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(color)

        if active:
            painter.setFont(self._arrow_font)
            painter.drawText(
                QRectF(2, 0, 14, self.height()),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                "▶",
            )

        painter.setFont(self._icon_font)
        painter.drawText(
            QRectF(14, 0, 22, self.height()),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            self._icon_char,
        )

        painter.setFont(self._label_font)
        painter.drawText(
            QRectF(40, 0, self.width() - 50, self.height()),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            self._label_text,
        )

        painter.end()
