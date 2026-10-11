"""
components.py

Reusable widgets styled to match the reference mockup
(assets/deepseek_html_20260917_f4ed9f.html), built once here so later GUI
phases (Dashboard/Scan/Protection/Results/Settings content) reuse them
instead of duplicating styling inline.

  Card          - panel with corner-bracket decoration (.panel)
  Button        - primary/secondary variant button (.btn / .btn.primary)
  ToggleSwitch  - animated on/off switch (.toggle / .toggle-slider)
  NavItem       - sidebar nav button, active-state highlight (.nav-item)
  PageHeader    - accent-bar + title + subtitle block (.page-header)
  HeroStatusCard- big status banner (.hero)
  StatCard      - label + value stat tile (.stat-card)
  ActionCard    - clickable icon+title+desc card (.action-card)
  RadioItem     - exclusive-group pill radio button (.radio-item)
  TreeCheckbox  - small custom checkbox, click-only (.tree-item input)
  TreeRow       - one checkbox-tree row, group or child (.tree-item)
  StatusCircle  - large outline circle with a drawn check/exclamation mark
  ModuleToggleCard - a Card with a title, description, and a ToggleSwitch,
                     used by the Protection page's auto-scan toggles
  ScanOrbitLogo - the app logo whose orbit ring rotates while a scan runs
                  (sidebar header; orbit_frame() is shared with the tray)
"""

import html

from PySide6.QtCore import (Property, QEasingCurve, QElapsedTimer, QPointF, QPropertyAnimation,
                            QRectF, Qt, QTimer, Signal)
from PySide6.QtGui import QColor, QFont, QFontMetrics, QImage, QPainter, QPen
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QVBoxLayout, QWidget

from devadara_gui import protection_modules, theme


class Card(QFrame):
    """A bordered panel with an optional title/badge header and neon
    corner brackets, matching the mockup's .panel.

    accent: the corner-bracket color (defaults to NEON, unchanged for every
    existing caller) - overridable so a card can reflect a semantic state,
    e.g. the scan-complete card's red brackets when threats were found."""

    def __init__(self, title="", badge="", accent=None, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._accent = accent or theme.NEON

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

    def set_accent(self, color):
        self._accent = color
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)  # draws the QSS background/border first

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor(self._accent))
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
        self._update_glow()

    def _update_glow(self):
        glow = getattr(self, "_variant", None) == "primary" and self.isEnabled()
        self.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=20) if glow else None)

    def setEnabled(self, enabled):
        super().setEnabled(enabled)
        # A disabled button must not look clickable: no pointing hand.
        self.setCursor(Qt.CursorShape.PointingHandCursor if enabled else Qt.CursorShape.ArrowCursor)
        self._update_glow()


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

        self._icon_font = QFont(theme.ICON_FONT_FAMILY)
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


class PageHeader(QWidget):
    """The accent-bar + title + subtitle block every page starts with,
    matching the mockup's .page-header."""

    def __init__(self, title, subtitle, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        accent = QFrame()
        accent.setObjectName("pageAccentBar")
        accent.setFixedWidth(3)
        accent.setMinimumHeight(48)
        accent.setMaximumHeight(48)
        accent.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        layout.addWidget(accent)

        text_col = QVBoxLayout()
        text_col.setSpacing(6)

        self.title_label = QLabel(title.upper())
        self.title_label.setObjectName("pageTitle")
        self.title_label.setFont(theme.letter_spaced_font(size=18, black=True, spacing=4))
        self.title_label.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=20))
        text_col.addWidget(self.title_label)

        self.sub_label = QLabel(subtitle)
        self.sub_label.setObjectName("pageSub")
        self.sub_label.setFont(theme.letter_spaced_font(size=8, spacing=1))
        text_col.addWidget(self.sub_label)

        layout.addLayout(text_col)
        layout.addStretch(1)


class HeroStatusCard(QFrame):
    """Big always-neon-bordered status banner, matching the mockup's .hero.
    Distinct from Card (no title header, no corner brackets, always-neon
    border instead of the dim one) so it's its own widget rather than a
    Card variant."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("heroCard")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(30, 26, 30, 26)
        layout.setSpacing(24)

        self._shield = QLabel("\U0001F6E1")
        self._shield.setFont(QFont(theme.FONT_FALLBACKS, 26))
        self._shield.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=16))
        layout.addWidget(self._shield)

        text_col = QVBoxLayout()
        text_col.setSpacing(6)

        self._greeting = QLabel("// SECURITY STATUS")
        self._greeting.setObjectName("heroGreeting")
        self._greeting.setFont(theme.letter_spaced_font(size=8, bold=True, spacing=3))
        text_col.addWidget(self._greeting)

        self._status = QLabel()
        self._status.setObjectName("heroStatus")
        self._status.setFont(theme.letter_spaced_font(size=17, black=True, spacing=3))
        text_col.addWidget(self._status)

        self._desc = QLabel()
        self._desc.setObjectName("heroDesc")
        self._desc.setFont(theme.letter_spaced_font(size=9, spacing=0.5))
        self._desc.setTextFormat(Qt.TextFormat.RichText)
        text_col.addWidget(self._desc)

        layout.addLayout(text_col)
        layout.addStretch(1)

    def set_state(self, level, last_scan_text):
        """level: a protection_modules level (SECURED / PARTIAL /
        NOT_PROTECTED, or STARTING before the watchers run) - from
        AutoScanController.protection_level_changed, the same signal and
        the same LEVEL_VIEW label/colour as the sidebar's status box.
        last_scan_text: scan_history.last_scan_text() - "No scan yet" when
        nothing was ever scanned, so SECURED never reads as "scanned"."""
        label, token = protection_modules.LEVEL_VIEW.get(
            level, protection_modules.LEVEL_VIEW[protection_modules.STARTING])
        accent = getattr(theme, token)
        glow = level != protection_modules.STARTING
        status_text = "STARTING PROTECTION…" if level == protection_modules.STARTING else label

        # Scoped to #heroCard so it can't cascade into the child QLabels;
        # only the border colour changes, the QSS gradient background stays.
        self.setStyleSheet(f"QFrame#heroCard {{ border-color: {accent}; }}")
        self._shield.setGraphicsEffect(theme.glow_effect(accent, blur=16) if glow else None)

        self._status.setText(status_text)
        self._status.setStyleSheet(f"color: {accent};")
        self._status.setGraphicsEffect(theme.glow_effect(accent, blur=18) if glow else None)

        # The label above already says how protected; this line only says
        # when the last scan was (or that there was none) - no numbers.
        self._desc.setText(html.escape(last_scan_text))


class ElidedLabel(QLabel):
    """A one-line label for live paths: long text is elided in the MIDDLE
    (drive … file name, like the Results page), it never wraps,
    its height never changes and it never asks for more width - so a long
    path can't make a layout jump or widen a window/popup. The full text is
    always in the tooltip; fullText() returns it."""

    def __init__(self, text="", parent=None):
        super().__init__(parent)
        self._full_text = ""
        self.setWordWrap(False)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.setText(text)

    def fullText(self):
        return self._full_text

    def setText(self, text):
        self._full_text = text or ""
        self.setToolTip(self._full_text)
        self._refresh()

    def setFont(self, font):
        super().setFont(font)
        self._refresh()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._refresh()

    def changeEvent(self, event):
        super().changeEvent(event)  # a stylesheet/font change can alter metrics
        if event.type() in (event.Type.FontChange, event.Type.StyleChange):
            self._refresh()

    def _refresh(self):
        metrics = QFontMetrics(self.font())
        width = max(0, self.contentsRect().width() - 2)
        super().setText(metrics.elidedText(self._full_text, Qt.TextElideMode.ElideMiddle, width))
        # One line, whatever the text: the height is fixed from the font
        # plus this label's own margins/padding.
        margins = self.contentsMargins()
        height = metrics.height() + margins.top() + margins.bottom() + 2 * self.margin()
        if self.height() != height or self.minimumHeight() != height:
            self.setFixedHeight(height)


class StatCard(QFrame):
    """Label + big value stat tile, matching the mockup's .stat-card.
    variant="warn"/"danger" recolors the value (.stat-card.warn/.danger)."""

    def __init__(self, label, value="", variant="default", parent=None):
        super().__init__(parent)
        self.setObjectName("statCard")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(10)

        self._label = QLabel(f"// {label}".upper())
        self._label.setObjectName("statLabel")
        self._label.setFont(theme.letter_spaced_font(size=8, bold=True, spacing=2))
        layout.addWidget(self._label)

        self._value = QLabel()
        self._value.setObjectName("statValue")
        self._value.setFont(theme.letter_spaced_font(size=17, black=True, spacing=1))
        layout.addWidget(self._value)

        self.set_value(value, variant)

    def set_value(self, value, variant="default"):
        color = {"warn": theme.WARN, "danger": theme.DANGER}.get(variant, theme.NEON)
        self._value.setText(str(value))
        self._value.setStyleSheet(f"color: {color};")
        self._value.setGraphicsEffect(theme.glow_effect(color, blur=12))

    def enterEvent(self, event):
        self.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=16))
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.setGraphicsEffect(None)
        super().leaveEvent(event)


class _ClickableLabel(QLabel):
    """A QLabel that emits clicked() - used for the tree's collapse arrow,
    where a full QPushButton's chrome/padding isn't wanted."""

    clicked = Signal()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class RadioItem(QPushButton):
    """A pill-shaped exclusive-group radio button matching .radio-item.
    The label is native QPushButton text (plain Latin text, no icon glyph,
    so none of the font-fallback risk NavItem/ActionCard's icons have) -
    only the circle+dot indicator is custom-painted, in the QSS rule's
    reserved left padding."""

    def __init__(self, text, parent=None):
        super().__init__(text.upper(), parent)
        self.setObjectName("radioItem")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setProperty("active", False)
        self.setFont(theme.letter_spaced_font(size=9, bold=True, spacing=1))
        self.toggled.connect(self._on_toggled)

    def _on_toggled(self, checked):
        self.setProperty("active", checked)
        self.style().unpolish(self)
        self.style().polish(self)
        self.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=10) if checked else None)
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)  # background/border/text via QSS

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        checked = self.isChecked()
        color = QColor(theme.NEON) if checked else QColor(theme.TEXT_MUTE)

        cx, cy, r = 18.0, self.height() / 2, 7.0
        painter.setPen(QPen(color, 2))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(QRectF(cx - r, cy - r, r * 2, r * 2))

        if checked:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(theme.NEON))
            inner_r = 3.0
            painter.drawEllipse(QRectF(cx - inner_r, cy - inner_r, inner_r * 2, inner_r * 2))

        painter.end()


class TreeCheckbox(QWidget):
    """Small checkbox matching the mockup's tree-item checkbox styling.

    Deliberately does NOT self-toggle on click like ToggleSwitch does - it
    only emits clicked(), and the owner decides whether to actually call
    setChecked(). That's what lets ScanPage intercept a System Area uncheck
    with a confirmation dialog *before* any visual change happens, instead
    of toggling then reverting (which would flash).
    """

    clicked = Signal()

    def __init__(self, checked=False, parent=None):
        super().__init__(parent)
        self.setFixedSize(16, 16)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._checked = checked

    def isChecked(self):
        return self._checked

    def setChecked(self, checked):
        checked = bool(checked)
        if checked == self._checked:
            return
        self._checked = checked
        self.update()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = QRectF(1, 1, self.width() - 2, self.height() - 2)
        if self._checked:
            painter.setBrush(QColor(0, 255, 170, 38))
            painter.setPen(QPen(QColor(theme.NEON), 1.5))
        else:
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(QColor(theme.TEXT_MUTE), 1.5))
        painter.drawRoundedRect(rect, 3, 3)

        if self._checked:
            # a drawn checkmark (line segments), not a font glyph - avoids
            # any repeat of the icon-font-fallback bug class for "✓".
            pen = QPen(QColor(theme.NEON), 2)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            painter.drawPolyline([
                QPointF(rect.left() + 3, rect.top() + 8),
                QPointF(rect.left() + 6.5, rect.bottom() - 3),
                QPointF(rect.right() - 3, rect.top() + 4),
            ])

        painter.end()


class TreeRow(QWidget):
    """One row in the Scan page's checkbox tree, matching .tree-item /
    .tree-indent - a group row (icon + collapsible ▾/▸ arrow, e.g. Computer
    Drive/System Area) or a plain indented child row.

    toggled(requested_checked) fires when the checkbox is clicked, carrying
    the state the user is requesting (not yet applied - see TreeCheckbox).
    The owner calls setChecked() to actually apply it, or doesn't (e.g. the
    System Area confirmation dialog was declined).
    """

    toggled = Signal(bool)
    collapse_toggled = Signal(bool)  # only meaningful for group rows; True = expanded

    def __init__(self, label, is_group=False, icon="", indent=False, checked=False, parent=None):
        super().__init__(parent)
        self.setObjectName("treeRow")
        self.setProperty("hoverable", True)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self._expanded = True

        layout = QHBoxLayout(self)
        left_margin = 34 if indent else 10
        layout.setContentsMargins(left_margin, 5, 10, 5)
        layout.setSpacing(10)

        self.arrow_label = None
        if is_group:
            self.arrow_label = _ClickableLabel("▾")
            self.arrow_label.setObjectName("treeArrow")
            self.arrow_label.setFixedWidth(14)
            self.arrow_label.setCursor(Qt.CursorShape.PointingHandCursor)
            self.arrow_label.setFont(QFont(theme.ICON_FONT_FAMILY, 9))
            self.arrow_label.clicked.connect(self._on_arrow_clicked)
            layout.addWidget(self.arrow_label)

        self.checkbox = TreeCheckbox(checked=checked)
        self.checkbox.clicked.connect(
            lambda: self.toggled.emit(not self.checkbox.isChecked())
        )
        layout.addWidget(self.checkbox)

        if icon:
            icon_label = QLabel(icon)
            icon_label.setFont(QFont(theme.FONT_FALLBACKS, 12))
            icon_label.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=6))
            layout.addWidget(icon_label)

        text_label = QLabel(label)
        text_label.setObjectName("treeLabel")
        text_label.setFont(theme.letter_spaced_font(size=9, bold=is_group, spacing=0.5))
        layout.addWidget(text_label)

        layout.addStretch(1)

    def _on_arrow_clicked(self):
        self._expanded = not self._expanded
        self.arrow_label.setText("▾" if self._expanded else "▸")
        self.collapse_toggled.emit(self._expanded)

    def isChecked(self):
        return self.checkbox.isChecked()

    def setChecked(self, checked):
        self.checkbox.setChecked(checked)


class ActionCard(QFrame):
    """Clickable icon+title card, matching the mockup's .action-card - icon
    centered above the title (no subtitle, unlike the mockup's left-icon/
    right-text row - a deliberate simplified variant)."""

    clicked = Signal()

    def __init__(self, icon, title, parent=None):
        super().__init__(parent)
        self.setObjectName("actionCard")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(10)

        icon_box = QLabel(icon)
        icon_box.setObjectName("actionIconBox")
        icon_box.setFixedSize(44, 44)
        icon_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_box.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        icon_box.setFont(QFont(theme.ICON_FONT_FAMILY, 15))
        icon_box.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=8))
        layout.addWidget(icon_box, 0, Qt.AlignmentFlag.AlignHCenter)

        title_label = QLabel(title.upper())
        title_label.setObjectName("actionTitle")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setFont(theme.letter_spaced_font(size=10, bold=True, spacing=1.5))
        layout.addWidget(title_label, 0, Qt.AlignmentFlag.AlignHCenter)

    def mouseReleaseEvent(self, event):
        # Checking the release position directly (not underMouse()) - Qt's
        # underMouse() tracking is driven by real enter/leave events, which
        # QTest.mouseClick's synthetic press+release doesn't reliably
        # generate, so it can't be trusted to reflect a synthetic click.
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)

    def enterEvent(self, event):
        self.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=18))
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.setGraphicsEffect(None)
        super().leaveEvent(event)


class StatusCircle(QWidget):
    """A large outline circle with a centered drawn symbol - checkmark
    ("success") or exclamation mark ("danger") - matching the scan-complete
    card's icon. The symbol is drawn with QPainter, not a font glyph - the
    same zero-font-risk approach TreeCheckbox's checkmark already uses,
    doubly worth it here since this icon is large and prominent."""

    def __init__(self, variant="success", size=90, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._variant = variant
        self._apply_glow()

    def set_variant(self, variant):
        self._variant = variant
        self._apply_glow()
        self.update()

    def _color(self):
        return QColor(theme.NEON if self._variant == "success" else theme.DANGER)

    def _apply_glow(self):
        self.setGraphicsEffect(theme.glow_effect(self._color().name(), blur=24))

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        color = self._color()

        ring_rect = QRectF(4, 4, self.width() - 8, self.height() - 8)
        painter.setPen(QPen(color, 2.5))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(ring_rect)

        cx, cy = self.width() / 2, self.height() / 2
        mark_pen = QPen(color, 3)
        mark_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        mark_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(mark_pen)

        if self._variant == "success":
            painter.drawPolyline([
                QPointF(cx - 14, cy + 1),
                QPointF(cx - 4, cy + 11),
                QPointF(cx + 16, cy - 13),
            ])
        else:
            painter.drawLine(QPointF(cx, cy - 18), QPointF(cx, cy + 6))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color)
            painter.drawEllipse(QRectF(cx - 2.5, cy + 12, 5, 5))

        painter.end()


class ModuleToggleCard(Card):
    """A Card with a title + ToggleSwitch header, a description line, and a
    small "// ACTIVE"/"// OFF" status label - used by the Protection page's
    Downloads/USB Auto-Scan toggles. title="" skips Card's own header (a
    custom one is built here instead, since it needs the switch inline)."""

    toggled = Signal(bool)

    def __init__(self, title, description, initial_checked=True, parent=None):
        super().__init__(parent=parent)

        header = QHBoxLayout()
        header.setSpacing(8)

        title_label = QLabel(title)
        title_label.setFont(theme.letter_spaced_font(size=11, bold=True, spacing=1))
        title_label.setStyleSheet(f"color: {theme.TEXT};")
        header.addWidget(title_label)
        header.addStretch(1)

        self._switch = ToggleSwitch(checked=initial_checked)
        self._switch.toggled.connect(self._on_switch_toggled)
        header.addWidget(self._switch)

        self.content_layout.addLayout(header)

        desc = QLabel(description)
        desc.setWordWrap(True)
        desc.setFont(theme.letter_spaced_font(size=8, spacing=0.3))
        desc.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.content_layout.addWidget(desc)

        self._status_label = QLabel()
        self._status_label.setFont(theme.letter_spaced_font(size=7, bold=True, spacing=1))
        self.content_layout.addWidget(self._status_label)

        self._update_status(initial_checked)

    def _on_switch_toggled(self, checked):
        self._update_status(checked)
        self.toggled.emit(checked)

    def set_checked_silently(self, checked):
        """Reflect external state (e.g. re-read from the registry) without
        emitting toggled - so syncing the UI never writes anything back."""
        self._switch.blockSignals(True)
        self._switch.setChecked(checked, animate=False)
        self._switch.blockSignals(False)
        self._update_status(checked)

    def _update_status(self, checked):
        self._status_label.setText("// ACTIVE" if checked else "// OFF")
        self._status_label.setStyleSheet(f"color: {theme.NEON if checked else theme.TEXT_MUTE};")


# ─── Scan-running orbit animation (sidebar logo + tray icon) ───

# The orbit ring's centre in app_icon.png as a fraction of the icon size,
# measured from the 600px source - the eye (and the ring drawn around it)
# sits ~9px above the rounded square's own centre.
ORBIT_CENTER = (0.5, 287 / 600)
ORBIT_PERIOD_MS = 2400  # one full turn


def load_orbit_layers():
    """(base, orbit) QImages, or None if either asset is missing - callers
    then simply stay static. base + orbit at 0 degrees == app_icon.png."""
    base = QImage(theme.ICON_BASE_PATH)
    orbit = QImage(theme.ICON_ORBIT_PATH)
    if base.isNull() or orbit.isNull():
        return None
    return base, orbit


def scaled_image(image, pixels):
    return image.scaled(pixels, pixels, Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation)


def orbit_frame(base, orbit, angle):
    """One frame: base, plus the orbit layer rotated `angle` degrees about
    ORBIT_CENTER and added on as light (CompositionMode_Plus), then clipped
    back to base's own rounded-square alpha so rotated glow never spills
    into the transparent corners. base and orbit must be the same size."""
    frame = base.convertToFormat(QImage.Format.Format_ARGB32_Premultiplied)
    cx = ORBIT_CENTER[0] * frame.width()
    cy = ORBIT_CENTER[1] * frame.height()
    painter = QPainter(frame)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus)
    painter.translate(cx, cy)
    painter.rotate(angle)
    painter.translate(-cx, -cy)
    painter.drawImage(0, 0, orbit)
    painter.resetTransform()
    painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_DestinationIn)
    painter.drawImage(0, 0, base)
    painter.end()
    return frame


class ScanOrbitLogo(QWidget):
    """The app logo at a fixed size. While a scan runs (set_scanning(True),
    fed by ScanPage.scan_active_changed) its orbit ring - both arcs and
    both dots - rotates around the eye; idle it's exactly the static
    app_icon.png. One QTimer drives it, running only while scanning AND
    visible, so nothing ticks when idle or when hidden to the tray."""

    FRAME_MS = 33  # ~30fps

    def __init__(self, size, parent=None):
        super().__init__(parent)
        self._size = size
        self.setFixedSize(size, size)
        # Blur 14 was tuned for the original 36px logo - scale with it.
        self.setGraphicsEffect(theme.glow_effect(theme.NEON, blur=round(14 * size / 36)))

        self._layers = load_orbit_layers()
        self._scanning = False
        self._cache_ratio = None
        self._static = self._base = self._orbit = None

        self._clock = QElapsedTimer()
        self._timer = QTimer(self)
        self._timer.setInterval(self.FRAME_MS)
        self._timer.timeout.connect(self.update)

    def set_scanning(self, scanning):
        self._scanning = bool(scanning) and self._layers is not None
        if self._scanning:
            self._clock.start()
            if self.isVisible():
                self._timer.start()
        else:
            self._timer.stop()
        self.update()

    def showEvent(self, event):
        super().showEvent(event)
        if self._scanning:
            self._timer.start()

    def hideEvent(self, event):
        super().hideEvent(event)
        self._timer.stop()

    def _ensure_cache(self):
        # Images are cached at device pixels so a high-DPI screen stays sharp.
        ratio = self.devicePixelRatioF()
        if ratio == self._cache_ratio:
            return
        self._cache_ratio = ratio
        pixels = round(self._size * ratio)
        self._static = scaled_image(QImage(theme.ICON_PATH), pixels)
        if self._layers is not None:
            self._base = scaled_image(self._layers[0], pixels)
            self._orbit = scaled_image(self._layers[1], pixels)

    def paintEvent(self, event):
        self._ensure_cache()
        if self._scanning:
            angle = (self._clock.elapsed() % ORBIT_PERIOD_MS) * 360 / ORBIT_PERIOD_MS
            image = orbit_frame(self._base, self._orbit, angle)
        else:
            image = self._static
        if image.isNull():
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        painter.drawImage(QRectF(0, 0, self._size, self._size), image)
