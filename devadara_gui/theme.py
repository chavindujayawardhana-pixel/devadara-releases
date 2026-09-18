"""
theme.py

DEVADARA's design tokens (colors, type, spacing, radius) in one place, plus
the single QSS stylesheet built from them. Every widget in the app should
pull its color from here rather than hardcoding a hex value.

Object names (setObjectName) are how individual widgets opt into a specific
QSS rule below (e.g. a QPushButton needs objectName "primaryButton" or
"secondaryButton" to get filled/outlined styling - a bare QPushButton falls
back to the generic button rule).

---- Visual language: assets/dashboard_reference.html ---------------------
Every color/gradient/glow value below is copied directly from that
reference file, not approximated. Two things in it have NO single-brush
QSS equivalent, so they're real QPainter code instead of a stylesheet
string:

  1. The page background: a radial gradient (circle at 20%/20%, farthest-
     corner) PLUS two independent elliptical ambient-glow highlights PLUS
     an inset vignette - three separate layers, whereas a QSS
     background-color can only ever be ONE brush. See PageCanvas below;
     every top-level page inherits from it instead of plain QWidget.
  2. Any "glow" (box-shadow) - Qt Style Sheets have no such property at
     all. See apply_glow(), a real QGraphicsDropShadowEffect, applied to
     the same deliberately small set of marquee surfaces as before
     (primary buttons, hero/primary cards, the active nav item, the two
     floating notification surfaces) - never per-row in a table/list, to
     keep this cheap on a typical Windows machine.

Everything else (linear/radial gradients with 2-3 stops, translucent
borders) is a plain QSS qlineargradient/qradialgradient string.
"""

import math

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QPainter, QRadialGradient
from PySide6.QtWidgets import QGraphicsDropShadowEffect, QWidget

# ============================================================================
# EXACT reference colors (assets/dashboard_reference.html) - copied, not
# approximated. Grouped by the role the reference uses them for.
# ============================================================================

# ---- Page background (radial gradient stops) ----
PAGE_BG_1 = "#1a1a2e"
PAGE_BG_2 = "#121220"
PAGE_BG_3 = "#0a0a0f"

# ---- Ambient glow overlay (two independent elliptical highlights) ----
AMBIENT_GLOW_1 = (0, 255, 170, 40)    # neon green, alpha ~0.16
AMBIENT_GLOW_2 = (0, 229, 255, 30)    # neon cyan, alpha ~0.12
PAGE_VIGNETTE = (0, 0, 0, 153)        # rgba(0,0,0,0.6)       -> alpha 0.6*255

# ---- Sidebar ----
SIDEBAR_GRADIENT_TOP = "rgba(10, 40, 25, 0.6)"
SIDEBAR_GRADIENT_BOTTOM = "rgba(0, 0, 0, 0.7)"
SIDEBAR_BORDER = "rgba(80, 255, 170, 0.15)"

# ---- Logo mark ----
LOGO_GRADIENT_1 = "#7CFFB2"
LOGO_GRADIENT_2 = "#16A34A"
LOGO_GRADIENT_3 = "#04160c"
LOGO_GLOW = (60, 220, 140, 179)  # rgba(60,220,140,0.7)

# ---- Nav items ----
NAV_ACTIVE_GRADIENT_1 = "rgba(60, 220, 140, 0.25)"
NAV_ACTIVE_GRADIENT_2 = "rgba(0, 0, 0, 0.1)"
NAV_ACTIVE_GLOW = (60, 220, 140, 64)   # rgba(60,220,140,0.25)
NAV_ACTIVE_TEXT = "#EFFFF6"
NAV_ACTIVE_ICON = "#7CFFB2"
NAV_INACTIVE_TEXT = "#B7D9C4"
NAV_INACTIVE_ICON = "#7AA98C"

# ---- Hero card ("Your PC is protected") ----
# Background/glow deliberately match the Dashboard's Security Overview
# card (NEUTRAL_CARD_GRADIENT_*/the app's one true glow-accent rgb below)
# rather than their own one-off values - see the app-wide color-consistency
# pass this comment was added in. HERO_BORDER stays distinct (0.2, not
# 0.12): that is the app's real, intentional "emphasized/elevated" border
# tier, reused everywhere via BORDER_STRONG (hover states, dialogs, the
# hero card itself) - collapsing it into the plain 0.12 tier would erase
# real hover/elevation affordances app-wide, which was never the ask.
HERO_GRADIENT_1 = "rgba(18, 18, 32, 0.7)"
HERO_GRADIENT_2 = "rgba(10, 10, 15, 0.7)"
HERO_BORDER = "rgba(120, 255, 180, 0.2)"
HERO_GLOW = (60, 220, 140, 38)          # rgba(60,220,140,0.15) - the same
                                         # glow-accent rgb as NAV_ACTIVE_GLOW/
                                         # PRIMARY_SCAN_GLOW/AMBIENT_GLOW_1/
                                         # LOGO_GLOW below, not its own hue.
HERO_INSET_TOP_HIGHLIGHT = "rgba(255, 255, 255, 0.06)"
HERO_HEADING_COLOR = "#F2FFF7"
HERO_SUBTEXT_COLOR = "#A9D6BC"
HERO_DOT_GRADIENT_1 = "#B9FFDA"
HERO_DOT_GRADIENT_2 = "#22C55E"
HERO_DOT_GLOW = (60, 220, 140, 230)     # rgba(60,220,140,0.9)
STAT_LABEL_COLOR = "#8FBFA3"
STAT_VALUE_COLOR = "#F2FFF7"

# ---- Quick Scan card (the one highlighted/primary scan action) ----
# Its background/border now come from the shared NEUTRAL_CARD_GRADIENT/
# BORDER_STRONG tokens (app-wide color-consistency pass) - only the glow
# and icon color stay its own, as the sole way this card differs from its
# siblings, matching Security Overview's own text/dot-only differentiation.
PRIMARY_SCAN_GLOW = (60, 220, 140, 64)  # rgba(60,220,140,0.25)
PRIMARY_SCAN_ICON = "#B9FFDA"

# ---- The other (non-primary) scan-action cards ----
SCAN_CARD_ICON = "#7AA98C"
SCAN_CARD_LABEL = "#C7E3D3"

# ---- Security Overview card (the reference's generic/neutral card) ----
NEUTRAL_CARD_GRADIENT_1 = "rgba(18, 18, 32, 0.7)"
NEUTRAL_CARD_GRADIENT_2 = "rgba(10, 10, 15, 0.7)"
NEUTRAL_CARD_BORDER = "rgba(120, 255, 180, 0.12)"
EYEBROW_LABEL_COLOR = "#8FBFA3"
ROW_LABEL_COLOR = "#F2FFF7"
ROW_ACTIVE_VALUE_COLOR = "#7CFFB2"

# ============================================================================
# General-purpose tokens, built from / matched to the palette above. The
# reference only shows the Dashboard, so these extend its same language to
# every other page/component it doesn't explicitly cover, per the brief's
# "propagate this token system app-wide" instruction.
# ============================================================================

TEXT_PRIMARY = HERO_HEADING_COLOR          # #F2FFF7 - the reference's one
                                            # "brightest" text tier, reused
                                            # everywhere (hero heading, stat
                                            # values, row labels all agree).
TEXT_SECONDARY = NAV_INACTIVE_TEXT          # #B7D9C4
TEXT_DISABLED = "#5C7A6A"                   # a step dimmer than TEXT_SECONDARY,
                                            # not given explicitly by the
                                            # reference - kept in the same
                                            # muted-sage family.
ICON_MUTED = NAV_INACTIVE_ICON              # #7AA98C - default/inactive icon
ICON_ACTIVE = NAV_ACTIVE_ICON               # #7CFFB2 - hover/active icon

ACCENT_GREEN = HERO_DOT_GRADIENT_2          # #22C55E - general "on/active" solid accent
KELLY_GREEN = NAV_ACTIVE_ICON               # #7CFFB2 - brightest interactive accent
BRAND_ORANGE = "#C87A2E"                    # unchanged - the app's one sanctioned
                                            # decorative-only exception; the
                                            # reference doesn't touch this rule.

# "Raised/floating" surfaces (dialogs, slide-over panel, toast, the
# real-time popup) - the reference has no dedicated example for these, so
# they reuse the hero card's treatment (the reference's most "elevated"
# card), per the same propagation instruction.
RAISED_GRADIENT_1 = HERO_GRADIENT_1
RAISED_GRADIENT_2 = HERO_GRADIENT_2
RAISED_BORDER = HERO_BORDER
RAISED_GLOW = HERO_GLOW

BORDER_DEFAULT = NEUTRAL_CARD_BORDER
BORDER_STRONG = HERO_BORDER

FONT_FAMILY = "Consolas, 'SF Mono', 'Courier New', monospace"

RADIUS_CARD = 12          # reference cards use 12-14px radii, not the old 10px
RADIUS_HERO = 14
RADIUS_BUTTON = 8
RADIUS_INPUT = 6

SPACING_UNIT = 8
PAGE_PADDING = 32
CARD_PADDING = 20
CARD_GAP = 16

SIDEBAR_WIDTH = 160       # reference's exact sidebar width (was 240)
CONTENT_MIN_WIDTH = 900

# ============================================================
# CYBERPUNK THEME TOKENS (Phase 1 — added, not yet applied)
# ============================================================

# Backgrounds
CYBER_BG_BASE = "#0a0a0f"          # deep space black
CYBER_BG_PANEL = "#12122099"       # panel translucent
CYBER_BG_PANEL_SOLID = "#121220"
CYBER_BG_ELEVATED = "#1a1a2e"
CYBER_BG_INSET = "#08080d"

# Borders
CYBER_BORDER_DEFAULT = "#1a3a3a"
CYBER_BORDER_GLOW = "#00ffaa33"    # border with alpha glow
CYBER_BORDER_STRONG = "#2e7d5e"

# Neon accents
CYBER_NEON = "#00ffaa"             # primary neon green
CYBER_NEON_DIM = "#00cc88"
CYBER_CYAN = "#00e5ff"             # secondary accent
CYBER_DANGER = "#ff3355"           # threat red
CYBER_WARN = "#ffcc00"             # warning amber

# Text
CYBER_TEXT_PRIMARY = "#d4fff0"     # main text (WCAG AA on #0a0a0f)
CYBER_TEXT_SECONDARY = "#5a8a7a"   # dim text
CYBER_TEXT_MUTE = "#3a5a4a"        # muted labels
CYBER_TEXT_ACCENT = "#00ffaa"      # accent text (neon)

# Glow tuples (R, G, B, A) for theme.apply_glow()
CYBER_GLOW_NEON = (0, 255, 170, 102)    # rgba(0,255,170,0.4)
CYBER_GLOW_CYAN = (0, 229, 255, 102)    # rgba(0,229,255,0.4)
CYBER_GLOW_DANGER = (255, 51, 85, 102)  # rgba(255,51,85,0.4)
CYBER_GLOW_SOFT = (0, 255, 170, 51)     # rgba(0,255,170,0.2)

# Scanline effect (for Phase 2 — declared here for reference)
CYBER_SCANLINE_ALPHA = 0.02


def _rgba(rgba_tuple):
    r, g, b, a = rgba_tuple
    return f"rgba({r}, {g}, {b}, {a / 255:.3f})"


# Primary buttons: not shown in the reference file at all (no <button> in
# it) - reuse the hero status dot's exact glossy gradient (its brightest
# "interactive accent" example) rather than inventing a new one.
GRADIENT_BUTTON_PRIMARY = (
    f"qlineargradient(x1:0, y1:0, x2:1, y2:1, "
    f"stop:0 {HERO_DOT_GRADIENT_1}, stop:1 {HERO_DOT_GRADIENT_2})"
)
GRADIENT_BUTTON_PRIMARY_HOVER = (
    "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #CFFFE8, stop:1 #2FE070)"
)

GRADIENT_SIDEBAR = (
    f"qlineargradient(x1:0, y1:0, x2:0, y2:1, "
    f"stop:0 {SIDEBAR_GRADIENT_TOP}, stop:1 {SIDEBAR_GRADIENT_BOTTOM})"
)
GRADIENT_LOGO = (
    f"qradialgradient(cx:0.35, cy:0.30, radius:1.0, fx:0.35, fy:0.30, "
    f"stop:0 {LOGO_GRADIENT_1}, stop:0.6 {LOGO_GRADIENT_2}, stop:1 {LOGO_GRADIENT_3})"
)
GRADIENT_NAV_ACTIVE = (
    f"qlineargradient(x1:0, y1:0, x2:1, y2:1, "
    f"stop:0 {NAV_ACTIVE_GRADIENT_1}, stop:1 {NAV_ACTIVE_GRADIENT_2})"
)
GRADIENT_HERO_CARD = (
    f"qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {HERO_GRADIENT_1}, stop:1 {HERO_GRADIENT_2})"
)
GRADIENT_STATUS_DOT_ACTIVE = (
    f"qradialgradient(cx:0.35, cy:0.30, radius:1.0, fx:0.35, fy:0.30, "
    f"stop:0 {HERO_DOT_GRADIENT_1}, stop:0.7 {HERO_DOT_GRADIENT_2}, stop:1 {HERO_DOT_GRADIENT_2})"
)
# The reference gives no separate "attention" dot example - kept in the
# same white-to-accent family as before, just re-based on the new accent.
GRADIENT_STATUS_DOT_ATTENTION = (
    "qradialgradient(cx:0.35, cy:0.30, radius:1.0, fx:0.35, fy:0.30, "
    f"stop:0 #FFFFFF, stop:0.5 {HERO_DOT_GRADIENT_1}, stop:1 {NAV_ACTIVE_ICON})"
)
GRADIENT_NEUTRAL_CARD = (
    f"qlineargradient(x1:0, y1:0, x2:0.34, y2:0.94, "
    f"stop:0 {NEUTRAL_CARD_GRADIENT_1}, stop:1 {NEUTRAL_CARD_GRADIENT_2})"
)
# Raised/floating surfaces reuse the hero card's gradient verbatim.
GRADIENT_RAISED = GRADIENT_HERO_CARD


# ---------------------------------------------------------------------
# Glow helper - see module docstring for why this exists instead of QSS
# box-shadow, and why it's applied selectively rather than everywhere.
# ---------------------------------------------------------------------
def apply_glow(widget, color, blur=24, alpha=None, x_offset=0, y_offset=0):
    """
    color: either a hex string/QColor, or an (r, g, b, a) tuple copied
    straight from the reference's rgba(...) box-shadow value - pass the
    tuple as-is and leave alpha=None to use its own alpha channel exactly.
    """
    if isinstance(color, tuple):
        qc = QColor(color[0], color[1], color[2], color[3] if alpha is None else alpha)
    else:
        qc = QColor(color)
        if alpha is not None:
            qc.setAlpha(alpha)
    effect = QGraphicsDropShadowEffect(widget)
    effect.setColor(qc)
    effect.setBlurRadius(blur)
    effect.setOffset(x_offset, y_offset)
    # QGraphicsDropShadowEffect renders its source widget into an
    # intermediate ARGB buffer before compositing the blur back onto the
    # parent - if that buffer isn't properly alpha-transparent outside the
    # widget's own QSS-rounded shape (border-radius), the corners "outside
    # the arc but inside the bounding rect" can show through as an opaque
    # rectangular remnant behind the rounded card/button - a reported
    # seam/box artifact confirmed fixed by forcing a real alpha-aware
    # backing store (WA_TranslucentBackground) for the glowing widget.
    #
    # BUT: a bare QWidget (not QFrame) that already needs WA_StyledBackground
    # for its OWN QSS gradient/border to paint at all (QuickActionCard,
    # Toast - see their own comments) breaks completely if
    # WA_TranslucentBackground is ALSO set - confirmed live via a rendered
    # comparison grid: WA_StyledBackground + WA_TranslucentBackground
    # together on such a widget silently suppresses the QSS background/
    # border paint entirely (just the icon/text floats with no card behind
    # it), while either attribute alone renders correctly. QFrame-based
    # Card instances (hero card, threat card, ...) never set
    # WA_StyledBackground themselves and are unaffected either way - only
    # skip WA_TranslucentBackground for the widgets that need this specific
    # combination avoided.
    if not widget.testAttribute(Qt.WA_StyledBackground):
        widget.setAttribute(Qt.WA_TranslucentBackground, True)
    widget.setAutoFillBackground(False)
    widget.setGraphicsEffect(effect)
    return effect


def clear_glow(widget):
    widget.setGraphicsEffect(None)


# ---------------------------------------------------------------------
# PageCanvas - see module docstring point 1. Every top-level page
# (Dashboard, Scan, Protection, Threats, Tools, Settings, and Tools' own
# sub-pages) inherits from this instead of plain QWidget, so its actual
# background paints the reference's exact layered scene: base radial
# gradient (circle at 20%/20%, farthest-corner sizing) + two independent
# elliptical ambient-glow highlights + an inset vignette. This replaces
# what used to be a single QSS gradient string on a "#pageRoot" object
# name - no single QSS brush can express three independently-shaped,
# independently-positioned layers like this.
# ---------------------------------------------------------------------
class PageCanvas(QWidget):
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect()
        w, h = rect.width(), rect.height()
        if w <= 0 or h <= 0:
            super().paintEvent(event)
            return

        # 1) base radial gradient - "circle at 20% 20%", CSS default
        # farthest-corner sizing (the radius that reaches the corner
        # furthest from the center point).
        cx, cy = w * 0.20, h * 0.20
        center = QPointF(cx, cy)
        corners = (QPointF(0, 0), QPointF(w, 0), QPointF(0, h), QPointF(w, h))
        radius = max(math.hypot(c.x() - cx, c.y() - cy) for c in corners)
        base = QRadialGradient(center, max(radius, 1))
        base.setColorAt(0.0, QColor(PAGE_BG_1))
        base.setColorAt(0.35, QColor(PAGE_BG_2))
        base.setColorAt(0.75, QColor(PAGE_BG_3))
        base.setColorAt(1.0, QColor(PAGE_BG_3))
        painter.fillRect(rect, base)

        # 2) ambient glow overlay - two independent elliptical highlights.
        # Qt's qradialgradient (QSS) is circular and one-per-widget, so
        # this is real QPainter: scale the coordinate system to squash a
        # circular gradient into the reference's exact ellipse aspect.
        self._paint_ellipse_glow(painter, w, h, 0.15, 0.10, 0.60, 0.40, AMBIENT_GLOW_1)
        self._paint_ellipse_glow(painter, w, h, 0.90, 0.85, 0.50, 0.30, AMBIENT_GLOW_2)

        # 3) inset vignette - approximates "inset 0 0 80px rgba(0,0,0,0.6)"
        # (CSS inset box-shadow has no direct Qt/QSS equivalent either) as
        # a radial vignette darkening toward the widget's edges.
        self._paint_vignette(painter, w, h)

        super().paintEvent(event)

    @staticmethod
    def _paint_ellipse_glow(painter, w, h, cx_frac, cy_frac, rx_frac, ry_frac, rgba):
        rx = max(w * rx_frac, 1.0)
        ry = max(h * ry_frac, 1.0)
        painter.save()
        painter.translate(w * cx_frac, h * cy_frac)
        painter.scale(rx, ry)
        grad = QRadialGradient(QPointF(0, 0), 1.0)
        color = QColor(rgba[0], rgba[1], rgba[2], rgba[3])
        faded = QColor(color)
        faded.setAlpha(0)
        grad.setColorAt(0.0, color)
        grad.setColorAt(0.6, faded)
        grad.setColorAt(1.0, faded)
        painter.setPen(Qt.NoPen)
        painter.setBrush(grad)
        painter.drawRect(QRectF(-100, -100, 200, 200))
        painter.restore()

    @staticmethod
    def _paint_vignette(painter, w, h):
        half_diag = math.hypot(w, h) / 2.0
        grad = QRadialGradient(QPointF(w / 2, h / 2), half_diag)
        transparent = QColor(0, 0, 0, 0)
        dark = QColor(*PAGE_VIGNETTE)
        inner_stop = max(0.0, min(1.0, 1.0 - (80.0 / half_diag))) if half_diag else 0.0
        grad.setColorAt(0.0, transparent)
        grad.setColorAt(inner_stop, transparent)
        grad.setColorAt(1.0, dark)
        painter.setPen(Qt.NoPen)
        painter.setBrush(grad)
        painter.drawRect(QRectF(0, 0, w, h))


def stylesheet() -> str:
    return f"""
    * {{
        font-family: {FONT_FAMILY};
        outline: none;
    }}

    QWidget {{
        background-color: {CYBER_BG_BASE};
        color: {CYBER_TEXT_PRIMARY};
    }}

    QLabel {{
        background-color: transparent;
    }}

    /* Fallback for QMainWindow/#contentArea (the chrome around whichever
       page is current) - the real layered scene (base gradient + ambient
       glow + vignette) is painted per-page by PageCanvas; this is a plain
       single-layer approximation for the thin margins PageCanvas doesn't
       cover. */
    QMainWindow, #contentArea {{
        background: qradialgradient(cx:0.2, cy:0.2, radius:0.9, fx:0.2, fy:0.2,
            stop:0 {CYBER_BG_ELEVATED}, stop:0.35 {CYBER_BG_PANEL_SOLID}, stop:0.75 {CYBER_BG_BASE}, stop:1 {CYBER_BG_BASE});
    }}

    QScrollArea {{
        border: none;
        background-color: transparent;
    }}
    QScrollArea > QWidget > QWidget {{
        background-color: transparent;
    }}

    QScrollBar:vertical {{
        background: transparent;
        width: 10px;
        margin: 0px;
    }}
    QScrollBar::handle:vertical {{
        background: {CYBER_NEON_DIM};
        border-radius: 5px;
        min-height: 24px;
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0px;
    }}

    /* ---- Sidebar ---- */
    #sidebar {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
            stop:0 {CYBER_BG_ELEVATED}, stop:1 {CYBER_BG_BASE});
        border-right: 1px solid {CYBER_BORDER_DEFAULT};
    }}
    #sidebarLogo {{
        color: {CYBER_NEON};
        font-size: 13px;
        font-weight: 600;
        letter-spacing: 0.5px;
    }}
    #navRow {{
        background-color: transparent;
        border: 1px solid transparent;
        border-radius: 8px;
        text-align: left;
        padding-left: 10px;
        color: {CYBER_TEXT_SECONDARY};
        font-size: 12px;
        font-weight: 500;
        letter-spacing: 1px;
    }}
    #navRow:hover {{
        background-color: {_rgba(CYBER_GLOW_SOFT)};
        color: {CYBER_NEON};
        border-color: {CYBER_BORDER_GLOW};
    }}
    #navRow[active="true"] {{
        background: rgba(0, 255, 170, 0.10);
        color: {CYBER_NEON};
        border-color: {CYBER_NEON};
        padding-left: 10px;
        font-weight: 600;
    }}
    #sidebarSectionLabel {{
        color: {CYBER_TEXT_MUTE};
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 1px;
    }}
    #sidebarFooter {{
        color: {CYBER_TEXT_MUTE};
        font-size: 12px;
    }}
    #sidebarDivider {{
        background-color: {CYBER_BORDER_DEFAULT};
        max-height: 1px;
        min-height: 1px;
    }}

    /* ---- Cards / panels ---- */
    /* Generic/neutral card - the reference's "Security Overview card". */
    #card, #threatCard {{
        background: {CYBER_BG_PANEL};
        border: 1px solid {CYBER_BORDER_DEFAULT};
        border-radius: {RADIUS_CARD}px;
    }}
    /* Raised/floating surfaces (dialogs, slide-over, toast, popup) reuse
       the hero card's exact gradient/border - the reference's own most
       "elevated" example, no dedicated raised-surface sample given. */
    #cardRaised {{
        background: {GRADIENT_RAISED};
        border: 1px solid {CYBER_BORDER_STRONG};
        border-top: 1px solid {HERO_INSET_TOP_HIGHLIGHT};
        border-radius: {RADIUS_CARD}px;
    }}
    /* The Dashboard hero card gets its own exact rule (distinct radius
       from the generic card - the reference's cards are otherwise all one
       system now, see the app-wide color-consistency pass). */
    #heroCard {{
        background: {GRADIENT_HERO_CARD};
        border: 1px solid {CYBER_NEON};
        border-top: 1px solid {HERO_INSET_TOP_HIGHLIGHT};
        border-radius: {RADIUS_HERO}px;
    }}

    /* ---- Dashboard quick-action cards (scoped separately from #card so
       their hover treatment never leaks onto the many other, non-clickable
       cards that reuse that base object name elsewhere in the app). All
       three interactive tiers (default/primary/disabled) now share the
       exact same background/default-border as every plain card in the app
       (Security Overview's own card, #card) - #quickActionCardDisabled
       already did; default and primary are fixed here to match it, so a
       card's role is read from its glow/text/icon color, never a
       different card-background wash, matching how Security Overview
       itself differentiates state (dot/text color) on one consistent
       card surface. ---- */
    #quickActionCard {{
        background: {GRADIENT_NEUTRAL_CARD};
        border: 1px solid {NEUTRAL_CARD_BORDER};
        border-radius: {RADIUS_CARD}px;
    }}
    #quickActionCard:hover {{
        border-color: {CYBER_BORDER_STRONG};
    }}
    #quickActionCardPrimary {{
        background: {GRADIENT_NEUTRAL_CARD};
        border: 1px solid {CYBER_BORDER_STRONG};
        border-radius: {RADIUS_CARD}px;
    }}
    #quickActionCardPrimary:hover {{
        border-color: {CYBER_BORDER_STRONG};
    }}
    #quickActionCardDisabled {{
        background: {GRADIENT_NEUTRAL_CARD};
        border: 1px solid {NEUTRAL_CARD_BORDER};
        border-radius: {RADIUS_CARD}px;
    }}

    #statBlockRow, #statBlockItem {{
        background-color: transparent;
    }}
    #transparentPanel {{
        background-color: transparent;
    }}
    #overviewSubgroup {{
        background-color: transparent;
        border: none;
        border-left: 2px solid {CYBER_BORDER_STRONG};
    }}
    #hairline {{
        background-color: {BORDER_DEFAULT};
        max-height: 1px;
        min-height: 1px;
    }}

    /* ---- Typography helper classes (via objectName) ---- */
    #pageTitle {{ font-size: 22px; font-weight: 600; color: {CYBER_TEXT_PRIMARY}; letter-spacing: 3px; }}
    #pageSubtitle {{ font-size: 13px; color: {CYBER_TEXT_SECONDARY}; letter-spacing: 1px; }}
    #sectionTitle {{ font-size: 16px; font-weight: 600; color: {CYBER_TEXT_PRIMARY}; letter-spacing: 1.5px; }}
    #displayText {{ font-size: 32px; font-weight: 700; color: {CYBER_TEXT_PRIMARY}; }}
    #bodyText {{ font-size: 14px; color: {CYBER_TEXT_PRIMARY}; }}
    #bodySecondary {{ font-size: 13px; color: {CYBER_TEXT_SECONDARY}; }}
    #metadataText {{ font-size: 12px; color: {CYBER_TEXT_SECONDARY}; }}
    #metadataDisabled {{ font-size: 12px; color: {CYBER_TEXT_MUTE}; }}
    #linkText {{ font-size: 13px; color: {CYBER_NEON}; letter-spacing: 1px; }}
    /* Small uppercase eyebrow label - the reference's "SECURITY OVERVIEW"
       card-header treatment, reused for any card-header eyebrow app-wide. */
    #eyebrowLabel {{ font-size: 11px; font-weight: 600; letter-spacing: 0.5px; color: {EYEBROW_LABEL_COLOR}; }}

    /* ---- Buttons ---- */
    QPushButton {{
        background: {GRADIENT_RAISED};
        color: {CYBER_TEXT_PRIMARY};
        border: 1px solid {BORDER_DEFAULT};
        border-radius: {RADIUS_BUTTON}px;
        padding: 8px 16px;
        font-size: 14px;
        font-weight: 600;
    }}
    QPushButton:hover {{
        border-color: {CYBER_BORDER_STRONG};
    }}
    QPushButton:disabled {{
        color: {CYBER_TEXT_MUTE};
        background: {GRADIENT_NEUTRAL_CARD};
        border-color: {BORDER_DEFAULT};
    }}
    QPushButton:focus {{
        border: 2px solid {CYBER_NEON};
        padding: 7px 15px;
    }}

    QPushButton#primaryButton {{
        background: {CYBER_NEON};
        color: #000000;
        border: 1px solid {CYBER_NEON};
        padding: 9px 16px;
        letter-spacing: 1.5px;
    }}
    QPushButton#primaryButton:hover {{
        background: #00ffcc;
        color: #000000;
    }}
    QPushButton#primaryButton:disabled {{
        background: {GRADIENT_RAISED};
        color: {CYBER_TEXT_MUTE};
        border-color: {BORDER_DEFAULT};
    }}

    QPushButton#secondaryButton {{
        background-color: transparent;
        border: 1px solid {BORDER_DEFAULT};
        letter-spacing: 1.5px;
    }}
    QPushButton#secondaryButton:hover {{
        background-color: {_rgba(CYBER_GLOW_SOFT)};
        border-color: {CYBER_NEON};
        color: {CYBER_NEON};
    }}

    QPushButton#textButton {{
        background-color: transparent;
        border: none;
        color: {CYBER_TEXT_SECONDARY};
        padding: 4px 6px;
        font-weight: 500;
    }}
    QPushButton#textButton:hover {{
        color: {CYBER_TEXT_PRIMARY};
        background-color: transparent;
    }}

    QPushButton#dangerTextButton {{
        background-color: transparent;
        border: 1px solid {BORDER_DEFAULT};
        color: {CYBER_TEXT_PRIMARY};
    }}
    QPushButton#dangerTextButton:hover {{
        background-color: rgba(60, 220, 140, 0.08);
        border-color: {CYBER_BORDER_STRONG};
    }}

    /* ---- Inputs ---- */
    QLineEdit {{
        background: {GRADIENT_RAISED};
        border: 1px solid {BORDER_DEFAULT};
        border-radius: {RADIUS_INPUT}px;
        padding: 7px 10px;
        color: {CYBER_TEXT_PRIMARY};
        font-size: 13px;
    }}
    QLineEdit:focus {{
        border: 1px solid {CYBER_NEON};
    }}

    /* ---- Toggle switch (QCheckBox re-skinned as a pill) ---- */
    QCheckBox#toggleSwitch {{
        spacing: 0px;
    }}
    QCheckBox#toggleSwitch::indicator {{
        width: 40px;
        height: 22px;
        border-radius: 11px;
        background: rgba(0, 0, 0, 0.5);
        border: 1px solid {CYBER_TEXT_MUTE};
    }}
    QCheckBox#toggleSwitch::indicator:checked {{
        background: {_rgba(CYBER_GLOW_SOFT)};
        border: 1px solid {CYBER_NEON};
    }}

    /* ---- Tabs (Threats: Detected / Quarantine) ---- */
    QTabWidget::pane {{
        border: none;
        top: 0px;
    }}
    QTabBar::tab {{
        background: transparent;
        color: {CYBER_TEXT_SECONDARY};
        padding: 10px 4px;
        margin-right: 24px;
        font-size: 14px;
        font-weight: 600;
        border-bottom: 3px solid transparent;
    }}
    QTabBar::tab:selected {{
        color: {CYBER_TEXT_PRIMARY};
        border-bottom: 3px solid {CYBER_NEON};
    }}
    QTabBar::tab:hover {{
        color: {CYBER_TEXT_PRIMARY};
    }}

    /* ---- Table (Process Scan) ---- */
    QTableWidget {{
        background: {GRADIENT_NEUTRAL_CARD};
        border: 1px solid {NEUTRAL_CARD_BORDER};
        border-radius: {RADIUS_CARD}px;
        gridline-color: {BORDER_DEFAULT};
        color: {CYBER_TEXT_PRIMARY};
        font-size: 13px;
    }}
    QTableWidget::item {{
        padding: 6px;
        border-bottom: 1px solid {BORDER_DEFAULT};
    }}
    QTableWidget::item:selected {{
        background-color: rgba(60, 220, 140, 0.10);
        color: {CYBER_TEXT_PRIMARY};
    }}
    QHeaderView::section {{
        background-color: transparent;
        color: {CYBER_TEXT_SECONDARY};
        border: none;
        border-bottom: 1px solid {BORDER_DEFAULT};
        padding: 8px 6px;
        font-size: 11px;
        font-weight: 600;
    }}

    /* ---- Progress bar ---- */
    QProgressBar {{
        background: {GRADIENT_RAISED};
        border: none;
        border-radius: 3px;
        height: 6px;
        text-align: center;
        color: transparent;
    }}
    QProgressBar::chunk {{
        background: {GRADIENT_BUTTON_PRIMARY};
        border-radius: 3px;
    }}

    /* ---- Menu (row overflow actions) ---- */
    QMenu {{
        background: {GRADIENT_RAISED};
        border: 1px solid {CYBER_BORDER_STRONG};
        border-radius: 8px;
        padding: 4px;
    }}
    QMenu::item {{
        padding: 6px 20px 6px 12px;
        border-radius: 6px;
        color: {CYBER_TEXT_PRIMARY};
        font-size: 13px;
    }}
    QMenu::item:selected {{
        background-color: rgba(60, 220, 140, 0.14);
    }}

    QToolTip {{
        background: {GRADIENT_RAISED};
        color: {CYBER_TEXT_PRIMARY};
        border: 1px solid {CYBER_BORDER_STRONG};
        padding: 4px 8px;
    }}
    """
