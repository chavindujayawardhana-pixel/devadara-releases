"""
dashboard.py

The landing screen (Section 3). Answers "Is my PC protected?" immediately
via the hero card, then offers the four quick-scan actions, a read-only
mirror of protection module state, and a real recent-activity feed backed
by devadara_gui.services.activity_log.
"""

from datetime import datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from devadara_gui import theme
from devadara_gui.components import (
    Card,
    EmptyState,
    StatusDot,
    body_secondary,
    body_text,
    format_timestamp,
    hairline,
    make_label,
    page_title,
    stat_block,
    status_row,
)
from devadara_gui.icons import icon_label, icon_style
from devadara_gui.services import activity_log

# Kinds that are always worth surfacing on the Dashboard even amid a run of
# routine scans - anything NOT in this "routine" set is always shown.
# scan_log.py/activity_log.py themselves are untouched by this - it only
# changes what the Dashboard's own Recent Activity list chooses to surface.
_ROUTINE_ACTIVITY_KINDS = {"scan_completed"}
_ROUTINE_DEDUP_WINDOW_SECONDS = 10 * 60


def _filter_meaningful_events(events):
    """
    events: activity_log entries, newest first (as recent_events() returns).
    Collapses back-to-back routine "scan completed, nothing found" entries
    within a short window down to just the newest one, so five near-
    identical "Quick Scan completed" rows don't crowd out anything else
    that happened. A routine scan that DID find something (its own detail
    text says so - see AppState.finalize_scan()'s summary) is never
    collapsed - only genuinely uneventful completions are.
    """
    filtered = []
    last_routine_at = None
    for event in events:
        is_routine = (
            event.get("kind") in _ROUTINE_ACTIVITY_KINDS
            and "No threats found" in (event.get("detail") or "")
        )
        if is_routine:
            try:
                this_time = datetime.fromisoformat(event["timestamp"])
            except (KeyError, ValueError):
                this_time = None
            if last_routine_at is not None and this_time is not None:
                if abs((last_routine_at - this_time).total_seconds()) < _ROUTINE_DEDUP_WINDOW_SECONDS:
                    continue  # near-duplicate of the routine completion we already kept
            if this_time is not None:
                last_routine_at = this_time
        filtered.append(event)
    return filtered


# icon, label, primary?, key - exactly one icon per card now (the earlier
# two-icon-per-card design was reverted: magnifying glass dropped from
# Quick/Full Scan, down-arrow dropped from Scan Downloads).
_QUICK_ACTIONS = [
    ("flash", "Quick Scan", True, "quick"),
    ("monitor", "Full Scan", False, "full"),
    ("folder", "Scan Downloads", False, "downloads"),
    ("usb", "Scan USB", False, "usb"),
]


class QuickActionCard(QWidget):
    clicked = Signal()

    # Exact reference values: the primary (Quick Scan) card's icon is
    # #B9FFDA and its label is #F2FFF7; the other three cards' icon is
    # #7AA98C and their label is #C7E3D3 - two genuinely distinct tiers,
    # not one shared default recolored on hover.
    _ICON_HOVER_COLOR = theme.NAV_ACTIVE_ICON

    def __init__(self, icon_name, label, primary=False, disabled=False, caption=None, parent=None):
        super().__init__(parent)
        # A plain QWidget subclass does NOT automatically track mouse-enter/
        # leave for :hover QSS the way QAbstractButton/QFrame-derived
        # widgets do - confirmed live: the #quickActionCard:hover rule was
        # syntactically fine but never actually repainted the card without
        # this. Needed for the hover CSS (and the icon-hover recolor below)
        # to have any visual effect at all. Set BEFORE apply_glow() below
        # (not after) - theme.apply_glow() checks WA_StyledBackground to
        # decide whether it's safe to also set WA_TranslucentBackground
        # (the seam-artifact fix): the two together break this widget's own
        # QSS background/border painting entirely, confirmed live via a
        # rendered comparison grid (the Quick Scan card silently lost its
        # background/border, just the icon/text floating with nothing
        # behind it) - order matters here, this must run first.
        self.setAttribute(Qt.WA_Hover, True)
        self.setAttribute(Qt.WA_StyledBackground, True)
        if disabled:
            self.setObjectName("quickActionCardDisabled")
        elif primary:
            self.setObjectName("quickActionCardPrimary")
            # box-shadow 0 0 18px rgba(60,220,140,0.25) - Quick Scan card's
            # exact glow.
            theme.apply_glow(self, theme.PRIMARY_SCAN_GLOW, blur=18)
        else:
            self.setObjectName("quickActionCard")
        self.setCursor(Qt.PointingHandCursor if not disabled else Qt.ArrowCursor)
        self.setFixedHeight(100)
        self._disabled = disabled
        self._primary = primary
        self._icon_default_color = theme.PRIMARY_SCAN_ICON if primary else theme.SCAN_CARD_ICON

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(6)

        icon_color = theme.TEXT_DISABLED if disabled else self._icon_default_color
        self._icon_widget = icon_label(icon_name, size=20, color=icon_color)
        layout.addWidget(self._icon_widget, alignment=Qt.AlignHCenter)

        text_color = theme.TEXT_DISABLED if disabled else (theme.TEXT_PRIMARY if primary else theme.SCAN_CARD_LABEL)
        text = make_label(label, "bodyText")
        text.setStyleSheet(f"font-size: 11px; font-weight: 500; color: {text_color};")
        text.setAlignment(Qt.AlignCenter)
        layout.addWidget(text)

        if caption:
            cap = make_label(caption, "metadataDisabled")
            cap.setAlignment(Qt.AlignCenter)
            layout.addWidget(cap)

    def mousePressEvent(self, event):
        if not self._disabled:
            self.clicked.emit()
        super().mousePressEvent(event)

    def enterEvent(self, event):
        if not self._disabled:
            self._icon_widget.setStyleSheet(icon_style(self._ICON_HOVER_COLOR))
            theme.apply_glow(self._icon_widget, theme.NAV_ACTIVE_ICON, blur=10, alpha=150)
        super().enterEvent(event)

    def leaveEvent(self, event):
        if not self._disabled:
            self._icon_widget.setStyleSheet(icon_style(self._icon_default_color))
            theme.clear_glow(self._icon_widget)
        super().leaveEvent(event)


class DashboardPage(theme.PageCanvas):
    scan_requested = Signal(str)  # "quick" | "full" | "downloads" | "usb"
    navigate_requested = Signal(str)

    def __init__(self, app_state, parent=None):
        super().__init__(parent)
        self.app_state = app_state
        self.setObjectName("pageRoot")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)

        content = QWidget()
        scroll.setWidget(content)

        self.layout_ = QVBoxLayout(content)
        self.layout_.setContentsMargins(
            theme.PAGE_PADDING, theme.PAGE_PADDING, theme.PAGE_PADDING, theme.PAGE_PADDING
        )
        self.layout_.setSpacing(theme.CARD_GAP)

        self.layout_.addWidget(page_title("Dashboard"))

        self.hero_card = Card(object_name="heroCard", padding=22, glow=True,
                              glow_color=theme.HERO_GLOW, glow_blur=30)
        self.layout_.addWidget(self.hero_card)

        quick_actions_row = QHBoxLayout()
        quick_actions_row.setSpacing(theme.CARD_GAP)
        self.layout_.addLayout(quick_actions_row)
        self._quick_actions_row = quick_actions_row

        # Extra breathing room between the scan buttons and Security
        # Overview - theme.CARD_GAP alone (already applied uniformly by
        # the outer layout's spacing) read as cramped.
        self.layout_.addSpacing(theme.CARD_GAP)

        self.overview_card = Card()
        self.overview_card.addWidget(make_label("SECURITY OVERVIEW", "eyebrowLabel"))
        self._overview_body = QVBoxLayout()
        self.overview_card.addLayout(self._overview_body)
        self.layout_.addWidget(self.overview_card)

        self.activity_card = Card()
        activity_header = QHBoxLayout()
        activity_header.addWidget(make_label("RECENT ACTIVITY", "eyebrowLabel"))
        activity_header.addStretch()
        self._view_all_btn = QPushButton("View All")
        self._view_all_btn.setObjectName("textButton")
        self._view_all_btn.setStyleSheet(f"color: {theme.ACCENT_GREEN};")
        self._view_all_btn.setCursor(Qt.PointingHandCursor)
        self._view_all_btn.hide()
        activity_header.addWidget(self._view_all_btn)
        self.activity_card.addLayout(activity_header)
        self._activity_body = QVBoxLayout()
        self.activity_card.addLayout(self._activity_body)
        self.layout_.addWidget(self.activity_card)

        self.layout_.addStretch()

        self.app_state.protection_changed.connect(self.refresh)
        self.app_state.activity_changed.connect(self.refresh)
        self.app_state.findings_changed.connect(self.refresh)

        self.refresh()

    # ------------------------------------------------------------------
    def refresh(self):
        self._refresh_hero()
        self._refresh_quick_actions()
        self._refresh_overview()
        self._refresh_activity()

    def _hero_accent_dot(self):
        """
        The single, deliberately tiny decorative warm-amber touch called for
        in the new visual language - a small highlight point on the hero
        card only, never anywhere functional/interactive. It carries no
        status meaning (it's identical whether protection is on or off) and
        is never clicked - purely a nod to the reference image's one warm
        accent amid all the green.
        """
        dot = QLabel()
        dot.setFixedSize(6, 6)
        dot.setStyleSheet(f"background-color: {theme.BRAND_ORANGE}; border-radius: 3px;")
        theme.apply_glow(dot, theme.BRAND_ORANGE, blur=10, alpha=120)
        return dot

    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            elif item.layout() is not None:
                self._clear_layout(item.layout())

    def _refresh_hero(self):
        self._clear_layout(self.hero_card.layout_)
        protected = self.app_state.is_realtime_protection_enabled()

        if protected:
            heading_row = QHBoxLayout()
            heading_row.setSpacing(10)
            heading_row.addWidget(StatusDot("active", glow=True))
            # Exact reference values: hero heading 17px/600/#F2FFF7.
            heading = make_label("Your PC is protected", "displayText")
            heading.setStyleSheet(f"font-size: 17px; font-weight: 600; color: {theme.HERO_HEADING_COLOR};")
            heading_row.addWidget(heading)
            heading_row.addStretch()
            heading_row.addWidget(self._hero_accent_dot())
            self.hero_card.addLayout(heading_row)
            subtext = body_secondary("Real-time protection is active")
            subtext.setStyleSheet(f"font-size: 12px; color: {theme.HERO_SUBTEXT_COLOR};")
            self.hero_card.addWidget(subtext)

            self.hero_card.addWidget(hairline())
            last_scan_raw = self.app_state.last_scan_at()
            last_scan = format_timestamp(last_scan_raw) if last_scan_raw else "Never"
            # "Threats Detected" read as contradicting "protected" right
            # above it - this count is scan_log's currently-OPEN findings
            # (not yet quarantined/deleted/ignored), so "Open Threats" is
            # the accurate label: it doesn't claim they were handled
            # (which "Blocked"/"Quarantined" would, incorrectly, for ones
            # still sitting unresolved), and it doesn't read as "your PC
            # is protected" being false.
            open_threats = str(self.app_state.threats_detected_count())
            self.hero_card.addWidget(stat_block([("LAST SCAN", last_scan), ("OPEN THREATS", open_threats)]))
        else:
            heading_row = QHBoxLayout()
            heading_row.setSpacing(10)
            heading_row.addWidget(StatusDot("attention", glow=True))
            heading = make_label("Protection is disabled", "displayText")
            heading.setStyleSheet(f"font-size: 17px; font-weight: 600; color: {theme.HERO_HEADING_COLOR};")
            heading_row.addWidget(heading)
            heading_row.addStretch()
            heading_row.addWidget(self._hero_accent_dot())
            self.hero_card.addLayout(heading_row)
            subtext = body_secondary("Real-time protection is currently turned off.")
            subtext.setStyleSheet(f"font-size: 12px; color: {theme.HERO_SUBTEXT_COLOR};")
            self.hero_card.addWidget(subtext)

            btn = QPushButton("Turn On Protection")
            btn.setObjectName("primaryButton")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda: self.app_state.set_realtime_protection(True))
            theme.apply_glow(btn, theme.ACCENT_GREEN, blur=20, alpha=130)
            row = QHBoxLayout()
            row.addWidget(btn)
            row.addStretch()
            self.hero_card.addLayout(row)

    def _refresh_quick_actions(self):
        while self._quick_actions_row.count():
            item = self._quick_actions_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        drives = self.app_state.connected_removable_drives()
        for icon_name, label, primary, key in _QUICK_ACTIONS:
            disabled = key == "usb" and len(drives) == 0
            caption = "No drive" if (key == "usb" and disabled) else None
            card = QuickActionCard(icon_name, label, primary=primary, disabled=disabled, caption=caption)
            card.clicked.connect(lambda k=key: self.scan_requested.emit(k))
            self._quick_actions_row.addWidget(card)

    def _refresh_overview(self):
        self._clear_layout(self._overview_body)
        protected = self.app_state.is_realtime_protection_enabled()

        # Real-Time Protection: the main item.
        self._overview_body.addWidget(
            status_row("Real-Time Protection", "active" if protected else "inactive",
                       "Active" if protected else "Off")
        )

        # Behavior Monitoring / Downloads Protection / USB Auto-Scan only
        # ever run because Real-Time Protection is on, so they're grouped
        # as indented sub-items beneath it (smaller text, a subtle left
        # rule) rather than three more independent-looking top-level rows.
        sub_items = [
            ("Behavior Monitoring", protected and self.app_state.is_module_enabled("behavior_monitoring")),
            ("Downloads Protection", protected and self.app_state.is_module_enabled("downloads_autoscan")),
            ("USB Auto-Scan", protected and self.app_state.is_module_enabled("usb_autoscan")),
        ]
        sub_group = QFrame()
        sub_group.setObjectName("overviewSubgroup")
        sub_layout = QVBoxLayout(sub_group)
        sub_layout.setContentsMargins(16, 2, 0, 2)
        sub_layout.setSpacing(0)
        for label, active in sub_items:
            sub_layout.addWidget(
                status_row(label, "active" if active else "inactive", "Active" if active else "Off", compact=True)
            )
        self._overview_body.addWidget(sub_group)
        self._overview_body.addWidget(hairline())

        # Windows Startup: unrelated to real-time protection - stays a
        # separate top-level item, not part of the group above.
        startup = self.app_state.is_startup_enabled()
        self._overview_body.addWidget(
            status_row("Windows Startup", "active" if startup else "inactive", "Enabled" if startup else "Off")
        )

    def _refresh_activity(self):
        self._clear_layout(self._activity_body)
        pool = activity_log.recent_events(limit=30)
        meaningful = _filter_meaningful_events(pool)
        events = meaningful[:5]

        if not events:
            empty = EmptyState("You're all clear", "No recent security issues have been detected.")
            empty.setFixedHeight(140)
            self._activity_body.addWidget(empty)
            self._view_all_btn.hide()
            return

        for event in events:
            row = QHBoxLayout()
            row.setSpacing(10)
            attention_kinds = {"threat_detected", "behavior_alert"}
            dot = StatusDot("attention" if event["kind"] in attention_kinds else "active")
            row.addWidget(dot)
            col = QVBoxLayout()
            col.setSpacing(2)
            col.addWidget(body_text(event["title"]))
            when = format_timestamp(event["timestamp"])
            col.addWidget(make_label(when, "metadataText"))
            row.addLayout(col)
            row.addStretch()
            self._activity_body.addLayout(row)

        self._view_all_btn.setVisible(len(meaningful) > 5)
