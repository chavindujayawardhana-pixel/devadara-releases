"""
dashboard_page.py

Phase 2: the Dashboard page's real content - hero status card, stats row,
and Quick Actions - wired to whatever real backend data actually exists.

Data-source investigation (see the Phase 2 plan for the full table):
real-time protection state (AutoScanController.realtime_state_changed,
connected to set_realtime_state by MainWindow - the same signal the
sidebar's REAL-TIME label uses, so the two always agree) and
threat/suspicious counts (devadara.scan_log.read_findings()) are real. Nothing in the backend currently persists a "files scanned"
running total or a "last scan" timestamp for any of the interactive scan
tools (scan_cli.py, full_drive_scan_cli.py, downloads_scan_cli.py,
usb_scan_cli.py never write to scan_log.jsonl - only the unattended
startup_protect.py sweep does, and only for notable findings, never a
clean-scan tally) - those two show an honest empty state ("—" / "Never")
rather than a fake or stale number.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from devadara import scan_log, self_integrity

from devadara_gui import theme
from devadara_gui.components import ActionCard, Button, Card, ElidedLabel, HeroStatusCard, PageHeader, StatCard

# Tiers scan_log.read_findings() entries can carry that count as an actual
# threat (as opposed to "suspicious", which gets its own stat).
THREAT_TIERS = {"known_bad", "malware"}

QUICK_ACTIONS = [
    # (icon, title, nav_index, scan_mode) - nav_index matches
    # main_window.NAV_ITEMS order (0 Dashboard, 1 Scan, 2 Protection,
    # 3 Results, 4 Settings). Quick Scan and Full Scan both go to the Scan
    # page, additionally selecting that mode there (scan_mode); Protection/
    # Results just navigate (scan_mode=None).
    ("⌖", "Quick Scan", 1, "Quick Scan"),
    ("◈", "Full Scan", 1, "Full Scan"),
    ("\U0001F6E1", "Protection", 2, None),  # 🛡 - was ⚙, duplicated Settings' icon
    ("▤", "Results", 3, None),
]


# App integrity strip: status -> (headline, theme colour token).
INTEGRITY_VIEW = {
    self_integrity.VERIFIED: ("VERIFIED", "NEON"),
    self_integrity.PROBLEMS: ("PROBLEMS FOUND", "DANGER"),
    self_integrity.BAD_SIGNATURE: ("SIGNATURE INVALID", "DANGER"),
    self_integrity.NOT_SIGNED_BUILD: ("NOT A SIGNED BUILD", "TEXT_DIM"),
    self_integrity.ERROR: ("CHECK COULDN'T RUN", "WARN"),
}
INTEGRITY_TOOLTIP_PATHS = 25  # problem paths listed in the tooltip before "... and N more"


def integrity_summary(result):
    """(one-line text, colour token, tooltip) for a check_install() result."""
    status = result.get("status")
    headline, token = INTEGRITY_VIEW.get(status, INTEGRITY_VIEW[self_integrity.ERROR])
    when = (result.get("checked_at") or "").replace("T", " ")[:16]
    if status == self_integrity.VERIFIED:
        detail = f"all {result.get('checked', 0):,} program files match the signed manifest"
        tip = ("Every DEVADARA program file matches the manifest signed with the DEVADARA key.\n"
               "Limit: a replaced DEVADARA.exe controls this check itself and could fake this result.")
    elif status == self_integrity.PROBLEMS:
        groups = [(name, result.get(name) or []) for name in ("changed", "missing", "extra", "unreadable")]
        detail = " · ".join(f"{len(paths)} {name}" for name, paths in groups if paths)
        lines = [f"{name}: {path}" for name, paths in groups for path in paths]
        more = len(lines) - INTEGRITY_TOOLTIP_PATHS
        tip = "\n".join(lines[:INTEGRITY_TOOLTIP_PATHS] + ([f"... and {more} more"] if more > 0 else []))
        tip += ("\n\nNothing was changed or removed. These files are not treated as Known Good - "
                "they're scanned like any other file. Reinstalling DEVADARA from a copy you trust fixes this.")
    elif status == self_integrity.BAD_SIGNATURE:
        detail = result.get("message") or ""
        tip = ("The integrity manifest isn't signed by the DEVADARA key, so no DEVADARA file is "
               "treated as Known Good.\nReinstall DEVADARA from a copy you trust.")
    elif status == self_integrity.NOT_SIGNED_BUILD:
        detail = result.get("message") or ""
        tip = ("The self-check works only in a packaged, signed build.\n"
               "Until then no file is treated as a verified DEVADARA file.")
    else:
        detail = result.get("message") or ""
        tip = "The check couldn't finish. Nothing was changed. Try Check now again."
    text = f"{headline} — {detail}" if detail else headline
    if when:
        text += f" · checked {when}"
    return text, token, tip


def _gather_stats():
    """Pull real values from the backend. Returns a dict - see module
    docstring for which two fields have no real backend source yet."""
    findings = scan_log.read_findings()
    threats = sum(1 for entry in findings if entry.get("tier") in THREAT_TIERS)
    suspicious = sum(1 for entry in findings if entry.get("tier") == "suspicious")

    return {
        "files_scanned": "—",  # no backend source yet
        "threats": threats,
        "suspicious": suspicious,
        "last_full_scan": "Never",  # no backend source yet
    }


class DashboardPage(QWidget):
    # "Check now" on the App integrity strip - MainWindow runs the check
    # (integrity_check.IntegrityChecker) and feeds the result back.
    integrity_check_requested = Signal()

    def __init__(self, navigate, parent=None):
        """navigate: callable(index) - switches both the content stack and
        the sidebar's active nav item to the given page index (see
        MainWindow.navigate_to)."""
        super().__init__(parent)
        self._navigate = navigate

        # Same as the Protection page: with the App integrity strip, the
        # cards don't fit the window's minimum height (560) - without
        # scrolling, Qt squeezes the Quick Actions cards until their icons
        # and labels are cut off. At the normal size nothing scrolls.
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(40, 30, 40, 60)
        layout.setSpacing(20)

        stats = _gather_stats()

        self._header = PageHeader("Dashboard", "")
        layout.addWidget(self._header)

        self._last_scan_text = stats["last_full_scan"]
        self._hero = HeroStatusCard()
        layout.addWidget(self._hero)

        # STARTING until the controller's first realtime_state_changed
        # (emitted once the model has loaded and watchers have started).
        self._apply_realtime_state("starting")

        layout.addLayout(self._build_stats_row(stats))
        layout.addWidget(self._build_quick_actions())
        layout.addWidget(self._build_integrity_strip())
        layout.addStretch(1)

        # Vertical scrolling only: the stats row's own minimum width is wider
        # than the page, and the page has always fitted it to the width (as
        # before this scroll area existed) - so the width follows the page.
        content.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        scroll = QScrollArea()
        scroll.setWidget(content)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        # Page-level scrolling has no visible bars: the mouse wheel / touchpad
        # still scroll it (the hidden scroll bar keeps working) when the
        # window is too short. Bars inside data tables/lists are unaffected.
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(scroll)

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_stats()

    def refresh_stats(self):
        """Re-read data/scan_log.jsonl - auto-scans append to it while the
        app runs, so the counts read at construction go stale."""
        stats = _gather_stats()
        self._threats_card.set_value(stats["threats"])
        self._suspicious_card.set_value(
            stats["suspicious"], variant="warn" if stats["suspicious"] else "default",
        )

    def set_realtime_state(self, active):
        """Connected to AutoScanController.realtime_state_changed."""
        self._apply_realtime_state("active" if active else "off")

    def _apply_realtime_state(self, state):
        status = {"starting": "starting", "active": "secured", "off": "unprotected"}[state]
        self._header.sub_label.setText(f"// system_status: {status} — welcome back, operator")
        self._hero.set_state(state, self._last_scan_text)

    def _build_stats_row(self, stats):
        row = QHBoxLayout()
        row.setSpacing(12)
        row.addWidget(StatCard("Files Scanned", stats["files_scanned"]))
        self._threats_card = StatCard("Threats Detected", stats["threats"])
        row.addWidget(self._threats_card)
        self._suspicious_card = StatCard(
            "Suspicious Items", stats["suspicious"],
            variant="warn" if stats["suspicious"] else "default",
        )
        row.addWidget(self._suspicious_card)
        row.addWidget(StatCard("Last Full Scan", stats["last_full_scan"]))
        return row

    def _build_integrity_strip(self):
        """App integrity: one compact row (the Dashboard has little spare
        height) - label, status, Check now. The changed/missing/extra file
        list is in the status tooltip. Read-only, so no confirm dialog."""
        card = Card()
        card.layout().setContentsMargins(20, 10, 20, 10)
        row = QHBoxLayout()
        row.setSpacing(14)
        title = QLabel("APP INTEGRITY")
        title.setObjectName("cardTitle")
        title.setFont(theme.letter_spaced_font(size=8, bold=True, spacing=2))
        row.addWidget(title)
        self._integrity_status = ElidedLabel()
        self._integrity_status.setFont(theme.letter_spaced_font(size=8, spacing=0.3))
        row.addWidget(self._integrity_status, 1)
        self._integrity_button = Button("Check now")
        self._integrity_button.setToolTip("Compare DEVADARA's own program files with its signed "
                                          "manifest again. Only reads files - changes nothing.")
        self._integrity_button.clicked.connect(self.integrity_check_requested)
        row.addWidget(self._integrity_button)
        card.content_layout.addLayout(row)
        self._integrity_card = card
        self._show_integrity("WAITING — the self-check runs shortly after startup", "TEXT_DIM",
                             "DEVADARA compares its own program files with its signed manifest.")
        return card

    def _show_integrity(self, text, token, tooltip):
        color = getattr(theme, token)
        self._integrity_status.setText(text)
        self._integrity_status.setToolTip(tooltip)
        self._integrity_status.setStyleSheet(f"color: {color};")
        self._integrity_card.set_accent(theme.NEON if token in ("NEON", "TEXT_DIM") else color)

    def set_integrity_checking(self):
        """IntegrityChecker.started."""
        self._integrity_button.setEnabled(False)
        self._show_integrity("CHECKING — comparing DEVADARA's files with its signed manifest…",
                             "TEXT_DIM", "Only reads files - changes nothing.")

    def set_integrity_result(self, result):
        """IntegrityChecker.finished. Never raises on an odd result."""
        self._integrity_button.setEnabled(True)
        try:
            self._show_integrity(*integrity_summary(result or {}))
        except Exception as exc:
            self._show_integrity(f"CHECK COULDN'T RUN — {exc}", "WARN", "")

    def _build_quick_actions(self):
        card = Card(title="Quick Actions", badge=f"[{len(QUICK_ACTIONS)}]")
        grid = QGridLayout()
        grid.setSpacing(12)

        for col, (icon, title, nav_index, scan_mode) in enumerate(QUICK_ACTIONS):
            action = ActionCard(icon, title)
            action.clicked.connect(lambda index=nav_index, mode=scan_mode: self._navigate(index, mode))
            grid.addWidget(action, 0, col)
            grid.setColumnStretch(col, 1)

        card.content_layout.addLayout(grid)
        return card
