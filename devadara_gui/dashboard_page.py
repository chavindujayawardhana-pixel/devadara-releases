"""
dashboard_page.py

Phase 2: the Dashboard page's real content - hero status card, stats row,
and Quick Actions - wired to whatever real backend data actually exists.

Data-source investigation (see the Phase 2 plan for the full table):
real-time protection state (devadara.startup_registration.is_in_startup())
and threat/suspicious counts (devadara.scan_log.read_findings()) are real
and live. Nothing in the backend currently persists a "files scanned"
running total or a "last scan" timestamp for any of the interactive scan
tools (scan_cli.py, full_drive_scan_cli.py, downloads_scan_cli.py,
usb_scan_cli.py never write to scan_log.jsonl - only the unattended
startup_protect.py sweep does, and only for notable findings, never a
clean-scan tally) - those two show an honest empty state ("—" / "Never")
rather than a fake or stale number.
"""

from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QVBoxLayout, QWidget

from devadara import scan_log
from devadara.startup_registration import is_in_startup

from devadara_gui.components import ActionCard, Card, HeroStatusCard, PageHeader, StatCard

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


def _gather_stats():
    """Pull real values from the backend. Returns a dict - see module
    docstring for which two fields have no real backend source yet."""
    findings = scan_log.read_findings()
    threats = sum(1 for entry in findings if entry.get("tier") in THREAT_TIERS)
    suspicious = sum(1 for entry in findings if entry.get("tier") == "suspicious")

    return {
        "protected": is_in_startup(),
        "files_scanned": "—",  # no backend source yet
        "threats": threats,
        "suspicious": suspicious,
        "last_full_scan": "Never",  # no backend source yet
    }


class DashboardPage(QWidget):
    def __init__(self, navigate, parent=None):
        """navigate: callable(index) - switches both the content stack and
        the sidebar's active nav item to the given page index (see
        MainWindow.navigate_to)."""
        super().__init__(parent)
        self._navigate = navigate

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 30, 40, 60)
        layout.setSpacing(20)

        stats = _gather_stats()

        header = PageHeader(
            "Dashboard",
            "// system_status: {} — welcome back, operator".format(
                "secured" if stats["protected"] else "unprotected"
            ),
        )
        layout.addWidget(header)

        self._hero = HeroStatusCard()
        self._hero.set_state(stats["protected"], stats["last_full_scan"])
        layout.addWidget(self._hero)

        layout.addLayout(self._build_stats_row(stats))
        layout.addWidget(self._build_quick_actions())
        layout.addStretch(1)

    def _build_stats_row(self, stats):
        row = QHBoxLayout()
        row.setSpacing(12)
        row.addWidget(StatCard("Files Scanned", stats["files_scanned"]))
        row.addWidget(StatCard("Threats Detected", stats["threats"]))
        row.addWidget(StatCard(
            "Suspicious Items", stats["suspicious"],
            variant="warn" if stats["suspicious"] else "default",
        ))
        row.addWidget(StatCard("Last Full Scan", stats["last_full_scan"]))
        return row

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
