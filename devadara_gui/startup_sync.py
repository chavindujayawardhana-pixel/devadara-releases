"""
startup_sync.py

Keeps the Windows Registry Run-key entry (devadara.startup_registration)
in sync with the "Windows Startup" toggle on the Protection page and the
app's actual current install location, across every GUI launch - call
once per launch, before the window is shown.

Registers once by default on the very first launch ever (or the first
launch since this feature shipped), then on every later launch either
refreshes the registered command if the app moved (e.g. after a
reinstall) or leaves it alone if the user has explicitly turned the
toggle off - it never fights that choice by re-adding the entry itself.

That same refresh is also what upgrades an entry registered by an older
version to the current command format (e.g. one written before the
--autostart flag existed): add_to_startup() always overwrites the value
with _resolve_launch_command()'s current output.
"""

from devadara import startup_registration


def sync_startup_registration(config_store):
    if not config_store.get("startup_setup_done", False):
        startup_registration.add_to_startup()
        config_store.set("startup_setup_done", True)
        return

    if startup_registration.is_in_startup():
        startup_registration.add_to_startup()
