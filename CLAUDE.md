# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

DEVADARA is a Windows-only antivirus/EDR tool written in Python. It has no
formal package structure (no setup.py/pyproject.toml) — the `devadara/`
package holds all detection logic, each top-level `*_cli.py` script is a
thin, manually-run interactive entry point over that logic, and
`devadara_gui/` (launched by `gui_app.py`) is the PySide6 desktop app over
the same logic — see "The GUI" below. (The original GUI was removed on
2026-09-18 and rebuilt from scratch; `devadara_gui/` is the rebuild.)

## Running things

There's no test runner, build step, or lint config in this repo. Everything
is run directly with the venv's Python from the project root (imports rely
on `devadara/` being resolvable from the working directory, or on the
`*_cli.py` script's own directory being on `sys.path`):

```
venv\Scripts\python.exe gui_app.py                # the desktop app (single instance; X hides to the tray)
venv\Scripts\pythonw.exe gui_app.py --autostart   # what Windows runs at sign-in: auto-hides, startup scan after 60 s
venv\Scripts\python.exe scan_cli.py              # hash-scan a folder, prompts to quarantine matches
venv\Scripts\python.exe ml_scan_cli.py            # ML layer only, in isolation (no hash/signature)
venv\Scripts\python.exe downloads_scan_cli.py     # watch Downloads, full pipeline on every new file
venv\Scripts\python.exe usb_scan_cli.py           # watch for USB drives, full pipeline on every file
venv\Scripts\python.exe full_drive_scan_cli.py    # on-demand whole-drive scan (Quick/Full)
venv\Scripts\python.exe persistence_scan_cli.py   # scan registry Run keys / scheduled tasks / services
venv\Scripts\python.exe process_scan_cli.py       # sweep running processes for behavioral tells
venv\Scripts\python.exe monitor_cli.py            # watch a folder for ransomware-like burst activity
venv\Scripts\python.exe quarantine_cli.py list|restore <id>|delete <id>
venv\Scripts\python.exe startup_cli.py enable|disable|status|review-log
```

`python -m devadara.train_model` retrains the ML model — this is a manual,
one-off step (see "train once, bundle, never retrain automatically" below);
nothing in the app itself calls it.

Manual behavior-monitor test (two terminals): run `monitor_cli.py` watching
a folder in one, then `python tests/simulate_ransomware.py` in the other —
it mimics ransomware's file-activity *pattern* (fast bulk rewrites/renames)
without doing anything actually harmful.

There is no pytest suite. `tests/simulate_ransomware.py` is a manual
integration script, not an automated test.

## The GUI (`devadara_gui/`)

`gui_app.py` is the entry point (single-instance guard, `--autostart`
handling, `multiprocessing.freeze_support()`). `main_window.py` holds
`MainWindow`: sidebar + page stack (Dashboard, Scan, Protection; Results and
Settings are still placeholders), the tray icon, and the scan-running orbit
animation (`components.ScanOrbitLogo` in the sidebar, `TrayOrbitAnimator`
on the tray; layers `assets/app_icon_base.png` + `app_icon_orbit.png`).
Colours/sizes are tokens in `theme.py` — don't add new colours.

- **Scanning** — `scan_page.py` queues every scan (manual, Downloads/USB
  auto-scan, the `--autostart` startup sweep) and runs one at a time in a
  `scan_worker.ScanWorker` on a `QThread`, always through
  `scan_engine.evaluate_file()`. Two calls must stay on the GUI thread
  (they hang on a QThread on this machine): loading the ML model and
  `persistence_scanner.list_persistence_entries()` — see `scan_worker.py`.
  Auto-scan findings are logged to `data/scan_log.jsonl` (`log_source` on
  the request; manual scans are not logged) and raise a tray message while
  the window is hidden.
- **Watchers** — `auto_scan_controller.AutoScanController` wraps
  `downloads_monitor`, `usb_monitor` and `behavior_monitor`; each is a
  Protection-page toggle saved in `data/gui_state.json` (`config_store.py`)
  and counts toward the sidebar's REAL-TIME status. Watcher callbacks fire
  on background threads and only emit Qt signals.
- **Behavior alerts** — `behavior_alert_popup.py` shows "possible
  ransomware-like activity" with the suspected programs (best-effort; often
  empty on a busy PC). Suspend/Resume/Kill each need a confirmation dialog
  and go through `process_guard.ProcessGuard`, which refuses Windows' own
  processes, anything under `%SystemRoot%`, DEVADARA itself and recycled
  PIDs (start time re-checked). Every attempt is logged to
  `data/process_actions.jsonl`.

## Architecture: the detection pipeline

`devadara/scan_engine.py::evaluate_file()` is the single pipeline every
scanning entry point funnels through (`usb_scan_cli.py`,
`downloads_scan_cli.py`, `persistence_scan_cli.py`, `process_scan_cli.py`,
`full_drive_scan_cli.py`/`drive_scanner.py`, `startup_protect.py`, the
GUI's `devadara_gui/scan_worker.py`) — it's
implemented exactly once and must stay that way. Four layers run in a fixed
order, each only firing if the previous one didn't already reach a verdict:

1. **Hash check** (`hash_scanner.py`) — SHA256 against
   `data/known_bad_hashes.json` (bundled) + `data/memory_hashes.json`
   (grows at runtime via `memory.py` whenever a threat is confirmed).
   Exact match only; runs against every file regardless of type.
2. **YARA check** (`yara_scanner.py`) — shells out to bundled
   `tools/yara64.exe` (no `yara-python` wheel exists for this project's
   Python 3.14) against every `.yar`/`.yara` file in `data/yara_rules/`.
   Also runs against every file regardless of type — it's the only layer
   that inspects non-executables (scripts, documents, ransom notes). A
   rule's `severity="high"` meta is decisive like a hash match;
   `severity="suspicious"` sets a **floor** — later layers can push the
   verdict higher but nothing (not even a fully trusted signature) can
   push it back down below "suspicious".
3. **Digital signature check** (`signature_scanner.py`) — shells out to
   PowerShell's `Get-AuthenticodeSignature` (no native Authenticode
   support in Python). Only runs for executable-shaped files
   (`scan_engine.EXECUTABLE_EXTENSIONS`) since each check costs ~1-4s. A
   full chain-trusted, non-expired signature short-circuits straight to
   `trusted_signed`, skipping ML entirely — this is what prevents the ML
   layer's structural heuristics from false-positiving a legitimate but
   unusually-structured executable. A signature whose chain does NOT
   validate but whose claimed publisher name matches
   `data/trusted_publishers.json` is a much weaker signal: it can only
   downgrade an ML `malware` verdict to `suspicious`, never grant `safe`.
4. **ML check** (`ml_scanner.py`) — last resort, only for files that
   reached this point unresolved. Loads a pre-trained
   `RandomForestClassifier` (`models/malware_model.joblib` +
   `models/feature_columns.json`, produced once by `train_model.py`, never
   retrained at runtime) and extracts 52 raw PE header fields via
   `pefile`. Returns a **tiered** confidence rather than a binary verdict:
   `malware` (>=85%), `suspicious` (60-85%, needs manual review), `safe`
   (<60%).

Every layer that shells out to an external process (PowerShell, yara64.exe)
binds untrusted input (file paths) as a separate process argument /
parameter, never string-concatenated into command text — preserve this
pattern in any new shell-out code; it's what prevents a malicious filename
from becoming a command injection vector. Every such call also passes
`**hidden_process.hidden_window_kwargs()` (`CREATE_NO_WINDOW` + `SW_HIDE`
on Windows, `{}` elsewhere) — under `pythonw` there's no parent console, so
without it each child pops up a visible console window.

A failure inside any one layer (locked file, missing binary, timeout)
degrades to "this layer found nothing" rather than raising or aborting the
whole scan — errors in optional layers should never block the rest of the
pipeline.

## Other layers, outside the main pipeline

- **`persistence_scanner.py`** — enumerates registry Run/RunOnce keys,
  Scheduled Tasks, and auto-start Services (what Windows will run on its
  own, vs. what a scan happens to look at right now), then feeds each
  resolved target executable through the same `scan_engine` pipeline.
- **`process_scanner.py`** — psutil-metadata-only sweep of running
  processes for behavioral tells (wrong-folder process names, user-writable
  "drop" locations, a document/browser process spawning a shell, a vanished
  backing .exe) — deliberately not yara-on-PID (proven slow and noisy).
  Flagged processes' .exe still goes through `scan_engine`.
- **`behavior_monitor.py`** — `watchdog`-based rolling-window detector for
  ransomware-like *bursts* of file activity (many files changed very fast),
  not per-file judgment; on trigger, uses `psutil` to guess which process
  has files open in the affected folder.
- **`downloads_monitor.py`** / **`usb_monitor.py`** — reactive, per-file
  watchers (new file arrives -> scan immediately) feeding the same
  `scan_engine` pipeline; downloads_monitor specifically waits for the
  browser's temp-name -> final-name rename rather than reacting to the
  temp file.
- **`quarantine.py`** — neutralizes a confirmed threat by Fernet-encrypting
  it and moving it out of place (never deleting outright); always
  reversible via `restore_file()` except `delete_permanently()`, which
  nothing in the codebase calls without you typing the id yourself at a
  CLI prompt.
- **`memory.py`** / **`scan_log.py`** — `memory.py` is the growing
  confirmed-threat hash list (`data/memory_hashes.json`) fed back into the
  hash-check layer; `scan_log.py` is the append-only unattended-findings
  log (`data/scan_log.jsonl`) written instead of prompting, since nobody's
  there to answer a prompt. Entries are built only by
  `scan_log.record_scan_result()` / `record_behavior_alert()`, shared by the
  GUI and `startup_protect.py` so the format can't drift; the Dashboard's
  counts and `startup_cli.py review-log` read it. Confirmed process actions
  go to a separate `data/process_actions.jsonl` (not findings).
- **`startup_registration.py`** — registers DEVADARA under the per-user
  `HKCU...\Run` key (no admin rights needed, visible/removable via Task
  Manager's Startup Apps tab) to launch `gui_app.py --autostart` via
  `pythonw.exe` at logon. That unattended path never auto-confirms a
  threat: it scans, logs to `scan_log.jsonl` and notifies, for later review
  via `startup_cli.py review-log`.
- **`startup_protect.py`** / **`startup_protect_cli.py`** — CLI-only /
  manual now (no longer launched at logon): the older console version of
  the same startup sweep + watchers, notifying via PowerShell toasts
  (`notifier.py`).

## Project rules worth preserving

- **Never auto-confirm a threat.** Every destructive/consequential action
  (quarantine, kill/suspend a process, delete-permanently) requires an
  explicit human "y" (or, for `quarantine_cli.py delete`, a typed `DELETE`)
  at an interactive CLI prompt — or, in the GUI, an explicit click in a
  confirmation dialog whose default button is Cancel. Unattended paths (GUI
  auto-scans, the startup sweep, behavior alerts, `startup_protect.py`)
  deliberately only *log and notify* — they never act on a finding.
- **Train once, bundle, never retrain automatically.** `train_model.py` is
  a manual, one-time script; nothing else in the app calls it, and it must
  stay that way.
- **`scan_engine.evaluate_file()` is the one true pipeline.** Don't
  reimplement the Hash -> YARA -> Signature -> ML sequence anywhere else;
  add a new scanning entry point by calling into it.
- **A YARA "suspicious" match is a floor, never erased.** See point 2 above
  — concrete evidence in a file shouldn't be silently overridden by a trust
  signal from a later layer.
- **A trusted-publisher-name match (unlike a real trusted signature) is
  weak.** It can only downgrade `malware` -> `suspicious`, never grant
  `safe` — a certificate's claimed name can be forged even when its chain
  doesn't validate.
- File paths passed to any shelled-out process (PowerShell, yara64.exe)
  must be bound as separate arguments/parameters, never interpolated into
  command/script text.
