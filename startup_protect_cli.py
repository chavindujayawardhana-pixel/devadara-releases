"""
startup_protect_cli.py

Thin launcher for devadara/startup_protect.py, following the same shape as
the project's other top-level *_cli.py entry points (scan_cli.py,
monitor_cli.py, ...). This file exists specifically so Windows can launch
it by an absolute path (see devadara/startup_registration.py) - Python
inserts THIS script's own directory (the project root) onto sys.path when
it runs, which is what makes "from devadara.x import y" resolve, regardless
of whatever working directory Windows happened to start the process in.
"""

from devadara.startup_protect import main

if __name__ == "__main__":
    main()
