"""App directory/path resolution (reference ``paths.py`` port).

The base dir differs between dev runs and frozen (PyInstaller) builds:
- dev: repository root (where ``config/`` and ``output/`` live)
- frozen: the EXE's own folder

All runtime data (config, exports, per-export bw data) stays under the base
dir so a portable ZIP can be moved around without touching user folders.
"""

from __future__ import annotations

import sys
from pathlib import Path


def app_base_dir() -> Path:
    """The app's own directory (EXE folder when frozen, repo root in dev)."""
    if getattr(sys, "frozen", False):  # PyInstaller
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def config_dir() -> Path:
    return app_base_dir() / "config"


def config_file() -> Path:
    return config_dir() / "app_config.yaml"


def output_dir() -> Path:
    return app_base_dir() / "output"


def bw_data_dir() -> Path:
    """App-owned bw data folder - created per export and wiped afterwards.

    Every bw invocation runs with ``BW_DATA_FOLDER``/``BW_CONFIG_FILE`` pointed
    here (see :class:`app.infrastructure.bw.bw_cli.BwCli`), so the bw CLI never
    writes vault data/session state into the user's own bw config.
    """
    return app_base_dir() / "bw_data"


def lock_file() -> Path:
    return app_base_dir() / "bitwarden2keepass.lock"
