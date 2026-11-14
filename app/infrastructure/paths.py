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
    """App-owned bw data folder - wiped at startup and shutdown.

    Every bw invocation runs with ``BITWARDENCLI_APPDATA_DIR`` pointed here
    (see :class:`app.infrastructure.bw.bw_cli.BwCli`), so the bw CLI never
    reads or writes the user's own bw profile.
    """
    return app_base_dir() / "bw_data"


def resource_path(name: str) -> Path:
    """Path of a read-only file shipped in ``app/resources``.

    In a frozen one-file build the resources are unpacked into PyInstaller's
    temporary bundle directory (``sys._MEIPASS``), not next to the EXE - the
    release build bundles them there via ``--add-data``.
    """
    bundle_dir = getattr(sys, "_MEIPASS", None)
    root = Path(bundle_dir) if bundle_dir else Path(__file__).resolve().parents[2]
    return root / "app" / "resources" / name


def lock_file() -> Path:
    return app_base_dir() / "bitwarden2keepass.lock"
