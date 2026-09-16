"""AppPaths tests - base dir resolution (dev vs frozen) and folder layout."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from app.infrastructure import paths

if TYPE_CHECKING:
    import pytest


def test_app_base_dir_is_the_repo_root() -> None:
    base = paths.app_base_dir()
    assert (base / "app" / "main.py").is_file()
    assert (base / "pyproject.toml").is_file()


def test_runtime_folders_live_under_the_base_dir() -> None:
    base = paths.app_base_dir()
    assert paths.config_dir().parent == base
    assert paths.config_file().parent == base / "config"
    assert paths.config_file().name == "app_config.yaml"
    assert paths.output_dir().parent == base
    assert paths.bw_data_dir().parent == base


def test_frozen_build_resolves_to_the_exe_director(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.frozen", True, raising=False)
    monkeypatch.setattr("sys.executable", "C:/fake/app/Bitwarden2KeePass.exe")

    assert paths.app_base_dir() == Path("C:/fake/app")

    monkeypatch.setattr("sys.frozen", False, raising=False)
    monkeypatch.setattr("sys.executable", "C:/Python/python.exe")

    assert paths.app_base_dir() == Path(__file__).resolve().parents[2]
