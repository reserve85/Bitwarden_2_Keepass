"""Bundled resources - the window icon must be loadable in dev and frozen builds."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtGui import QIcon

from app.infrastructure import paths

if TYPE_CHECKING:
    import pytest

_RELEASE_WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "release.yml"


def test_window_icon_exists_and_loads() -> None:
    """Regression: no window icon was set, so the title bar showed Qt's default."""
    icon_path = paths.resource_path("Icon.ico")

    assert icon_path.is_file()
    assert not QIcon(str(icon_path)).isNull()


def test_frozen_build_reads_resources_from_the_bundle_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("sys._MEIPASS", str(tmp_path), raising=False)

    assert paths.resource_path("Icon.ico") == tmp_path / "app" / "resources" / "Icon.ico"


def test_release_build_bundles_the_icon_where_the_app_looks_for_it() -> None:
    """The one-file EXE only contains what PyInstaller is told to add."""
    workflow = _RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert '--add-data "app/resources/Icon.ico;app/resources"' in workflow
