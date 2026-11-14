"""Composition-root tests - build_services wiring, live bw path,
overwrite-prompt wiring and the excepthook (none of these spawned a subprocess).

The real ``build_services`` is exercised here with the app-owned paths pointed
at a temp dir so the repo's own ``config/``/``output/``/``bw_data/`` are never
touched.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import app.main as main_module
from app.main import (
    _install_excepthook,
    _wire_export_use_case,
    build_services,
)

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

    from app.main import Services
    from tests.fakes import RecordingLogger

#: The composition root's single source for the delayed startup update check.
_EXPECTED_UPDATE_DELAY_MS = 2000


def _build_services(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Services:
    """Isolated services: all app-owned paths land under a temp dir."""
    monkeypatch.setattr(
        main_module,
        "config_file",
        lambda: tmp_path / "config" / "app_config.yaml",
    )
    monkeypatch.setattr(main_module, "bw_data_dir", lambda: tmp_path / "bw_data")
    return build_services()


def test_build_services_wires_the_full_service_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    services = _build_services(tmp_path, monkeypatch)

    # Ports + use cases are all present; the export use case is filled by
    # _wire_export_use_case once the MainWindow exists (prompt dependency).
    assert services.logger is not None
    assert services.bw_cli is not None
    assert services.login_use_case is not None
    assert services.check_updates_use_case is not None
    assert services.apply_update_use_case is not None
    assert services.export_use_case is None
    assert services.update_check_delay_ms == _EXPECTED_UPDATE_DELAY_MS
    # The PATH-hijack warning must ride the services seam (presentation never
    # imports infrastructure).
    assert callable(services.bw_warning)
    assert services.bw_data_dir == tmp_path / "bw_data"


def test_wire_export_use_case_fills_seam_and_wires_overwrite_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    services = _build_services(tmp_path, monkeypatch)
    asked: list[Path] = []

    def prompt(destination: Path) -> bool:
        asked.append(destination)
        return False  # never overwrite

    _wire_export_use_case(services, prompt)

    assert services.export_use_case is not None
    # The callback is wired into the OutputPort: a pre-existing destination is
    # skipped (False) exactly once and recorded as such.
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    source = out_dir / "20240101_bitwarden_export.kdbx"
    source.write_bytes(b"new")
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    destination = target_dir / source.name
    destination.write_bytes(b"existing")

    outcomes = services.output.copy(source, [destination])

    assert asked == [destination]
    assert outcomes[0].skipped is True
    assert outcomes[0].copied is False


def test_bw_path_change_in_settings_applies_without_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: the bw adapter used to keep the path it was started with."""
    services = _build_services(tmp_path, monkeypatch)
    assert services.bw_cli._bw_path == "bw"  # noqa: SLF001

    services.settings_use_case.update({"bitwarden.bw_path": "/opt/bw/bw"})

    assert services.bw_cli._bw_path == "/opt/bw/bw"  # noqa: SLF001
    assert services.bw_path() == "/opt/bw/bw"


def test_excepthook_logs_redacted_unhandled_exceptions(logger: RecordingLogger) -> None:
    _install_excepthook(logger)
    try:
        sys.excepthook(RuntimeError, RuntimeError("boom password=supersecret"), None)
    finally:
        sys.excepthook = sys.__excepthook__

    assert any("Unhandled exception" in message for message in logger.messages)
    # The handler redacts secret-like payloads before they reach the log.
    assert not any("supersecret" in message for message in logger.messages)
