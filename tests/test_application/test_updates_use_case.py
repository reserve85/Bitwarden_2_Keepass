"""Update use-case tests - check error handling + release-note sha256 gate."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from app.application.use_cases.updates import (
    ApplyUpdateUseCase,
    CheckForUpdatesUseCase,
    _extract_sha256,
)
from tests.fakes import FakeUpdatePort, RecordingLogger

if TYPE_CHECKING:
    from pathlib import Path

_EXE = b"the-new-exe-bytes"
_SHA256 = hashlib.sha256(_EXE).hexdigest()


def _notes_with_sha256(content: bytes = _EXE) -> str:
    digest = hashlib.sha256(content).hexdigest()
    # Matches the exact marker ``release.yml`` writes into every release body.
    return f"Release v1.1.0\nsha256 of Bitwarden2KeePass.exe: {digest}\nchangelog line"


def test_extract_sha256_parses_release_notes() -> None:
    assert _extract_sha256(_notes_with_sha256()) == _SHA256
    assert _extract_sha256("no checksum here") is None


def test_check_reports_available_update() -> None:
    port = FakeUpdatePort(
        check_result={
            "has_update": True,
            "latest_version": "v1.1.0",
            "download_url": "u",
            "release_notes": "n",
            "error": "",
        },
    )
    logger = RecordingLogger()

    result = CheckForUpdatesUseCase(port, logger).run()

    assert result["has_update"] is True
    assert any("Update available: v1.1.0" in m for m in logger.messages)


def test_check_without_update_logs_no_update() -> None:
    logger = RecordingLogger()

    CheckForUpdatesUseCase(FakeUpdatePort(), logger).run()

    assert any("No update available" in m for m in logger.messages)


def test_check_failure_is_not_reported_as_no_update() -> None:
    """The updater reports network errors in ``error`` - that is not "up to date"."""
    port = FakeUpdatePort(check_result={"has_update": False, "error": "Network error: offline"})
    logger = RecordingLogger()

    with pytest.raises(RuntimeError, match="offline"):
        CheckForUpdatesUseCase(port, logger).run()
    assert not any("No update available" in m for m in logger.messages)


def test_apply_refuses_when_the_release_check_failed() -> None:
    port = FakeUpdatePort(check_result={"error": "Network error: offline"})

    with pytest.raises(RuntimeError, match="offline"):
        ApplyUpdateUseCase(port, RecordingLogger()).run("https://example.com/exe.zip")
    assert port.calls == ["check"]


def test_apply_verifies_sha256_before_applying(tmp_path: Path) -> None:
    asset = tmp_path / "nightly.zip"
    asset.write_bytes(_EXE)
    port = FakeUpdatePort(
        check_result={
            "has_update": True,
            "latest_version": "v1.1.0",
            "download_url": "u",
            "release_notes": _notes_with_sha256(),
            "error": "",
        },
        download_path=str(asset),
    )

    ok = ApplyUpdateUseCase(port, RecordingLogger()).run("https://example.com/exe.zip")

    assert ok is True
    assert port.calls == ["check", "download https://example.com/exe.zip", "apply"]
    assert port.applied_paths == [str(asset)]


def test_apply_refuses_when_release_notes_lack_sha256(tmp_path: Path) -> None:
    asset = tmp_path / "nightly.zip"
    asset.write_bytes(_EXE)
    port = FakeUpdatePort(
        check_result={"release_notes": "release without a checksum"},
        download_path=str(asset),
    )

    with pytest.raises(RuntimeError, match="refused"):
        ApplyUpdateUseCase(port, RecordingLogger()).run("https://example.com/exe.zip")
    assert "apply" not in port.calls


def test_apply_refuses_on_checksum_mismatch(tmp_path: Path) -> None:
    asset = tmp_path / "nightly.zip"
    asset.write_bytes(b"corrupted-bytes")
    port = FakeUpdatePort(
        check_result={"release_notes": _notes_with_sha256(_EXE)},
        download_path=str(asset),
    )

    with pytest.raises(RuntimeError, match="does not match"):
        ApplyUpdateUseCase(port, RecordingLogger()).run("https://example.com/exe.zip")
    assert "apply" not in port.calls


def test_apply_download_failure_propagates() -> None:
    port = FakeUpdatePort(
        check_result={"release_notes": _notes_with_sha256()},
        download_path="",
        download_error="network down",
    )

    with pytest.raises(RuntimeError, match="network down"):
        ApplyUpdateUseCase(port, RecordingLogger()).run("https://example.com/exe.zip")
    assert "apply" not in port.calls
