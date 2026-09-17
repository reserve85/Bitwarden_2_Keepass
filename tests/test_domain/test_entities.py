"""Domain entity tests - dataclass defaults, enum member regression."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from app.domain.entities import (
    CopyOutcome,
    ExportPhase,
    ExportProgress,
    ExportRequest,
    ExportResult,
    LogCategory,
    LogLevel,
    TwoFactorRequired,
    UpdateCheckInfo,
)

_EXPECTED_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_EXPECTED_CATEGORIES = {
    "STARTUP",
    "SHUTDOWN",
    "AUTH",
    "TOTP",
    "SYNC",
    "EXPORT",
    "KDBX",
    "COPY",
    "CONFIG",
    "UPDATE",
    "GUI",
    "SECURITY",
    "ERROR",
    "WIPE",
}
_EXPECTED_PHASES = {
    "LOGIN",
    "SYNC",
    "FOLDERS",
    "ITEMS",
    "SAVE",
    "VERIFY",
    "COPY",
    "DONE",
}


def test_enums_expose_members__regression() -> None:
    """A bare comma-list in an Enum class body is a discarded EMPTY enum."""
    assert {member.name for member in LogLevel} == _EXPECTED_LEVELS
    assert {member.name for member in LogCategory} == _EXPECTED_CATEGORIES
    assert {member.name for member in ExportPhase} == _EXPECTED_PHASES


def test_log_level_values_are_uppercase_names() -> None:
    for member in LogLevel:
        assert member.value == member.name


def test_log_category_value_matches_name() -> None:
    for member in LogCategory:
        assert member.value == member.name


def test_export_phase_value_matches_name() -> None:
    for member in ExportPhase:
        assert member.value == member.name


def test_export_progress_defaults_and_fields() -> None:
    progress = ExportProgress(
        phase=ExportPhase.LOGIN,
        current=0,
        total=0,
        message="Logging in",
    )
    assert progress.fraction == 0.0
    assert progress.phase == ExportPhase.LOGIN
    assert progress.current == 0
    assert progress.total == 0
    assert progress.message == "Logging in"


def test_copy_outcome_defaults() -> None:
    outcome = CopyOutcome(destination="C:\\out", copied=True)
    assert outcome.skipped is False
    assert outcome.error == ""
    assert outcome.sha256 == ""


def test_export_result_defaults() -> None:
    result = ExportResult(path="C:\\out\\file.kdbx", copies=[])
    assert result.source_deleted is False


def test_update_check_info_fields() -> None:
    info = UpdateCheckInfo(
        has_update=True,
        latest_version="1.2.0",
        download_url="https://example.com/v1.2.0",
        release_notes="sha256: abc",
        error="",
    )
    assert info.has_update is True
    assert info.latest_version == "1.2.0"
    assert info.download_url.startswith("https://")
    assert info.release_notes
    assert info.error == ""


def test_export_request_default_and_fields() -> None:
    request = ExportRequest(
        url="https://bitwarden.eu",
        email="u@example.com",
        session="session",
        master_password="pw",
        output_folder=Path("C:\\out"),
        target_folders=(),
    )
    assert request.delete_after_copy is False
    assert request.url == "https://bitwarden.eu"
    assert request.email == "u@example.com"
    assert request.session == "session"
    assert request.master_password == "pw"
    assert request.target_folders == ()


def test_dataclasses_are_frozen_and_slotted() -> None:
    progress = ExportProgress(ExportPhase.DONE, 1, 1, "Done")
    with pytest.raises(FrozenInstanceError):
        progress.current = 5  # type: ignore[misc]
    assert not hasattr(progress, "__dict__")

    outcome = CopyOutcome(destination="dest", copied=True)
    with pytest.raises(FrozenInstanceError):
        outcome.copied = False  # type: ignore[misc]
    assert not hasattr(outcome, "__dict__")


def test_two_factor_required_is_runtime_error() -> None:
    assert issubclass(TwoFactorRequired, RuntimeError)
    with pytest.raises(TwoFactorRequired):
        raise TwoFactorRequired("Two-step login required")
