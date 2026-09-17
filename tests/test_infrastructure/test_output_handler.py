"""OutputHandler tests - sha256 content verification, overwrite callback, delete."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from app.infrastructure.output.output_handler import OutputHandler
from tests.fakes import FakeOverwriteAnswers

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

_PAYLOAD = b"kdbx-binary-content\x00\x01\x02"


def _write_source(tmp_path: Path) -> Path:
    source = tmp_path / "source.kdbx"
    source.write_bytes(_PAYLOAD)
    return source


def _expected_sha256() -> str:
    return hashlib.sha256(_PAYLOAD).hexdigest()


def test_file_sha256_matches_reference_hash(tmp_path: Path) -> None:
    source = _write_source(tmp_path)

    assert OutputHandler().file_sha256(source) == _expected_sha256()


def test_copy_copies_and_verifies_content(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    destination = tmp_path / "dest" / source.name

    outcomes = OutputHandler().copy(source, [destination])

    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.copied
    assert outcome.sha256 == _expected_sha256()
    assert destination.read_bytes() == _PAYLOAD


def test_copy_skips_existing_file_without_overwrite_consent(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    destination = tmp_path / "dest" / source.name
    destination.parent.mkdir()
    destination.write_bytes(b"old")

    outcomes = OutputHandler().copy(source, [destination])

    assert outcomes[0].skipped
    assert not outcomes[0].copied
    assert destination.read_bytes() == b"old"


def test_copy_overwrites_existing_file_on_consent(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    destination = tmp_path / "dest" / source.name
    destination.parent.mkdir()
    destination.write_bytes(b"old")

    answers = FakeOverwriteAnswers([True])
    outcomes = OutputHandler(answers).copy(source, [destination])

    assert outcomes[0].copied
    assert destination.read_bytes() == _PAYLOAD
    assert answers.asked == [str(destination)]


def test_copy_continues_when_one_target_fails(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    good_destination = tmp_path / "good" / source.name
    # A regular file in place of a directory makes the copy fail.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir")

    outcomes = OutputHandler().copy(source, [blocker / "nested" / source.name, good_destination])

    assert not outcomes[0].copied
    assert outcomes[0].error
    assert outcomes[1].copied


def test_copy_flags_checksum_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A corrupted destination (different content, same name) must be flagged."""
    source = _write_source(tmp_path)
    target = tmp_path / "dest"

    monkeypatch.setattr(
        "app.infrastructure.output.output_handler.OutputHandler.file_sha256",
        lambda _self, path: _expected_sha256() if path == source else "deadbeef",
    )

    outcomes = OutputHandler().copy(source, [target])

    assert not outcomes[0].copied
    assert "Checksum mismatch" in outcomes[0].error


def test_delete_source_removes_file_and_tolerates_missing(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    handler = OutputHandler()

    handler.delete_source(source)
    assert not source.exists()

    handler.delete_source(source)  # missing_ok=True, must not raise
