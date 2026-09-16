"""CopyToTargetsUseCase tests - real OutputHandler over tmp dirs.

The copy use case talks to the OutputPort, and the real OutputHandler is the
cheapest honest implementation: the safety-critical delete rules exercise real
files without any mocking.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.application.use_cases.output import CopyToTargetsUseCase
from app.domain.entities import CopyOutcome, ExportPhase
from app.infrastructure.output.output_handler import OutputHandler
from tests.fakes import FakeOverwriteAnswers, RecordingLogger

if TYPE_CHECKING:
    from pathlib import Path

_PAYLOAD = b"kdbx-content-bytes"


def _write_source(tmp_path: Path) -> Path:
    source = tmp_path / "20240101_bitwarden_export.kdbx"
    source.write_bytes(_PAYLOAD)
    return source


def _run_copy(
    source: Path,
    targets: list[Path],
    *,
    delete_after_copy: bool = False,
    overwrite: FakeOverwriteAnswers | None = None,
) -> tuple[list[CopyOutcome], list[ExportPhase]]:
    progress_phases: list[ExportPhase] = []
    use_case = CopyToTargetsUseCase(OutputHandler(overwrite), RecordingLogger())

    result = use_case.run(
        source,
        targets,
        delete_after_copy=delete_after_copy,
        progress_cb=lambda p: progress_phases.append(p.phase),
    )
    return result.copies, progress_phases


def test_copy_to_targets_copies_and_verifies(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    targets = [tmp_path / "a", tmp_path / "b"]

    copies, phases = _run_copy(source, targets)

    assert len(copies) == len(targets)
    assert all(outcome.copied for outcome in copies)
    assert all(outcome.sha256 for outcome in copies)
    assert (targets[0] / source.name).read_bytes() == _PAYLOAD
    assert (targets[1] / source.name).read_bytes() == _PAYLOAD
    assert ExportPhase.COPY in phases


def test_copy_overwrite_answers_drive_skip_and_replace(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    first_dir = tmp_path / "first"
    first_dir.mkdir()
    (first_dir / source.name).write_bytes(b"old-content")
    second_dir = tmp_path / "second"
    second_dir.mkdir()
    (second_dir / source.name).write_bytes(b"old-content")
    overwrite = FakeOverwriteAnswers([False, True])

    copies, _ = _run_copy(source, [first_dir, second_dir], overwrite=overwrite)

    assert copies[0].skipped
    assert not copies[0].copied
    assert copies[1].copied  # second ask answered True, replaces the file
    assert (first_dir / source.name).read_bytes() == b"old-content"
    assert (second_dir / source.name).read_bytes() == _PAYLOAD


def test_copy_never_deletes_source_without_opt_in(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    target = tmp_path / "dest"

    _, _ = _run_copy(source, [target], delete_after_copy=False)

    assert source.exists()
    assert copies_to(target, source)


def test_copy_deletes_source_only_after_success(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    target = tmp_path / "dest"

    copies, _ = _run_copy(source, [target], delete_after_copy=True)

    assert copies[0].copied
    assert not source.exists()
    assert (target / source.name).exists()


def test_copy_never_deletes_source_when_no_target_succeeded(tmp_path: Path) -> None:
    source = _write_source(tmp_path)

    # A file in place of a directory makes the copy fail for every target.
    blocking = tmp_path / "blocker"
    blocking.write_text("i am a file, not a directory")
    copies, _ = _run_copy(source, [blocking / "nested"], delete_after_copy=True)

    assert all(not outcome.copied for outcome in copies)
    assert source.exists()  # the only export survives


def test_copy_never_deletes_source_when_no_targets(tmp_path: Path) -> None:
    source = _write_source(tmp_path)

    copies, _ = _run_copy(source, [], delete_after_copy=True)

    assert copies == []
    assert source.exists()


def test_copy_targets_are_deduplicated(tmp_path: Path) -> None:
    source = _write_source(tmp_path)

    copies, _ = _run_copy(source, [tmp_path / "x", tmp_path / "x", tmp_path / "x"])

    assert len(copies) == 1


def copies_to(directory: Path, source: Path) -> bool:
    return (directory / source.name).exists()
