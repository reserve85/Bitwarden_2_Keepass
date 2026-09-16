"""ExportVaultUseCase tests - fake bw + fake kdbx + real OutputHandler.

The export use case owns the sync and the kdbx lifecycle; these tests verify
the orchestration: phase progress, per-item resilience, attachment wiring and
the safety rule that the copy/delete step runs on the verified file.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from app.application.use_cases.export import ExportVaultUseCase
from app.domain.entities import ExportPhase, ExportProgress, ExportRequest
from app.infrastructure.output.output_handler import OutputHandler
from tests.fakes import FakeBwCli, RecordingLogger


class FakeKdbx:
    """In-memory KdbxPort fake recording entries and lifecycle calls."""

    def __init__(self, fail_on_items: set[str] | None = None) -> None:
        self.fail_on_items = fail_on_items or set()
        self.created_path: Path | None = None
        self.added: list[dict] = []
        self.saved_path: Path | None = None
        self.attachment_source: Any = None

    def create(self, path: Path, _master_password: str) -> object:
        self.created_path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        return "kp-handle"

    def load_folders(self, _kp: object, folders: list[dict]) -> dict[str | None, object]:
        groups: dict[str | None, object] = {None: object()}
        for folder in folders:
            groups[folder["id"]] = object()
        return groups

    def set_attachment_source(self, source: object) -> None:
        self.attachment_source = source

    def add_entry(
        self,
        _kp: object,
        _groups_by_id: dict[str | None, object],
        item: dict,
    ) -> None:
        if item.get("id") in self.fail_on_items:
            message = f"boom processing item {item.get('id')}"
            raise RuntimeError(message)
        self.added.append(item)

    def save(self, _kp: object, path: Path) -> None:
        self.saved_path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fake-kdbx-content")

    def verify(self, _path: Path, _master_password: str) -> int:
        return len(self.added)


def _request(tmp_path: Path, target_folders: tuple[Path, ...] = ()) -> ExportRequest:
    return ExportRequest(
        url="https://bitwarden.eu",
        email="user@example.com",
        session="session-fake",
        master_password="pw",
        output_folder=tmp_path / "out",
        target_folders=target_folders,
        delete_after_copy=False,
    )


def _make_use_case(
    bw: FakeBwCli,
    kdbx: FakeKdbx,
    logger: RecordingLogger,
) -> ExportVaultUseCase:
    return ExportVaultUseCase(
        bw_client_factory=lambda _session: bw,
        kdbx=kdbx,
        output=OutputHandler(),
        logger=logger,
    )


def _collector() -> tuple[list[ExportProgress], Any]:
    samples: list[ExportProgress] = []

    def collect(progress: ExportProgress) -> None:
        samples.append(progress)

    return samples, collect


def test_export_runs_full_flow(
    tmp_path: Path,
    sample_folders: list[dict],
    sample_items: list[dict],
) -> None:
    bw = FakeBwCli(folders=sample_folders, items=sample_items)
    target = tmp_path / "copy"
    logger = RecordingLogger()
    samples, collect = _collector()

    kdbx = FakeKdbx()
    use_case = _make_use_case(bw, kdbx, logger)
    result = use_case.run(_request(tmp_path, (target,)), collect)

    assert bw.calls.count("sync") == 1  # sync happens here (single owner)
    assert len(kdbx.added) == len(sample_items)
    assert kdbx.attachment_source is not None  # wired for real writers
    expected_name = f"{datetime.now():%Y%m%d}_bitwarden_export.kdbx"  # noqa: DTZ005 - local date in file name
    assert result.path.endswith(expected_name)
    result_path = Path(result.path)
    assert result_path.exists()
    assert result.copies
    assert result.copies[0].copied
    assert (target / expected_name).exists()
    phases = {sample.phase for sample in samples}
    assert {
        ExportPhase.SYNC,
        ExportPhase.FOLDERS,
        ExportPhase.ITEMS,
        ExportPhase.SAVE,
        ExportPhase.VERIFY,
        ExportPhase.COPY,
        ExportPhase.DONE,
    } <= phases


def test_export_skips_broken_item_and_continues(
    tmp_path: Path,
    sample_folders: list[dict],
    sample_items: list[dict],
) -> None:
    bw = FakeBwCli(folders=sample_folders, items=sample_items)
    kdbx = FakeKdbx(fail_on_items={"note-1"})
    logger = RecordingLogger()
    _, collect = _collector()
    use_case = _make_use_case(bw, kdbx, logger)

    result = use_case.run(_request(tmp_path), collect)

    assert len(kdbx.added) == len(sample_items) - 1
    assert Path(result.path).exists()
    log_text = " ".join(logger.messages)
    assert "Skipping item 'Recovery codes'" in log_text
    assert "ABC-123" not in log_text  # notes are never logged


def test_export_attachment_source_is_wired_to_bw(
    tmp_path: Path,
    sample_folders: list[dict],
    sample_items: list[dict],
) -> None:
    bw = FakeBwCli(
        folders=sample_folders,
        items=sample_items,
        attachment_payload=b"\x00\x01bin",
    )
    kdbx = FakeKdbx()
    _, collect = _collector()
    use_case = _make_use_case(bw, kdbx, RecordingLogger())

    use_case.run(_request(tmp_path), collect)

    assert kdbx.attachment_source is not None
    assert kdbx.attachment_source("login-1", "att-1") == b"\x00\x01bin"
    assert "get_attachment login-1/att-1" in bw.calls


def test_export_file_name_starts_with_yyyymmdd(tmp_path: Path, sample_items: list[dict]) -> None:
    bw = FakeBwCli(items=sample_items)
    _, collect = _collector()
    use_case = _make_use_case(bw, FakeKdbx(), RecordingLogger())

    result = use_case.run(_request(tmp_path), collect)

    assert re.fullmatch(r"\d{8}_bitwarden_export\.kdbx", Path(result.path).name)


def test_export_sync_failure_aborts(tmp_path: Path) -> None:
    bw = FakeBwCli(fail_sync=RuntimeError("server unavailable"))
    _, collect = _collector()
    use_case = _make_use_case(bw, FakeKdbx(), RecordingLogger())

    with pytest.raises(RuntimeError, match="server unavailable"):
        use_case.run(_request(tmp_path), collect)


def test_export_no_targets_still_writes_file(tmp_path: Path, sample_items: list[dict]) -> None:
    bw = FakeBwCli(items=sample_items)
    _, collect = _collector()
    use_case = _make_use_case(bw, FakeKdbx(), RecordingLogger())

    result = use_case.run(_request(tmp_path), collect)

    assert result.copies == []
    assert Path(result.path).exists()
