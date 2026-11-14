"""Export safety regressions - nothing silently lost, never a damaged export.

Real ``KdbxWriter`` + real ``OutputHandler`` over temp dirs; only the bw data
source is faked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pykeepass import PyKeePass

from app.application.use_cases.export import (
    PARTIAL_SUFFIX,
    ExportVaultUseCase,
    export_filename,
)
from app.application.use_cases.output import CopyToTargetsUseCase
from app.domain.entities import ExportProgress, ExportRequest
from app.infrastructure.kdbx.kdbx_writer import KdbxWriter
from app.infrastructure.output.output_handler import OutputHandler
from tests.fakes import FakeBwCli, FakeOverwriteAnswers, RecordingLogger

if TYPE_CHECKING:
    from pathlib import Path

_PASSWORD = "pw"


def _login(item_id: str, name: str, **extra: object) -> dict:
    return {
        "id": item_id,
        "type": 1,
        "name": name,
        "login": {"username": "u", "password": "p"},
        **extra,
    }


def _request(tmp_path: Path) -> ExportRequest:
    return ExportRequest(
        url="https://vault.example.com",
        email="user@example.com",
        session="session-fake",
        master_password=_PASSWORD,
        output_folder=tmp_path / "out",
        target_folders=(),
        delete_after_copy=False,
    )


def _use_case(bw: FakeBwCli, logger: RecordingLogger | None = None) -> ExportVaultUseCase:
    return ExportVaultUseCase(
        bw_client_factory=lambda _session: bw,
        kdbx=KdbxWriter(),
        output=OutputHandler(),
        logger=logger or RecordingLogger(),
    )


def _ignore(_progress: ExportProgress) -> None:
    return None


def test_result_counts_every_item_and_reports_nothing_for_a_clean_vault(tmp_path: Path) -> None:
    bw = FakeBwCli(items=[_login("1", "A"), _login("2", "B")])

    result = _use_case(bw).run(_request(tmp_path), _ignore)

    assert (result.item_total, result.entry_count) == (2, 2)
    assert result.skipped_items == ()
    assert result.notices == ()
    assert len(PyKeePass(result.path, password=_PASSWORD).entries) == result.entry_count


def test_formerly_dropped_items_are_now_exported(tmp_path: Path) -> None:
    """SSH keys, reserved field names and control characters used to drop the item."""
    items = [
        {"id": "ssh", "type": 5, "name": "Key", "sshKey": {"privateKey": "k"}},
        _login("res", "Reserved", fields=[{"name": "Password", "value": "v", "type": 0}]),
        _login("ctl", "Control", notes="a\x00b"),
    ]
    bw = FakeBwCli(items=items)

    result = _use_case(bw).run(_request(tmp_path), _ignore)

    assert result.skipped_items == ()
    assert result.entry_count == len(items)
    assert any("Control" in notice for notice in result.notices)


def test_skipped_item_is_reported_in_the_result(tmp_path: Path) -> None:
    """An item that cannot be written must surface in the result, not just the log."""
    # A non-string attachment id makes the (fake) download raise inside add_entry.
    bw = FakeBwCli(items=[_login("1", "Good"), {"id": "2", "type": 1, "name": "Bad", "fields": 5}])
    writer = KdbxWriter()
    original = writer.add_entry

    def add_entry(kp: object, groups: dict, item: dict) -> list[str]:
        if item["name"] == "Bad":
            message = "cannot write this one"
            raise RuntimeError(message)
        return original(kp, groups, item)

    writer.add_entry = add_entry  # type: ignore[method-assign]
    logger = RecordingLogger()
    use_case = ExportVaultUseCase(lambda _s: bw, writer, OutputHandler(), logger)

    result = use_case.run(_request(tmp_path), _ignore)

    assert (result.item_total, result.entry_count) == (2, 1)
    assert result.skipped_items == ("Bad: cannot write this one",)
    assert any("Skipping item 'Bad'" in message for message in logger.messages)


def test_failed_export_keeps_the_earlier_export_of_the_day(tmp_path: Path) -> None:
    """Regression: the day's file used to be overwritten before the run succeeded."""
    out = tmp_path / "out"
    out.mkdir()
    existing = out / export_filename()
    existing.write_bytes(b"earlier-good-export")
    bw = FakeBwCli(items=[_login("1", "A")], fail_items=RuntimeError("list items failed"))

    with pytest.raises(RuntimeError, match="list items failed"):
        _use_case(bw).run(_request(tmp_path), _ignore)

    assert existing.read_bytes() == b"earlier-good-export"
    assert list(out.iterdir()) == [existing]  # no partial file left behind


def test_cancelled_export_leaves_no_partial_file(tmp_path: Path) -> None:
    bw = FakeBwCli(items=[_login("1", "A"), _login("2", "B")])

    def cancel_on_second_item(progress: ExportProgress) -> None:
        if progress.message.startswith("Writing item 2"):
            message = "cancelled"
            raise RuntimeError(message)

    with pytest.raises(RuntimeError, match="cancelled"):
        _use_case(bw).run(_request(tmp_path), cancel_on_second_item)

    assert list((tmp_path / "out").iterdir()) == []


def test_successful_export_replaces_the_earlier_one_and_removes_the_partial(
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / export_filename()).write_bytes(b"earlier-export")
    bw = FakeBwCli(items=[_login("1", "A")])

    result = _use_case(bw).run(_request(tmp_path), _ignore)

    assert len(PyKeePass(result.path, password=_PASSWORD).entries) == 1
    assert not (out / (export_filename() + PARTIAL_SUFFIX)).exists()


def test_entry_count_mismatch_fails_the_export(tmp_path: Path) -> None:
    bw = FakeBwCli(items=[_login("1", "A")])
    writer = KdbxWriter()
    writer.verify = lambda _path, _password: 0  # type: ignore[method-assign]
    use_case = ExportVaultUseCase(lambda _s: bw, writer, OutputHandler(), RecordingLogger())

    with pytest.raises(RuntimeError, match="Verification failed"):
        use_case.run(_request(tmp_path), _ignore)

    assert not (tmp_path / "out" / export_filename()).exists()


def test_progress_never_moves_backwards(tmp_path: Path) -> None:
    """Regression: SAVE/VERIFY/COPY used to reset the bar from 80 % to 0 %."""
    bw = FakeBwCli(items=[_login("1", "A"), _login("2", "B")])
    fractions: list[float] = []
    request = _request(tmp_path)
    request = ExportRequest(**{**_as_kwargs(request), "target_folders": (tmp_path / "copy",)})

    _use_case(bw).run(request, lambda progress: fractions.append(progress.fraction))

    assert fractions == sorted(fractions)
    assert fractions[0] > 0
    assert fractions[-1] == 1.0


def _as_kwargs(request: ExportRequest) -> dict:
    return {name: getattr(request, name) for name in request.__dataclass_fields__}


# -- delete-after-copy rule ---------------------------------------------------


def _copy(
    source: Path,
    targets: list[Path],
    overwrite: FakeOverwriteAnswers | None = None,
) -> bool:
    use_case = CopyToTargetsUseCase(OutputHandler(overwrite), RecordingLogger())
    result = use_case.run(source, targets, delete_after_copy=True, progress_cb=_ignore)
    return result.source_deleted


def test_source_is_kept_when_one_target_failed(tmp_path: Path) -> None:
    """Regression: one successful copy used to be enough to delete the source."""
    source = tmp_path / "src" / "export.kdbx"
    source.parent.mkdir()
    source.write_bytes(b"data")
    blocked = tmp_path / "blocked"
    blocked.write_bytes(b"a file where a folder is expected")

    deleted = _copy(source, [tmp_path / "ok", blocked])

    assert deleted is False
    assert source.exists()


def test_source_is_kept_when_one_target_was_skipped(tmp_path: Path) -> None:
    source = tmp_path / "src" / "export.kdbx"
    source.parent.mkdir()
    source.write_bytes(b"data")
    kept = tmp_path / "kept"
    kept.mkdir()
    (kept / source.name).write_bytes(b"older")

    deleted = _copy(source, [tmp_path / "ok", kept], FakeOverwriteAnswers([False]))

    assert deleted is False
    assert source.exists()


def test_source_is_deleted_when_every_target_has_a_verified_copy(tmp_path: Path) -> None:
    source = tmp_path / "src" / "export.kdbx"
    source.parent.mkdir()
    source.write_bytes(b"data")

    deleted = _copy(source, [tmp_path / "a", tmp_path / "b"])

    assert deleted is True
    assert not source.exists()
    assert (tmp_path / "a" / "export.kdbx").read_bytes() == b"data"


def test_failed_copy_keeps_the_existing_destination_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A corrupt copy must never replace a good backup at the destination."""
    source = tmp_path / "export.kdbx"
    source.write_bytes(b"new-export")
    destination = tmp_path / "target" / "export.kdbx"
    destination.parent.mkdir()
    destination.write_bytes(b"old-good-backup")
    handler = OutputHandler(lambda _path: True)
    real_hash = handler.file_sha256
    monkeypatch.setattr(
        handler,
        "file_sha256",
        lambda path: "corrupt" if str(path).endswith(".partial") else real_hash(path),
    )

    outcome = handler.copy(source, [destination])[0]

    assert outcome.copied is False
    assert "Checksum mismatch" in outcome.error
    assert destination.read_bytes() == b"old-good-backup"
    assert not destination.with_name("export.kdbx.partial").exists()
