"""Export orchestration - the single owner of `bw sync` and the kdbx lifecycle.

One ``ExportRequest`` (no 10-arg signature), one progress callback. Phases:
SYNC -> FOLDERS -> ITEMS (per-item) -> SAVE -> VERIFY -> COPY -> DONE.

Safety invariants:
- the database is built in a ``.partial`` file next to the target and only
  moved onto the final name after it was saved, re-opened and its entry count
  matched the number of written items - a failed run can never replace or
  damage an earlier export, and never leaves a half-written file behind.
- nothing is dropped silently: an item that cannot be written is recorded in
  ``ExportResult.skipped_items``, everything that could not be exported 1:1 in
  ``ExportResult.notices`` - the GUI shows both.

Security invariants:
- ``bw_password`` is deliberately NOT accepted - the RAM-only session inside
  ``ExportRequest`` is enough, so the master password's lifetime ends at login.
- no secret is logged: only item NAMES + counts are ever logged; an item-level
  failure logs a "Skipping item ..." line (name + id) and the loop continues.
- the KeePass master password is wiped by the caller after delivery.

# ported from bitwarden-to-keepass (src/bitwarden_to_keepass.py)
"""

from __future__ import annotations

import contextlib
from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING

from app.application.use_cases.output import CopyToTargetsUseCase
from app.domain.entities import (
    ExportPhase,
    ExportProgress,
    ExportRequest,
    ExportResult,
    LogCategory,
    LogLevel,
)
from app.domain.security import redact_secrets

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from app.application.ports import BwDataPort, KdbxPort, LoggerPort, OutputPort

_SYNC_FRACTION = 0.05
_FOLDERS_FRACTION = 0.15
_ITEM_FRACTION_START = 0.2
_ITEM_FRACTION_END = 0.8
_SAVE_FRACTION = 0.85
_VERIFY_FRACTION = 0.9

PARTIAL_SUFFIX = ".partial"


def export_filename(now: datetime | None = None) -> str:
    """File name of today's export (local calendar date on purpose)."""
    moment = now or datetime.now()  # noqa: DTZ005 - local date is intended
    return f"{moment:%Y%m%d}_bitwarden_export.kdbx"


class ExportVaultUseCase:
    def __init__(
        self,
        bw_client_factory: Callable[[str], BwDataPort],
        kdbx: KdbxPort,
        output: OutputPort,
        logger: LoggerPort,
    ) -> None:
        """``bw_client_factory(session)`` builds the data client per export run."""
        self._bw_client_factory = bw_client_factory
        self._kdbx = kdbx
        self._copy = CopyToTargetsUseCase(output, logger)
        self._logger = logger

    def run(
        self,
        request: ExportRequest,
        progress: Callable[[ExportProgress], None],
    ) -> ExportResult:
        """Export the whole vault into a fresh kdbx and copy it to the targets."""
        bw = self._bw_client_factory(request.session)
        path = request.output_folder / export_filename()
        partial = path.with_name(path.name + PARTIAL_SUFFIX)

        try:
            total, skipped, notices = self._build(bw, request, partial, progress)

            self._emit(
                progress,
                ExportPhase.VERIFY,
                1,
                1,
                "Verifying KeePass database",
                fraction=_VERIFY_FRACTION,
            )
            entry_count = self._kdbx.verify(partial, request.master_password)
            expected = total - len(skipped)
            if entry_count != expected:
                message = (
                    f"Verification failed: {expected} item(s) were written but the "
                    f"saved database contains {entry_count} entries."
                )
                raise RuntimeError(message)
            # Only a complete, verified database replaces an earlier export.
            partial.replace(path)
        finally:
            with contextlib.suppress(OSError):
                partial.unlink(missing_ok=True)

        self._logger.log(
            LogCategory.KDBX,
            LogLevel.INFO,
            f"Verified {entry_count} entry/entries in {path.name}",
        )

        # The COPY phase emits its own progress samples through the same callback.
        result = self._copy.run(
            path,
            list(request.target_folders),
            delete_after_copy=request.delete_after_copy,
            progress_cb=progress,
        )

        self._emit(progress, ExportPhase.DONE, 1, 1, "Export finished", fraction=1.0)
        self._logger.log(
            LogCategory.EXPORT,
            LogLevel.WARNING if skipped else LogLevel.INFO,
            f"Export finished: {path.name} ({entry_count} of {total} item(s) exported, "
            f"{len(skipped)} skipped, {len(notices)} notice(s))",
        )
        return replace(
            result,
            item_total=total,
            entry_count=entry_count,
            skipped_items=tuple(skipped),
            notices=tuple(notices),
        )

    def _build(
        self,
        bw: BwDataPort,
        request: ExportRequest,
        partial: Path,
        progress: Callable[[ExportProgress], None],
    ) -> tuple[int, list[str], list[str]]:
        """Sync, write every item into *partial* and save it.

        Returns ``(item_total, skipped_items, notices)``.
        """
        self._emit(
            progress,
            ExportPhase.SYNC,
            0,
            1,
            "Syncing with Bitwarden server",
            fraction=_SYNC_FRACTION,
        )
        bw.sync()

        self._emit(
            progress,
            ExportPhase.FOLDERS,
            1,
            2,
            "Creating KeePass database",
            fraction=_FOLDERS_FRACTION,
        )
        folders = bw.list_folders()
        items = bw.list_items()
        kp = self._kdbx.create(partial, request.master_password)
        groups = self._kdbx.load_folders(kp, folders)
        self._logger.log(
            LogCategory.EXPORT,
            LogLevel.INFO,
            f"Loaded {len(folders)} folder(s)",
        )

        self._kdbx.set_attachment_source(bw.get_attachment)

        total = len(items)
        skipped: list[str] = []
        notices: list[str] = []
        for index, item in enumerate(items, start=1):
            fraction = _ITEM_FRACTION_START + (
                (_ITEM_FRACTION_END - _ITEM_FRACTION_START) * index / max(total, 1)
            )
            name = str(item.get("name") or "")
            item_id = str(item.get("id") or "")
            self._emit(
                progress,
                ExportPhase.ITEMS,
                index,
                total,
                f"Writing item {index}/{total}: {name}",
                fraction=fraction,
            )
            try:
                item_notices = self._kdbx.add_entry(kp, groups, item) or []
            except Exception as exc:
                # Only the name/id is logged - never notes, passwords or fields.
                # The exception text is ALSO redacted (an error raised deep in a
                # writer could embed a payload fragment; defense-in-depth).
                reason = redact_secrets(str(exc))
                skipped.append(f"{name or '(unnamed)'}: {reason}")
                self._logger.log(
                    LogCategory.EXPORT,
                    LogLevel.ERROR,
                    f"Skipping item {name!r} ({item_id}): {reason}",
                )
                continue
            for notice in item_notices:
                notices.append(f"{name or '(unnamed)'}: {notice}")
                self._logger.log(
                    LogCategory.EXPORT,
                    LogLevel.WARNING,
                    f"Item {name!r} ({item_id}): {notice}",
                )

        self._emit(
            progress,
            ExportPhase.SAVE,
            1,
            1,
            "Saving KeePass database",
            fraction=_SAVE_FRACTION,
        )
        self._kdbx.save(kp, partial)
        self._logger.log(LogCategory.KDBX, LogLevel.INFO, "Saved the KeePass database")
        return total, skipped, notices

    def _emit(  # noqa: PLR0913 - phase/current/total/message are one progress sample
        self,
        progress: Callable[[ExportProgress], None],
        phase: ExportPhase,
        current: int,
        total: int,
        message: str,
        *,
        fraction: float = 0.0,
    ) -> None:
        sample = ExportProgress(
            phase=phase,
            current=current,
            total=total,
            message=message,
            fraction=fraction,
        )
        progress(sample)
