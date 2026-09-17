"""Export orchestration - the single owner of `bw sync` and the kdbx lifecycle.

One ``ExportRequest`` (no 10-arg signature), one progress callback. Phases:
SYNC -> FOLDERS -> ITEMS (per-item) -> SAVE -> VERIFY -> COPY -> DONE.

Security invariants:
- ``bw_password`` is deliberately NOT accepted - the RAM-only session inside
  ``ExportRequest`` is enough, so the master password's lifetime ends at login.
- no secret is logged: only item NAMES + counts are ever logged; an item-level
  failure logs a "Skipping item ..." line (name + id) and the loop continues.
- the KeePass master password is wiped by the caller after delivery.

# ported from bitwarden-to-keepass (src/bitwarden_to_keepass.py)
"""

from __future__ import annotations

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

    from app.application.ports import BwDataPort, KdbxPort, LoggerPort, OutputPort

_ITEM_FRACTION_START = 0.2
_ITEM_FRACTION_END = 0.8


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

        # Local calendar date is intended for the file name (DTZ005).
        filename = f"{datetime.now():%Y%m%d}_bitwarden_export.kdbx"  # noqa: DTZ005
        path = request.output_folder / filename

        self._emit(progress, ExportPhase.SYNC, 0, 1, "Syncing with Bitwarden server")
        bw.sync()

        self._emit(progress, ExportPhase.FOLDERS, 1, 2, "Creating KeePass database")
        kp = self._kdbx.create(path, request.master_password)
        folders = bw.list_folders()
        groups = self._kdbx.load_folders(kp, folders)
        self._logger.log(
            LogCategory.EXPORT,
            LogLevel.INFO,
            f"Loaded {len(folders)} folder(s)",
        )

        self._kdbx.set_attachment_source(bw.get_attachment)

        items = bw.list_items()
        total = len(items)
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
                self._kdbx.add_entry(kp, groups, item)
            except Exception as exc:
                # Only the name/id is logged - never notes, passwords or fields.
                # The exception text is ALSO redacted (an error raised deep in a
                # writer could embed a payload fragment; defense-in-depth).
                self._logger.log(
                    LogCategory.EXPORT,
                    LogLevel.WARNING,
                    f"Skipping item {name!r} ({item_id}): {redact_secrets(str(exc))}",
                )

        self._emit(progress, ExportPhase.SAVE, 1, 1, "Saving KeePass database")
        self._kdbx.save(kp, path)
        self._logger.log(LogCategory.KDBX, LogLevel.INFO, f"Saved {path.name}")

        self._emit(progress, ExportPhase.VERIFY, 1, 1, "Verifying KeePass database")
        entry_count = self._kdbx.verify(path, request.master_password)
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
            LogLevel.INFO,
            f"Export finished: {path.name} ({entry_count} entries)",
        )
        return result

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
