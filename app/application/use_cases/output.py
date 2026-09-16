"""Copy the finished kdbx into the (unlimited) target folders.

Delete-source rules (safety-critical, documented):
- the only export file is deleted ONLY when the user opted in
  (``delete_after_copy``) AND at least one copy succeeded (every successful
  copy has been sha256-verified by the OutputPort) - i.e. a target-less run
  with ``delete_after_copy=True`` never deletes the only export, and a run
  where every copy failed leaves the source in place.

# ported from bitwarden-to-keepass copy orchestration
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from app.domain.entities import (
    ExportPhase,
    ExportProgress,
    ExportResult,
    LogCategory,
    LogLevel,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from app.application.ports import LoggerPort, OutputPort


class CopyToTargetsUseCase:
    def __init__(self, output: OutputPort, logger: LoggerPort) -> None:
        self._output = output
        self._logger = logger

    def run(
        self,
        source: Path,
        target_folders: Sequence[Path],
        *,
        delete_after_copy: bool,
        progress_cb: Callable[[ExportProgress], None],
    ) -> ExportResult:
        """Copy *source* into every (resolved, deduplicated) target folder.

        Returns an :class:`ExportResult` carrying one :class:`CopyOutcome` per
        destination; per-target failures are recorded and never abort the loop.
        """
        destinations = self._unique_resolved(source, target_folders)
        total = max(len(destinations), 1)

        progress_cb(
            ExportProgress(
                phase=ExportPhase.COPY,
                current=0,
                total=total,
                message=f"Copying to {len(destinations)} destination(s)",
            ),
        )

        outcomes = self._output.copy(source, destinations)
        for index, outcome in enumerate(outcomes, start=1):
            progress_cb(
                ExportProgress(
                    phase=ExportPhase.COPY,
                    current=index,
                    total=total,
                    fraction=index / total,
                    message=f"Copied {outcome.destination}",
                ),
            )

        copied = [outcome for outcome in outcomes if outcome.copied]
        source_deleted = False
        if delete_after_copy and copied:
            self._output.delete_source(source)
            source_deleted = True

        self._logger.log(
            LogCategory.COPY,
            LogLevel.INFO,
            f"Copied {len(copied)}/{len(destinations)} target(s)",
        )

        return ExportResult(
            path=str(source),
            copies=outcomes,
            source_deleted=source_deleted,
        )

    @staticmethod
    def _unique_resolved(source: Path, target_folders: Sequence[Path]) -> list[Path]:
        """Every target folder becomes the destination FILE path (folder / name).

        Duplicate folders collapse onto a single destination; the export's own
        folder is skipped so a target list cannot overwrite the only copy.
        """
        filename = source.name
        seen: set[str] = set()
        unique: list[Path] = []
        source_dir = Path(source).resolve().parent
        for folder in target_folders:
            path = Path(folder).resolve()
            if path == source_dir:
                continue
            destination = path / filename
            key = str(destination)
            if key in seen:
                continue
            seen.add(key)
            unique.append(destination)
        return unique
