"""Copy the finished kdbx into the (unlimited) target folders.

Delete-source rule (safety-critical, documented):
- the source export file is deleted ONLY when the user opted in
  (``delete_after_copy``) AND there is at least one target AND **every** target
  received a sha256-verified copy. A skipped target (existing file the user
  chose to keep) or a failed target keeps the source in place - so a
  target-less run never deletes the only export, and a partly failed run never
  leaves the user with fewer copies than they configured.

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

#: The COPY phase owns the last tenth of the export progress bar.
_COPY_FRACTION_START = 0.9


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
                fraction=_COPY_FRACTION_START,
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
                    fraction=_COPY_FRACTION_START + (1 - _COPY_FRACTION_START) * index / total,
                    message=f"Processed {outcome.destination}",
                ),
            )

        copied = [outcome for outcome in outcomes if outcome.copied]
        source_deleted = False
        if delete_after_copy and outcomes and len(copied) == len(outcomes):
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
