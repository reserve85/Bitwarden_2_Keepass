"""OutputHandler - copy/verify/delete for the finished export file.

Safety-critical rules:
- every copy is **content-verified** by comparing sha256(source) with
  sha256(dest) - a file-size check is NOT sufficient (a truncated/corrupt copy
  can have equal size). Outcomes carry the verified hash (or ``""`` + error).
- the copy is written to ``<name>.partial`` and only moved onto the final
  name after the hash matched, so an existing good backup at the destination
  is never replaced by a truncated or corrupt file.
- the overwrite-callback decides what happens when the destination file
  already exists: returning True overwrites it, False skips it
  (``CopyOutcome.skipped``) and True-with-"Skip" is never asked twice.
- per-target failures are recorded; the loop never aborts on one bad folder.

# ported from bitwarden-to-keepass output handling
"""

from __future__ import annotations

import contextlib
import hashlib
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from app.domain.entities import CopyOutcome

if TYPE_CHECKING:
    from collections.abc import Callable

_SHA256_CHUNK_BYTES = 1 << 20  # 1 MiB


class OutputHandler:
    def __init__(
        self,
        overwrite_callback: Callable[[Path], bool] | None = None,
    ) -> None:
        """``overwrite_callback(Path) -> bool``: True = overwrite, False = skip."""
        self._overwrite_callback = overwrite_callback

    def set_overwrite_callback(self, callback: Callable[[Path], bool]) -> None:
        """Wire (or swap) the overwrite prompt once the GUI window exists."""
        self._overwrite_callback = callback

    def file_sha256(self, path: Path) -> str:
        """Content hash, chunked to keep memory flat (not the streamed text hash)."""
        digest = hashlib.sha256()
        with Path(path).open("rb") as fh:
            while chunk := fh.read(_SHA256_CHUNK_BYTES):
                digest.update(chunk)
        return digest.hexdigest()

    def copy(self, source: Path, destinations: list[Path]) -> list[CopyOutcome]:
        """Copy *source* to every destination; verify content; never abort the list."""
        outcomes: list[CopyOutcome] = []
        source_hash = self.file_sha256(source)
        for destination in destinations:
            outcome = self._copy_one(source, destination, source_hash)
            outcomes.append(outcome)
        return outcomes

    def _copy_one(self, source: Path, destination: Path, source_hash: str) -> CopyOutcome:
        try:
            if destination.exists() and (
                self._overwrite_callback is None or not self._overwrite_callback(destination)
            ):
                return CopyOutcome(
                    destination=str(destination),
                    copied=False,
                    skipped=True,
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            partial = destination.with_name(destination.name + ".partial")
            try:
                shutil.copy2(source, partial)
                destination_hash = self.file_sha256(partial)
                if destination_hash != source_hash:
                    error = f"Checksum mismatch after copying to {destination}."
                    return CopyOutcome(destination=str(destination), copied=False, error=error)
                partial.replace(destination)
            finally:
                with contextlib.suppress(OSError):
                    partial.unlink(missing_ok=True)
            return CopyOutcome(
                destination=str(destination),
                copied=True,
                sha256=destination_hash,
            )
        except OSError as exc:
            return CopyOutcome(
                destination=str(destination),
                copied=False,
                error=f"Copy to {destination} failed: {exc}",
            )

    def delete_source(self, source: Path) -> None:
        Path(source).unlink(missing_ok=True)
