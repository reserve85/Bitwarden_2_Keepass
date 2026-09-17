"""Update orchestration - reference ports, plus the release-note sha256 gate.

Security model (documented in SECURITY.md):
- ``ApplyUpdateUseCase`` refuses to replace the running binary unless the
  release notes publish the asset's sha256 AND the downloaded bytes match it.
  The release pipeline (``release.yml``) writes that hash into the release
  body; a release without it can never be applied by this app.

# reference pattern (CheckForUpdatesUseCase/ApplyUpdateUseCase)
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import TYPE_CHECKING

from app.domain.entities import LogCategory, LogLevel

if TYPE_CHECKING:
    from collections.abc import Callable

    from app.application.ports import LoggerPort, SettingsPort, UpdatePort

#: The release body publishes the EXE hash with this marker (case-insensitive).
#: Anchored to the file name so a release note that gains a SECOND sha256 (e.g.
#: for the portable ZIP) cannot shift the gate onto the wrong asset.
_SHA256_PATTERN = re.compile(
    r"(?i)sha[-_]?256\s+of\s+bitwarden2keepass\b[-\w.]*\.exe\s*[:=]\s*([0-9a-f]{64})",
)
#: Size of a fresh copy when hashing is avoided; 1 MiB chunks keep memory flat.
_SHA256_CHUNK_BYTES = 1 << 20


def _extract_sha256(release_notes: str) -> str | None:
    """Return the 64-hex sha256 published in *release_notes*, or ``None``."""
    match = _SHA256_PATTERN.search(release_notes or "")
    return match.group(1).lower() if match else None


def _sha256_file(path: str) -> str:
    """Content hash of the downloaded asset (chunked, minimal memory)."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        while chunk := fh.read(_SHA256_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


class CheckForUpdatesUseCase:
    def __init__(
        self,
        port: UpdatePort,
        settings: SettingsPort,
        logger: LoggerPort,
        token_decrypt: Callable[[str], str] | None = None,
    ) -> None:
        self._port = port
        self._settings = settings
        self._logger = logger
        #: Injected by the composition root; decrypts an optional stored token
        #: without the application layer importing infrastructure.
        self._token_decrypt = token_decrypt

    def run(self) -> dict:
        """Check GitHub for a newer release and return the ``as_dict`` bridge."""
        raw_token = str(self._settings.get("update.token") or "")
        token = self._token_decrypt(raw_token) if (raw_token and self._token_decrypt) else raw_token
        self._logger.log(LogCategory.UPDATE, LogLevel.INFO, "Checking for updates...")
        result = self._port.check(token)
        if result.get("has_update"):
            latest = str(result.get("latest_version") or "")
            # latest_version may or may not carry a leading "v"; print exactly one.
            display = latest[1:] if latest.lower().startswith("v") else latest
            self._logger.log(LogCategory.UPDATE, LogLevel.INFO, f"Update available: v{display}")
        else:
            self._logger.log(LogCategory.UPDATE, LogLevel.INFO, "No update available.")
        return result


class ApplyUpdateUseCase:
    def __init__(self, port: UpdatePort, logger: LoggerPort) -> None:
        self._port = port
        self._logger = logger

    def run(
        self,
        download_url: str,
        token: str = "",
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> bool:
        """Download and apply, but ONLY when the asset matches the release-notes sha256.

        Raises on refusal (missing/invalid checksum); returns the result of the
        adapter's self-replacement once applied.
        """
        check = self._port.check(token)
        expected = _extract_sha256(str(check.get("release_notes") or ""))
        if expected is None:
            message = (
                "The release notes do not publish a sha256 checksum for the "
                "release - the update was refused."
            )
            raise RuntimeError(message)
        self._logger.log(
            LogCategory.UPDATE,
            LogLevel.INFO,
            "Downloading update (sha256 verified before apply)",
        )
        downloaded = self._port.download(download_url, token, progress_callback)
        actual = _sha256_file(downloaded)
        if actual != expected:
            message = (
                "Downloaded asset checksum does not match the release notes (refusing to update)."
            )
            raise RuntimeError(message)
        self._logger.log(
            LogCategory.UPDATE,
            LogLevel.INFO,
            "Checksum verified - applying update",
        )
        return self._port.apply(Path(downloaded))
