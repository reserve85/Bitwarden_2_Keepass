"""Self-update adapter around the SHA-pinned ``github_updater`` (v1.2.2).

Doubles as the ``UpdatePort`` implementation injected into the update use
cases. The adapter keeps the library behind one surface: the app layer sees
plain ``dict`` results and paths, never ``github_updater`` types; the library's
``UpdateError`` still travels to the presentation layer (the GUI shows it in a
warning box - see Gasmeter pattern).

# Gasmeter pattern (GithubUpdateAdapter port)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from github_updater import (
    DownloadResult,
    UpdateError,
    UpdateService,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

#: bitwarden_2_keepass release coordinates (owner must match the self-update
#: trust model in SECURITY.md; the app never updates from another owner).
_OWNER = "reserve85"
_REPO = "bitwarden_2_keepass"
_APP_NAME = "bitwarden2keepass"


class GithubUpdateAdapter:
    def __init__(self, current_version: str) -> None:
        self._current_version = current_version

    def check(self, token: str = "") -> dict:
        """Check the latest GitHub release; returns ``UpdateCheckResult.as_dict()``."""
        service = UpdateService(
            current_version=self._current_version,
            owner=_OWNER,
            repo=_REPO,
            app_name=_APP_NAME,
        )
        return service.check_for_update(token=token).as_dict()

    def download(
        self,
        url: str,
        token: str = "",
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> str:
        """Download the release asset to a validated temp path (``str``)."""
        service = UpdateService(
            current_version=self._current_version,
            owner=_OWNER,
            repo=_REPO,
            app_name=_APP_NAME,
        )
        result: DownloadResult = service.download_update(
            url,
            token=token,
            progress_callback=progress_callback,
        )
        if result.error:
            raise UpdateError(result.error)
        return result.path

    def apply(self, downloaded: Path) -> bool:
        """Validate, stage and launch the safe self-replacement."""
        service = UpdateService(
            current_version=self._current_version,
            owner=_OWNER,
            repo=_REPO,
            app_name=_APP_NAME,
        )
        return service.apply_update(str(downloaded))

    def restart(self) -> None:
        """Exit the app; the detached helper swaps in the new version."""
        UpdateService(
            current_version=self._current_version,
            owner=_OWNER,
            repo=_REPO,
            app_name=_APP_NAME,
        ).restart_app()

    def clean_old_files(self) -> None:
        """Restore a broken v0.x state, then remove leftover stages."""
        UpdateService.clean_old_files()
