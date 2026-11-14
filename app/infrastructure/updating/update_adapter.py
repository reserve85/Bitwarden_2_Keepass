"""Self-update adapter around the SHA-pinned ``github_updater`` (v1.2.2).

Doubles as the ``UpdatePort`` implementation injected into the update use
cases. The adapter keeps the library behind one surface: the app layer sees
plain ``dict`` results and paths, never ``github_updater`` types; the library's
``UpdateError`` still travels to the presentation layer (the GUI shows it in a
warning box - see reference pattern).

``github_updater`` is imported **lazily** inside the methods on purpose: the
library is only needed when the user actually checks for or downloads an
update, so a missing/broken installation can never break application startup.

# reference pattern (GithubUpdateAdapter port)
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

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

    def _update_service(self) -> object:
        """Build a ``github_updater.UpdateService`` for this app's coordinates."""
        from github_updater import UpdateService  # noqa: PLC0415 - deliberate lazy import

        return UpdateService(
            current_version=self._current_version,
            owner=_OWNER,
            repo=_REPO,
            app_name=_APP_NAME,
        )

    def check(self) -> dict:
        """Check the latest GitHub release; returns ``UpdateCheckResult.as_dict()``.

        The repository is public, so the check is always anonymous.
        """
        return self._update_service().check_for_update().as_dict()

    def download(
        self,
        url: str,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> str:
        """Download the release asset to a validated temp path (``str``)."""
        from github_updater import UpdateError  # noqa: PLC0415 - deliberate lazy import

        result = self._update_service().download_update(
            url,
            progress_callback=progress_callback,
        )
        if result.error:
            raise UpdateError(result.error)
        return result.path

    def apply(self, downloaded: Path) -> bool:
        """Validate, stage and launch the safe self-replacement.

        The detached helper swaps the executable in once this process has
        exited; the caller quits the app normally afterwards (the helper does
        not relaunch it).

        Only meaningful inside a frozen (PyInstaller) build: in a source
        checkout there is no single executable to swap, so the apply is
        refused with a clear error instead of corrupting the checkout.
        """
        if not getattr(sys, "frozen", False):
            from github_updater import UpdateError  # noqa: PLC0415 - deliberate lazy import

            raise UpdateError(
                "Self-update is only supported in the packaged application.",
            )
        return self._update_service().apply_update(str(downloaded))

    def clean_old_files(self) -> None:
        """Restore a broken state, then remove leftover stages (best-effort)."""
        from github_updater import UpdateService  # noqa: PLC0415 - deliberate lazy import

        UpdateService.clean_old_files()
