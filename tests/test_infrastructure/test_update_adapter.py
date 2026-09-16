"""GithubUpdateAdapter tests - delegation to github_updater (no network).

The adapter is the ONLY module importing github_updater (lazily, inside its
methods); these tests pin its wiring (owner/repo/app_name/version and the
``sys.frozen`` guard) by monkeypatching ``github_updater.UpdateService``.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import ClassVar

import github_updater as gu_module
import pytest
from github_updater import DownloadResult, UpdateCheckResult, UpdateError

from app.infrastructure.updating.update_adapter import GithubUpdateAdapter


class FakeUpdateService:
    """Configurable stand-in for github_updater.UpdateService."""

    constructor_calls: ClassVar[list[dict[str, str]]] = []
    check_result: ClassVar[dict] = {}
    download_result: ClassVar[DownloadResult | None] = None
    apply_result: ClassVar[bool] = True
    restarted: ClassVar[bool] = False
    cleaned: ClassVar[bool] = False

    def __init__(
        self,
        current_version: str,
        owner: str,
        repo: str,
        app_name: str,
    ) -> None:
        self.constructor_calls.append(
            {
                "current_version": current_version,
                "owner": owner,
                "repo": repo,
                "app_name": app_name,
            },
        )

    def check_for_update(self, token: str = "") -> _AsDict:  # noqa: ARG002 - signature parity with the real service
        return _AsDict(self.check_result)

    def download_update(
        self,
        url: str,  # noqa: ARG002 - signature parity with the real service
        token: str = "",  # noqa: ARG002 - signature parity with the real service
        progress_callback: object | None = None,  # noqa: ARG002 - signature parity with the real service
    ) -> DownloadResult:
        return self.download_result

    def apply_update(self, path: str) -> bool:  # noqa: ARG002 - signature parity with the real service
        return self.apply_result

    def restart_app(self) -> None:
        FakeUpdateService.restarted = True

    @staticmethod
    def clean_old_files() -> None:
        FakeUpdateService.cleaned = True


class _AsDict:
    def __init__(self, data: dict) -> None:
        self._data = data

    def as_dict(self) -> dict:
        return self._data


def _patch_service(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeUpdateService.constructor_calls = []
    FakeUpdateService.check_result = {
        "has_update": False,
        "latest_version": "",
        "download_url": "",
        "release_notes": "",
        "error": "",
    }
    FakeUpdateService.download_result = None
    FakeUpdateService.apply_result = True
    FakeUpdateService.restarted = False
    FakeUpdateService.cleaned = False
    monkeypatch.setattr(gu_module, "UpdateService", FakeUpdateService)


def test_check_returns_as_dict_and_uses_configured_owner_repo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_service(monkeypatch)
    FakeUpdateService.check_result = UpdateCheckResult(
        has_update=True,
        latest_version="v1.1.0",
        download_url="https://example.com/exe.zip",
        release_notes="notes",
        error="",
    ).as_dict()

    adapter = GithubUpdateAdapter("0.5.0")
    result = adapter.check(token="tok")

    assert result["has_update"] is True
    assert result["latest_version"] == "v1.1.0"
    call = FakeUpdateService.constructor_calls[0]
    assert call["current_version"] == "0.5.0"
    assert call["owner"] == "reserve85"
    assert call["repo"] == "bitwarden_2_keepass"
    assert call["app_name"] == "bitwarden2keepass"


def test_download_returns_path_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_service(monkeypatch)
    FakeUpdateService.download_result = DownloadResult(path="C:\\temp\\app_new.zip", error="")

    adapter = GithubUpdateAdapter("0.5.0")
    path = adapter.download("https://example.com/exe.zip", token="tok")

    assert path == "C:\\temp\\app_new.zip"


def test_download_raises_update_error_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_service(monkeypatch)
    FakeUpdateService.download_result = DownloadResult(path="", error="checksum of download failed")

    adapter = GithubUpdateAdapter("0.5.0")

    with pytest.raises(UpdateError, match="checksum"):
        adapter.download("https://example.com/exe.zip")


def test_apply_restart_and_cleanup_delegate(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_service(monkeypatch)
    # The sys.frozen guard only lets a packaged (PyInstaller) build apply.
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    adapter = GithubUpdateAdapter("0.5.0")

    assert adapter.apply(Path("C:\\temp\\app_new.zip")) is True
    assert FakeUpdateService.apply_result is True

    adapter.restart()
    assert FakeUpdateService.restarted is True

    adapter.clean_old_files()
    assert FakeUpdateService.cleaned is True


def test_apply_refuses_outside_a_frozen_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_service(monkeypatch)
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    adapter = GithubUpdateAdapter("0.5.0")

    with pytest.raises(UpdateError, match="packaged"):
        adapter.apply(Path("C:\\temp\\app_new.zip"))
    assert FakeUpdateService.apply_result is True  # never called
