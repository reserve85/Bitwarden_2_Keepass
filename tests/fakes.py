"""Test fakes - injected through the application ports (never imports infra)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.domain.entities import LogCategory, LogLevel, TwoFactorRequired

if TYPE_CHECKING:
    from collections.abc import Callable


class FakeBwCli:
    """In-memory BwPort fake with scriptable responses and call recording."""

    def __init__(  # noqa: PLR0913 - the fake's script surface is intentionally flat
        self,
        *,
        folders: list[dict] | None = None,
        items: list[dict] | None = None,
        session: str = "session-fake",
        attachment_payload: bytes = b"attachment-data",
        two_factor_on_login: bool = False,
        fail_sync: Exception | None = None,
        fail_items: Exception | None = None,
    ) -> None:
        self.folders = folders or []
        self.items = items or []
        self.session = session
        self.attachment_payload = attachment_payload
        self.two_factor_on_login = two_factor_on_login
        self.fail_sync = fail_sync
        self.fail_items = fail_items
        self.calls: list[str] = []
        self.configured_server: str | None = None
        self.login_methods: list[tuple[str | None, str | None]] = []
        self.last_login_attempt = 0

    # -- auth surface --------------------------------------------------------
    def resolve_and_validate(self) -> Path:
        self.calls.append("resolve_and_validate")
        return Path("/usr/bin/bw")

    def config_server(self, url: str) -> None:
        self.calls.append(f"config_server {url}")
        self.configured_server = url

    def login(
        self,
        _email: str,
        _password: bytearray,
        method: str | None = None,
        code: str | None = None,
    ) -> str:
        self.calls.append("login")
        self.last_login_attempt += 1
        self.login_methods.append((method, code))
        if self.two_factor_on_login and self.last_login_attempt == 1:
            raise TwoFactorRequired("Two-step login")
        return self.session

    def lock(self) -> None:
        self.calls.append("lock")

    def logout(self) -> None:
        self.calls.append("logout")

    # -- data surface ---------------------------------------------------------
    def sync(self) -> None:
        self.calls.append("sync")
        if self.fail_sync is not None:
            raise self.fail_sync

    def list_folders(self) -> list[dict]:
        self.calls.append("list_folders")
        return self.folders

    def list_items(self) -> list[dict]:
        self.calls.append("list_items")
        if self.fail_items is not None:
            raise self.fail_items
        return self.items

    def get_attachment(self, item_id: str, attachment_id: str) -> bytes:
        self.calls.append(f"get_attachment {item_id}/{attachment_id}")
        return self.attachment_payload


class RecordingLogger:
    """Collects (category, level, message) tuples for assertions."""

    def __init__(self) -> None:
        self.records: list[tuple[LogCategory, LogLevel, str]] = []
        self.gui_callback: Any | None = None

    def log(self, category: LogCategory, level: LogLevel, message: str) -> None:
        self.records.append((category, level, message))
        # Mirror the real AppLogger: a registered GUI sink receives a formatted
        # line (so tests can exercise the logger -> UI wiring).
        if self.gui_callback is not None:
            self.gui_callback(f"[{level.value}] <{category.value}> {message}")

    def install_gui_handler(self, callback: Callable[[str], None]) -> None:
        self.gui_callback = callback

    @property
    def messages(self) -> list[str]:
        return [message for _, _, message in self.records]


class FakeOverwriteAnswers:
    """Deque-backed overwrite callback: consumes answers in order, else False."""

    def __init__(self, answers: list[bool] | None = None) -> None:
        self._answers = list(answers or [])
        self.asked: list[str] = []

    def __call__(self, destination: Path) -> bool:
        self.asked.append(str(destination))
        return bool(self._answers.pop(0)) if self._answers else False


class FakeUpdatePort:
    """Scriptable UpdatePort fake recording every call."""

    def __init__(
        self,
        *,
        check_result: dict | None = None,
        download_path: str = "",
        download_error: str = "",
    ) -> None:
        self.check_result = check_result or {
            "has_update": False,
            "latest_version": "",
            "download_url": "",
            "release_notes": "",
            "error": "",
        }
        self.download_path = download_path
        self.download_error = download_error
        self.calls: list[str] = []
        self.checked_tokens: list[str] = []
        self.applied_paths: list[str] = []

    def check(self, token: str = "") -> dict:
        self.calls.append("check")
        self.checked_tokens.append(token)
        return dict(self.check_result)

    def download(
        self,
        url: str,
        _token: str = "",
        _progress_callback: object | None = None,
    ) -> str:
        self.calls.append(f"download {url}")
        if self.download_error:
            raise RuntimeError(self.download_error)
        return self.download_path

    def apply(self, downloaded: Path) -> bool:
        self.calls.append("apply")
        self.applied_paths.append(str(downloaded))
        return True

    def restart(self) -> None:
        self.calls.append("restart")

    def clean_old_files(self) -> None:
        self.calls.append("clean_old_files")


class FakeSettings:
    """In-memory SettingsPort fake (dict-backed get/set/to_dict)."""

    def __init__(self, initial: dict[str, Any] | None = None) -> None:
        self._data: dict[str, Any] = dict(initial or {})
        self.updated_keys: list[str] = []

    def get(self, key: str, default: Any = None) -> Any:  # noqa: ANN401 - mirrors the untyped SettingsPort
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:  # noqa: ANN401 - mirrors the untyped SettingsPort
        self._data[key] = value
        self.updated_keys.append(key)

    def to_dict(self) -> dict:
        return dict(self._data)
