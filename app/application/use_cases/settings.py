"""Validated read/update/persist of the app settings (reference shape).

The server URL must be a complete http(s) URL, the email must look like one,
an empty bw path falls back to the default ``bw`` (PATH lookup at use time),
and a malformed value is rejected with a plain ``ValueError`` before anything
is written - so a typo can never corrupt the persisted config. Values are
persisted ONLY on an explicit Save (the SettingsPage calls
``update``); ``get_all`` is a plain mirror for the GUI.

# reference pattern
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from app.domain.entities import LogCategory, LogLevel

if TYPE_CHECKING:
    from app.application.ports import LoggerPort, SettingsPort


class SettingsUseCase:
    def __init__(self, settings: SettingsPort, logger: LoggerPort) -> None:
        self._settings = settings
        self._logger = logger

    def get_all(self) -> dict:
        """Plain mirror of the current config (defaults merged)."""
        return self._settings.to_dict()

    def update(self, changes: dict) -> dict:
        """Validate *changes*, persist them atomically and return the new state.

        Raises ``ValueError`` (with a user-presentable message, no secrets) for
        the first invalid value; nothing is persisted in that case.
        """
        validated = self._validate(changes)
        for key, value in validated.items():
            self._settings.set(key, value)
        self._logger.log(LogCategory.CONFIG, LogLevel.INFO, "Settings saved.")
        return self.get_all()

    @staticmethod
    def _validate(changes: dict) -> dict:
        """Copy the changes after structural/format validation.

        Unknown keys are rejected so a typo cannot silently set a different
        setting than the user intended.
        """
        known = {
            "bitwarden.url",
            "bitwarden.email",
            "bitwarden.bw_path",
            "output.output_folder",
            "output.target_folders",
            "output.delete_after_copy",
            "update.check_at_startup",
        }
        validated: dict[str, Any] = {}
        for key, value in changes.items():
            if key not in known:
                message = f"Unknown setting: {key}"
                raise ValueError(message)
            if key == "bitwarden.url":
                validated[key] = _validated_url(value)
            elif key == "bitwarden.email":
                validated[key] = _validated_email(value)
            elif key == "bitwarden.bw_path":
                validated[key] = _validated_bw_path(value)
            elif key == "output.target_folders":
                validated[key] = _validated_folder_list(value)
            elif key in {"output.delete_after_copy", "update.check_at_startup"}:
                validated[key] = bool(value)
            else:
                validated[key] = value
        return validated


def _validated_url(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return text
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        host = None
    if parts.scheme not in {"http", "https"} or not host:
        message = "The server URL must be a complete address like https://vault.example.com"
        raise ValueError(message)
    return text


def is_unencrypted_url(url: str) -> bool:
    """True for a plain ``http://`` server URL (login data would travel unencrypted)."""
    return url.strip().lower().startswith("http://")


def _validated_email(value: object) -> str:
    text = str(value or "").strip()
    if text and not re.fullmatch(r"[^@\s]+@[^@\s]+", text):
        message = "The email address does not look valid."
        raise ValueError(message)
    return text


def _validated_bw_path(value: object) -> str:
    """bw_path: empty/whitespace falls back to the default ``bw`` (PATH lookup)."""
    return (str(value or "").strip()) or "bw"


def _validated_folder_list(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        message = "output.target_folders must be a list of paths"
        raise ValueError(message)  # noqa: TRY004 - one user-presentable error type
    return [str(item) for item in value if str(item).strip()]
