"""Validated read/update/persist of the app settings (reference shape).

Weird-URL and empty-bw_path are the two validation axes: the server URL must
be http(s), an empty bw path falls back to the default ``bw`` (PATH lookup at
use time), and a malformed value is rejected with a plain ``ValueError``
before anything is written - so a typo can never corrupt the persisted
config. Values are persisted ONLY on an explicit Save (the SettingsPage calls
``update``); ``get_all`` is a plain mirror for the GUI.

# reference pattern
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

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
            "update.token",
            "update.check_at_startup",
        }
        validated: dict[str, Any] = {}
        for key, value in changes.items():
            if key not in known:
                message = f"Unknown setting: {key}"
                raise ValueError(message)
            if key == "bitwarden.url":
                validated[key] = _validated_url(value)
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
    if text and not text.startswith(("http://", "https://")):
        message = "bitwarden.url must start with http:// or https://"
        raise ValueError(message)
    return text


def _validated_bw_path(value: object) -> str:
    """bw_path: empty/whitespace falls back to the default ``bw`` (PATH lookup)."""
    return (str(value or "").strip()) or "bw"


def _validated_folder_list(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        raise TypeError("output.target_folders must be a list of paths")
    return [str(item) for item in value if str(item).strip()]
