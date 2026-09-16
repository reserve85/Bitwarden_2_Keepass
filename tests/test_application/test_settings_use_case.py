"""SettingsUseCase tests - validation, atomic persist, no auto-save.

The use case only talks to the SettingsPort, so an in-memory fake stands in for
the YAML repository here (the real repository has its own tests).
"""

from __future__ import annotations

import pytest

from app.application.use_cases.settings import SettingsUseCase
from tests.fakes import FakeSettings, RecordingLogger


def _use_case() -> tuple[SettingsUseCase, FakeSettings, RecordingLogger]:
    settings = FakeSettings()
    logger = RecordingLogger()
    return SettingsUseCase(settings, logger), settings, logger


def test_get_all_mirrors_the_config() -> None:
    use_case, settings, _ = _use_case()
    settings.set("bitwarden.url", "https://bitwarden.eu")

    assert use_case.get_all() == {"bitwarden.url": "https://bitwarden.eu"}


def test_update_persists_all_validated_changes() -> None:
    use_case, settings, logger = _use_case()
    changes = {
        "bitwarden.url": "https://bitwarden.eu/",
        "bitwarden.email": "user@example.com",
        "bitwarden.bw_path": "bw",
        "output.delete_after_copy": True,
        "update.check_at_startup": False,
        "output.target_folders": ["C:\\vault", "D:\\backup"],
    }

    result = use_case.update(changes)

    assert result["bitwarden.url"] == "https://bitwarden.eu/"
    assert result["output.delete_after_copy"] is True
    assert result["output.target_folders"] == ["C:\\vault", "D:\\backup"]
    assert settings.updated_keys == list(changes)
    assert any(message == "Settings saved." for message in logger.messages)


def test_update_rejects_non_http_url() -> None:
    use_case, _, _ = _use_case()

    with pytest.raises(ValueError, match="http"):
        use_case.update({"bitwarden.url": "ftp://example.com"})


def test_update_strips_url_whitespace() -> None:
    use_case, _, _ = _use_case()

    result = use_case.update({"bitwarden.url": "  https://bitwarden.eu  "})

    assert result["bitwarden.url"] == "https://bitwarden.eu"


def test_update_rejects_unknown_key() -> None:
    use_case, _, _ = _use_case()

    with pytest.raises(ValueError, match="Unknown setting"):
        use_case.update({"bitwarden.passwort": "x"})


def test_update_defaults_empty_bw_path_to_bw() -> None:
    """Empty/whitespace bw_path means the default ``bw`` (PATH lookup at use time)."""
    use_case, settings, _ = _use_case()

    result = use_case.update({"bitwarden.bw_path": "   "})

    assert result["bitwarden.bw_path"] == "bw"
    assert settings.updated_keys == ["bitwarden.bw_path"]


def test_update_rejects_non_list_target_folders() -> None:
    use_case, _, _ = _use_case()

    with pytest.raises(TypeError, match="target_folders"):
        use_case.update({"output.target_folders": "C:\\vault"})
