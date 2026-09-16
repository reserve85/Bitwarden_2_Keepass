"""Config repository tests: default merge, atomic save, path resolution, new keys.

# Gasmeter pattern (ported test suite, bitwarden_2_keepass schema)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    import pytest

from app.infrastructure.config.config_repository import DEFAULTS, YamlAppSettings


def test_defaults_on_first_run(tmp_path: Path) -> None:
    config = tmp_path / "config" / "app_config.yaml"
    settings = YamlAppSettings(config, base=tmp_path)
    assert settings.get("bitwarden.url") == "https://bitwarden.eu"
    assert settings.get("bitwarden.email") == ""
    assert settings.get("bitwarden.bw_path") == "bw"
    assert settings.get("output.target_folders") == []
    assert settings.get("output.delete_after_copy") is False
    assert settings.get("update.token") is None
    assert settings.get("update.check_at_startup") is True


def test_get_unknown_key_returns_default(tmp_path: Path) -> None:
    settings = YamlAppSettings(tmp_path / "config" / "app_config.yaml", base=tmp_path)
    assert settings.get("bitwarden.url", "https://fallback.invalid") == "https://fallback.invalid"


def test_set_persists_atomically(tmp_path: Path) -> None:
    config = tmp_path / "config" / "app_config.yaml"
    settings = YamlAppSettings(config, base=tmp_path)
    settings.set("bitwarden.email", "me@example.com")
    reloaded = YamlAppSettings(config, base=tmp_path)
    assert reloaded.get("bitwarden.email") == "me@example.com"
    # file is valid YAML
    with config.open(encoding="utf-8") as fh:
        assert isinstance(yaml.safe_load(fh), dict)


def test_output_folder_defaults_to_base_output(tmp_path: Path) -> None:
    config = tmp_path / "config" / "app_config.yaml"
    settings = YamlAppSettings(config, base=tmp_path)
    assert Path(settings.get("output.output_folder")) == (tmp_path / "output").resolve()
    assert Path(settings.get("output.output_folder")).is_absolute()


def test_output_folder_key_resolves_absolute(tmp_path: Path) -> None:
    config = tmp_path / "config" / "app_config.yaml"
    settings = YamlAppSettings(config, base=tmp_path)
    settings.set("output.output_folder", "exports")
    assert settings.get("output.output_folder") == str((tmp_path / "exports").resolve())
    reloaded = YamlAppSettings(config, base=tmp_path)
    assert reloaded.get("output.output_folder") == str((tmp_path / "exports").resolve())


def test_output_folder_absolute_value_kept(tmp_path: Path) -> None:
    config = tmp_path / "config" / "app_config.yaml"
    settings = YamlAppSettings(config, base=tmp_path)
    absolute = tmp_path / "somewhere" / "else"
    settings.set("output.output_folder", str(absolute))
    assert settings.get("output.output_folder") == str(absolute.resolve())


def test_missing_keys_merged_on_load(tmp_path: Path) -> None:
    config = tmp_path / "config" / "app_config.yaml"
    config.parent.mkdir(parents=True)
    config.write_text("bitwarden:\n  url: https://vault.example.com\n", encoding="utf-8")
    settings = YamlAppSettings(config, base=tmp_path)
    assert settings.get("bitwarden.url") == "https://vault.example.com"
    assert settings.get("bitwarden.email", DEFAULTS["bitwarden"]["email"]) == ""
    assert settings.get("output.delete_after_copy") is False


def test_new_keys_roundtrip(tmp_path: Path) -> None:
    config = tmp_path / "config" / "app_config.yaml"
    settings = YamlAppSettings(config, base=tmp_path)
    settings.set("output.delete_after_copy", value=True)
    settings.set("update.check_at_startup", value=False)
    settings.set("output.target_folders", ["C:\\backups", "D:\\vault"])
    reloaded = YamlAppSettings(config, base=tmp_path)
    assert reloaded.get("output.delete_after_copy") is True
    assert reloaded.get("update.check_at_startup") is False
    assert reloaded.get("output.target_folders") == ["C:\\backups", "D:\\vault"]


def test_to_dict_contains_all_keys(tmp_path: Path) -> None:
    settings = YamlAppSettings(tmp_path / "config" / "app_config.yaml", base=tmp_path)
    data = settings.to_dict()
    assert set(data) == {
        "bitwarden.url",
        "bitwarden.email",
        "bitwarden.bw_path",
        "output.output_folder",
        "output.target_folders",
        "output.delete_after_copy",
        "update.token",
        "update.check_at_startup",
    }
    assert data["update.check_at_startup"] is True
    assert data["output.delete_after_copy"] is False


_REPLACE_ATTEMPTS = 3


def test_save_falls_back_when_replace_is_locked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WinError 5 on os.replace must not lose settings (direct-write fallback)."""
    config = tmp_path / "config" / "app_config.yaml"
    settings = YamlAppSettings(config, base=tmp_path)
    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    attempts = {"n": 0}

    def _locked_replace(_src: str, _dst: str) -> None:
        attempts["n"] += 1
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr("os.replace", _locked_replace)
    settings.set("bitwarden.url", "https://vault.example.com")
    assert attempts["n"] == _REPLACE_ATTEMPTS  # atomic path exhausted
    assert config.exists()
    reloaded = YamlAppSettings(config, base=tmp_path)
    assert reloaded.get("bitwarden.url") == "https://vault.example.com"
