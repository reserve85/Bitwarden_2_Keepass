"""YAML-backed app settings with default merge and atomic writes.

Ported from the reference project (``app/infrastructure/config/config_repository.py``)
with the bitwarden_2_keepass config schema. The config file is the single,
inspectable registry for user changes. Missing keys are merged with defaults on
load; writes go to a temp file + ``os.replace`` so a crash can never corrupt
the config (direct-write fallback when Windows holds the target file). Path
keys are stored as absolute paths resolved from the app base dir; the output
folder defaults to ``<base>/output``.

# reference pattern
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml

#: Runtime defaults applied when a key is missing or on first run (nested).
DEFAULTS: dict[str, Any] = {
    "bitwarden": {
        "url": "https://bitwarden.eu",
        "email": "",
        "bw_path": "bw",
    },
    "output": {
        "output_folder": "",  # "" == "not configured" -> <base>/output on read
        "target_folders": [],
        "delete_after_copy": False,
    },
    "update": {
        "token": None,  # optional, encrypted by TokenCrypto (never plaintext)
        "check_at_startup": True,
    },
}

#: Flat dotted keys (used by the application layer).
DEFAULT_KEYS = [
    "bitwarden.url",
    "bitwarden.email",
    "bitwarden.bw_path",
    "output.output_folder",
    "output.target_folders",
    "output.delete_after_copy",
    "update.token",
    "update.check_at_startup",
]

#: Keys that are resolved to absolute paths relative to the app base dir.
_PATH_KEYS = {"output.output_folder"}


def _dot_get(data: dict, key: str, default: Any = None) -> Any:  # noqa: ANN401 - settings values are untyped by design
    node: Any = data
    for part in key.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _dot_set(data: dict, key: str, value: Any) -> None:  # noqa: ANN401 - settings values are untyped by design
    parts = key.split(".")
    node = data
    for part in parts[:-1]:
        child = node.setdefault(part, {})
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = value


class YamlAppSettings:
    def __init__(self, config_path: str | Path, base: Path | None = None) -> None:
        self._config_path = Path(config_path)
        self._base = Path(base) if base else self._config_path.parent.parent
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        self._data = {}
        if self._config_path.exists():
            try:
                with self._config_path.open(encoding="utf-8") as fh:
                    loaded = yaml.safe_load(fh) or {}
                self._data = loaded if isinstance(loaded, dict) else {}
            except (OSError, yaml.YAMLError):
                self._data = {}

    def _resolve_path_key(self, key: str) -> Path:
        """Absolute path for a path key; empty config value -> ``<base>/<key-folder>``."""
        raw = _dot_get(self._data, key)
        if not raw:
            return (self._base / "output").resolve()
        path = Path(str(raw))
        return path if path.is_absolute() else (self._base / path).resolve()

    def get(self, key: str, default: Any = None) -> Any:  # noqa: ANN401 - settings values are untyped by design
        fallback = default if default is not None else _dot_get(DEFAULTS, key)
        value = _dot_get(self._data, key, fallback)
        if key in _PATH_KEYS:
            return str(self._resolve_path_key(key))
        return value

    def set(self, key: str, value: Any) -> None:  # noqa: ANN401 - settings values are untyped by design
        if key in _PATH_KEYS:
            path = Path(str(value))
            value = str(path if path.is_absolute() else (self._base / path).resolve())
        _dot_set(self._data, key, value)
        self._save()

    def _save(self) -> None:
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        # Windows sometimes holds the target file (editor/AV/indexer) so an atomic
        # os.replace can raise WinError 5. We retry briefly and - as a last resort -
        # write the file directly so settings always persist.
        last_error: OSError | None = None
        for _ in range(3):
            tmp_name = ""
            try:
                fd, tmp_name = tempfile.mkstemp(
                    prefix=".app_config_",
                    suffix=".tmp",
                    dir=str(self._config_path.parent),
                )
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    yaml.safe_dump(self._data, fh, allow_unicode=True, sort_keys=False)
                try:
                    Path(tmp_name).replace(self._config_path)
                except OSError as exc:
                    last_error = exc
                else:
                    return
            except OSError as exc:
                last_error = exc
            finally:
                if tmp_name and Path(tmp_name).exists():
                    with contextlib.suppress(OSError):
                        Path(tmp_name).unlink()
            time.sleep(0.05)
        try:
            with self._config_path.open("w", encoding="utf-8") as fh:
                yaml.safe_dump(self._data, fh, allow_unicode=True, sort_keys=False)
        except OSError as exc:
            message = f"Could not save settings {self._config_path}: {exc}"
            raise OSError(message) from (last_error or exc)

    def to_dict(self) -> dict:
        return {key: self.get(key, None) for key in DEFAULT_KEYS}
