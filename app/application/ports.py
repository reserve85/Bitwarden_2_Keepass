"""Application-layer ports - the ONLY thing use cases may import.

Dependency rule: ``application`` imports nothing from ``infrastructure``. The
composition root (``main.py``) wires concrete implementations in and tests
inject fakes - both through these structural interfaces. Duck-typed like the
reference project: a ``Protocol`` is documentation plus static checking,
nothing is enforced at runtime.

# reference pattern
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from typing import Any

    from pykeepass import PyKeePass
    from pykeepass.group import Group as KPGroup

    from app.domain.entities import CopyOutcome, LogCategory, LogLevel
    from app.infrastructure.kdbx.item import Item


class BwAuthPort(Protocol):
    """Auth surface of the bw CLI (implemented by ``BwCli``)."""

    def resolve_and_validate(self) -> Path: ...

    def config_server(self, url: str) -> None: ...

    def login(
        self,
        email: str,
        password: bytearray,
        method: str | None = None,
        code: str | None = None,
    ) -> str: ...

    def lock(self) -> None: ...

    def logout(self) -> None: ...


class BwDataPort(Protocol):
    """Vault-data surface of the bw CLI (implemented by ``BwClient``).

    The session rides inside the implementation (via ``BW_SESSION``) - it is
    never a parameter here.
    """

    def sync(self) -> None: ...

    def list_folders(self) -> list[dict]: ...

    def list_items(self) -> list[dict]: ...

    def get_attachment(self, item_id: str, attachment_id: str) -> bytes: ...


class BwPort(BwAuthPort, BwDataPort, Protocol):
    """The full bw surface; used by fakes and merged adapters."""


class KdbxPort(Protocol):
    """KeePass export engine (implemented by ``KdbxWriter``)."""

    def create(self, path: Path, master_password: str) -> PyKeePass: ...

    def load_folders(self, kp: PyKeePass, folders: list[dict]) -> dict[str | None, KPGroup]: ...

    def set_attachment_source(self, source: Callable[[str, str], bytes]) -> None: ...

    def add_entry(
        self,
        kp: PyKeePass,
        groups_by_id: dict[str | None, KPGroup],
        item: Item | dict,
    ) -> None: ...

    def save(self, kp: PyKeePass, path: Path) -> None: ...

    def verify(self, path: Path, master_password: str) -> int: ...


class OutputPort(Protocol):
    """File-copy + verification surface (implemented by ``OutputHandler``)."""

    def copy(self, source: Path, destinations: list[Path]) -> list[CopyOutcome]: ...

    def file_sha256(self, path: Path) -> str: ...

    def delete_source(self, source: Path) -> None: ...


class LoggerPort(Protocol):
    """The in-memory ring-buffer logger (implemented by ``AppLogger``)."""

    def log(self, category: LogCategory, level: LogLevel, message: str) -> None: ...


class SettingsPort(Protocol):
    """Persistent app settings (implemented by ``YamlAppSettings``)."""

    def get(self, key: str, default: Any = None) -> Any:  # noqa: ANN401 - settings values are untyped by design
        ...

    def set(self, key: str, value: Any) -> None:  # noqa: ANN401 - settings values are untyped by design
        ...

    def to_dict(self) -> dict: ...


class UpdatePort(Protocol):
    """Self-update pipeline (implemented by ``GithubUpdateAdapter``)."""

    def check(self, token: str = "") -> dict: ...

    def download(
        self,
        url: str,
        token: str = "",
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> str: ...

    def apply(self, downloaded: Path) -> bool: ...

    def restart(self) -> None: ...

    def clean_old_files(self) -> None: ...
