"""Domain entities and value objects.

The domain layer depends on nothing. Enum members are declared with explicit
``= "..."`` values on purpose: a bare comma-list in an Enum class body is a
discarded tuple and produces an EMPTY enum.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class TwoFactorRequired(RuntimeError):  # noqa: N818 - ported name, plan-mandated
    """Signaled by the bw adapter when the CLI asks for a 2FA code.

    Defined in the domain so the application layer can catch it without
    importing infrastructure (``app.infrastructure.bw.bw_cli`` re-exports it
    for backwards compat with the adapter).
    """


class LogLevel(str, Enum):  # noqa: UP042 - explicit str/Enum per plan
    """Severity levels - reference values."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogCategory(str, Enum):  # noqa: UP042 - explicit str/Enum per plan
    """Domain-specific log categories."""

    STARTUP = "STARTUP"
    SHUTDOWN = "SHUTDOWN"
    AUTH = "AUTH"
    TOTP = "TOTP"
    SYNC = "SYNC"
    EXPORT = "EXPORT"
    KDBX = "KDBX"
    COPY = "COPY"
    CONFIG = "CONFIG"
    UPDATE = "UPDATE"
    GUI = "GUI"
    SECURITY = "SECURITY"
    ERROR = "ERROR"
    WIPE = "WIPE"


class ExportPhase(str, Enum):  # noqa: UP042 - explicit str/Enum per plan
    """Progress phases of one export run."""

    LOGIN = "LOGIN"  # emitted by LoginWorker via its progress signal
    SYNC = "SYNC"
    FOLDERS = "FOLDERS"
    ITEMS = "ITEMS"
    SAVE = "SAVE"
    VERIFY = "VERIFY"
    COPY = "COPY"
    DONE = "DONE"


@dataclass(frozen=True, slots=True)
class ExportProgress:
    """One progress sample; human-readable and NEVER containing secrets."""

    phase: ExportPhase
    current: int
    total: int  # 0 == indeterminate
    message: str  # human-readable, NEVER contains secrets
    fraction: float = 0.0  # 0..1 for the QProgressBar, also during LOGIN phase


@dataclass(frozen=True, slots=True)
class CopyOutcome:
    """Outcome of copying the export file into one destination folder."""

    destination: str
    copied: bool
    skipped: bool = False  # user chose "Skip"
    error: str = ""  # never a secret; paths are fine
    sha256: str = ""  # content hash (source == dest) when copied


@dataclass(frozen=True, slots=True)
class ExportResult:
    """Outcome of a complete export run."""

    path: str
    copies: list[CopyOutcome]
    source_deleted: bool = False


@dataclass(frozen=True, slots=True)
class UpdateCheckInfo:
    """Thin wrapper around the ``as_dict`` bridge of ``github_updater``."""

    has_update: bool
    latest_version: str
    download_url: str
    release_notes: str
    error: str


@dataclass(frozen=True, slots=True)
class ExportRequest:
    """Everything the export use case needs - replaces a 10-arg signature.

    ``session`` is the RAM-only bw session key from ``BwLoginUseCase``;
    ``master_password`` is the KeePass master password (pykeepass API is str).
    ``target_folders`` are the unlimited additional destination folders.
    """

    url: str
    email: str
    session: str  # RAM-only bw session key (from BwLoginUseCase)
    master_password: str  # KeePass master password (pykeepass API is str)
    output_folder: Path
    target_folders: tuple[Path, ...]
    delete_after_copy: bool = False
