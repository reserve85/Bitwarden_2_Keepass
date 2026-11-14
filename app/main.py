"""Composition root - paths -> settings -> logger -> use cases -> MainWindow.

Mirrors the reference ``main.py``: single-instance guard via ``QLockFile``,
custom ``excepthook`` into the in-memory logger, startup update check after
``_UPDATE_CHECK_DELAY_MS``. The services object is duck-typed - the window
reads the exact attributes it needs.

# reference pattern
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

if not __package__:  # direct ``python app/main.py`` launch
    # When executed as a script, sys.path[0] is the ``app/`` directory and the
    # ``app`` package itself would not be importable without this bootstrap.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PyQt6.QtCore import QLockFile
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication, QMessageBox

from app._version import __version__
from app.application.use_cases.auth import BwLoginUseCase
from app.application.use_cases.export import ExportVaultUseCase
from app.application.use_cases.settings import SettingsUseCase
from app.application.use_cases.updates import (
    ApplyUpdateUseCase,
    CheckForUpdatesUseCase,
)
from app.domain.entities import LogCategory, LogLevel
from app.infrastructure.bw.bw_cli import BwCli, BwClient, user_writable_warning
from app.infrastructure.config.config_repository import YamlAppSettings
from app.infrastructure.kdbx.kdbx_writer import KdbxWriter
from app.infrastructure.logging.app_logger import AppLogger
from app.infrastructure.output.output_handler import OutputHandler
from app.infrastructure.paths import bw_data_dir, config_file, lock_file, resource_path
from app.infrastructure.secure import redact_secrets
from app.infrastructure.updating.update_adapter import GithubUpdateAdapter
from app.presentation.main_window import MainWindow

if TYPE_CHECKING:
    from collections.abc import Callable

    from app.application.ports import BwDataPort

_UPDATE_CHECK_DELAY_MS = 2000


class Services(SimpleNamespace):
    """Duck-typed service container built by :func:`build_services`."""


def build_services() -> Services:
    """Wire every port/use case; the window reads exactly what it needs."""
    logger = AppLogger()
    settings_repo = YamlAppSettings(config_file())
    settings_use_case = SettingsUseCase(settings_repo, logger)

    def current_bw_path() -> str:
        """The bw path as configured NOW (a change in Settings applies at once)."""
        return str(settings_repo.get("bitwarden.bw_path") or "bw")

    data_folder = bw_data_dir()
    bw_cli = BwCli(current_bw_path, data_folder)
    login_use_case = BwLoginUseCase(bw_cli, logger)

    output = OutputHandler()  # overwrite prompt is wired once the window exists
    kdbx_writer = KdbxWriter()

    update_adapter = GithubUpdateAdapter(current_version=__version__)

    return Services(
        logger=logger,
        settings_use_case=settings_use_case,
        bw_cli=bw_cli,
        bw_path=current_bw_path,
        # Presentation reads the bw location guard through this seam; it never
        # imports infrastructure itself.
        bw_warning=user_writable_warning,
        login_use_case=login_use_case,
        export_use_case=None,  # filled by _wire_export_use_case (needs the window)
        check_updates_use_case=CheckForUpdatesUseCase(update_adapter, logger),
        apply_update_use_case=ApplyUpdateUseCase(update_adapter, logger),
        clean_old_files=update_adapter.clean_old_files,
        update_check_delay_ms=_UPDATE_CHECK_DELAY_MS,
        output=output,
        kdbx_writer=kdbx_writer,
        bw_data_dir=data_folder,
    )


def _wire_export_use_case(services: Services, prompt_overwrite: Callable[[Path], bool]) -> None:
    """Build ExportVaultUseCase AFTER the MainWindow exists (prompt available)."""

    def bw_client_factory(session: str) -> BwDataPort:
        return BwClient(services.bw_path, session, services.bw_data_dir)

    services.output.set_overwrite_callback(prompt_overwrite)
    services.export_use_case = ExportVaultUseCase(
        bw_client_factory=bw_client_factory,
        kdbx=services.kdbx_writer,
        output=services.output,
        logger=services.logger,
    )


def _install_excepthook(logger: AppLogger) -> None:
    """Unhandled exceptions land in the in-memory log (redacted, never to disk)."""

    def handle(exception_type: type[BaseException], exception: BaseException, _tb: object) -> None:
        message = redact_secrets(f"{exception_type.__name__}: {exception}")
        logger.log(LogCategory.ERROR, LogLevel.CRITICAL, f"Unhandled exception: {message}")

    sys.excepthook = handle


def _wipe_bw_data_folder(folder: Path) -> None:
    """Remove the app-owned bw data folder (crash leftovers, shutdown hygiene)."""
    shutil.rmtree(folder, ignore_errors=True)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Bitwarden 2 KeePass")
    app.setApplicationVersion(__version__)
    # The EXE's embedded icon only covers Explorer; the title bar, taskbar and
    # every dialog take the application-wide window icon set here.
    app.setWindowIcon(QIcon(str(resource_path("Icon.ico"))))

    # Single-instance guard + writable-folder check FIRST - nothing below may
    # run next to another live instance (it would wipe that instance's bw data
    # folder and update stages). The two failure modes are indistinguishable:
    # either another instance holds the lock, or the app folder is not
    # writable enough to create one.
    lock = QLockFile(str(lock_file()))
    # 0 = the lock never expires by age. The app holds it for its whole
    # lifetime; a crashed owner is still detected through its dead PID.
    lock.setStaleLockTime(0)
    if not lock.tryLock(50):
        QMessageBox.information(
            None,
            "Bitwarden 2 KeePass",
            "Bitwarden 2 KeePass is already running, or its folder is not "
            "writable.\n"
            "\n"
            "Make sure the app runs from a user-writable folder (not Program "
            "Files or a read-only mount), then start it again.",
        )
        return 0

    try:
        services = build_services()
        _install_excepthook(services.logger)

        # Restore a broken ``.old`` state left by an interrupted self-update
        # (best-effort like the update pipeline itself; never blocks startup).
        try:
            services.clean_old_files()
        except Exception as exc:
            services.logger.log(
                LogCategory.UPDATE,
                LogLevel.WARNING,
                f"Could not clean old update files: {redact_secrets(str(exc))}",
            )

        window = MainWindow(services)
        _wire_export_use_case(services, window.prompt_overwrite)

        # bw data hygiene: wipe leftovers of a crashed run; the bw adapter
        # recreates the folder for the next export.
        _wipe_bw_data_folder(services.bw_data_dir)

        window.show()
        window.trigger_startup_update_check()

        try:
            return app.exec()
        finally:
            _wipe_bw_data_folder(services.bw_data_dir)
    finally:
        lock.unlock()


if __name__ == "__main__":
    raise SystemExit(main())
