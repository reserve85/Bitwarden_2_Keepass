"""MainWindow - navigation + export/update orchestration (reference pattern).

Wires the use cases/ports handed in as ``services``; owns the worker
lifecycles, the 2FA dialog round-trip and the deferred session close. Secrets
travel only as worker attributes/bytearrays - never via ``pyqtSignal``.

# reference pattern
"""

from __future__ import annotations

import queue
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QMainWindow,
    QMessageBox,
    QProgressDialog,
    QStackedWidget,
)

from app._version import __version__
from app.domain.entities import ExportRequest, LogCategory, LogLevel
from app.infrastructure.bw.bw_cli import BwCli, user_writable_warning
from app.presentation.dialogs.confirm_password_dialog import ConfirmPasswordDialog
from app.presentation.dialogs.error_dialog import ErrorDialog
from app.presentation.dialogs.password_dialog import PasswordDialog
from app.presentation.dialogs.twofactor_dialog import TwoFactorDialog
from app.presentation.pages.log_page import LogPage
from app.presentation.pages.main_page import MainPage
from app.presentation.pages.settings_page import SettingsPage
from app.presentation.workers import (
    ExportWorker,
    LoginWorker,
    UpdateCheckWorker,
    UpdateDownloadWorker,
)

if TYPE_CHECKING:
    from PyQt6.QtGui import QCloseEvent

    from app.domain.entities import ExportResult

_UPDATE_CHECK_DELAY_MS = 2000
#: Ceiling for the worker-thread overwrite prompt (see ``_OverwritePrompt``).
_PROMPT_TIMEOUT_SECONDS = 60


class _LogBridge(QObject):
    """Marshals AppLogger lines to the GUI thread via a queued signal."""

    line_received = pyqtSignal(str)

    def emit_line(self, line: str) -> None:
        self.line_received.emit(line)


class _OverwritePrompt(QObject):
    """Deadlock-free overwrite question (called from the ExportWorker thread).

    ``ask()`` is invoked inside the worker thread while copying; it emits a
    queued signal and BLOCKS on a queue (60 s cap) until the GUI thread
    answers the modal QMessageBox. When no answer arrives (window closed while
    the prompt was pending) it times out and reports "do not overwrite", so a
    worker can never hang forever. Same pattern as the 2FA round-trip - no
    nested event loops.
    """

    requested = pyqtSignal(object)  # Path

    def __init__(self, parent_window: QMainWindow) -> None:
        super().__init__(parent_window)
        self._window = parent_window
        self._answers: queue.Queue[bool] = queue.Queue()
        self.requested.connect(self._on_requested)

    def ask(self, destination: Path) -> bool:
        self.requested.emit(destination)
        try:
            return self._answers.get(timeout=_PROMPT_TIMEOUT_SECONDS)
        except queue.Empty:
            # No GUI answer (window closed while the prompt was pending): never
            # overwrite - treat as "Skip" and let the copy loop record it.
            return False

    def _on_requested(self, destination: Path) -> None:
        answer = QMessageBox.question(
            self._window,
            "Overwrite file?",
            f"{destination.name} already exists in {destination.parent}.\n"
            "Overwrite it with the new export?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        self._answers.put(answer == QMessageBox.StandardButton.Yes)


class MainWindow(QMainWindow):
    def __init__(self, services: Any) -> None:  # noqa: ANN401 - duck-typed service container
        super().__init__()
        self._services = services
        self._login_worker: LoginWorker | None = None
        self._export_worker: ExportWorker | None = None
        self._update_check_worker: UpdateCheckWorker | None = None
        self._update_download_worker: UpdateDownloadWorker | None = None
        self._update_dialog: QProgressDialog | None = None
        self._export_session: str | None = None

        self.setWindowTitle(f"Bitwarden 2 KeePass v{__version__}")
        self.resize(780, 540)

        # Overwrite prompt used by the OutputHandler from inside the worker
        # thread (the composition root wires prompt_overwrite into it).
        self._overwrite_prompt = _OverwritePrompt(self)
        self.prompt_overwrite = self._overwrite_prompt.ask

        # -- pages ---------------------------------------------------------------
        self.main_page = MainPage(self)
        self.settings_page = SettingsPage(self)
        self.log_page = LogPage(self)

        self._stack = QStackedWidget(self)
        self._stack.addWidget(self.main_page)  # 0 - Start Export
        self._stack.addWidget(self.settings_page)  # 1 - Settings
        self._stack.addWidget(self.log_page)  # 2 - Log
        self.setCentralWidget(self._stack)

        # -- navigation ----------------------------------------------------------
        menu = self.menuBar()
        start_action = menu.addAction("Start Export")
        settings_action = menu.addAction("Settings")
        update_action = menu.addAction("Check for Updates")
        log_action = menu.addAction("Log")
        start_action.triggered.connect(lambda: self._show_page(0))
        settings_action.triggered.connect(lambda: self._show_page(1))
        log_action.triggered.connect(lambda: self._show_page(2))
        update_action.triggered.connect(self.start_update_check)

        self.main_page.start_button.clicked.connect(self.start_export)
        self.settings_page.save_requested.connect(self._on_settings_save)

        # Show the persisted settings (config/app_config.yaml) in the form. Without
        # this the page starts blank and the next Save would overwrite the stored
        # values with the form defaults.
        self.settings_page.populate(self._services.settings_use_case.get_all())

        # -- logger -> GUI bridge ---------------------------------------------------
        self._log_bridge = _LogBridge(self)
        self._log_bridge.line_received.connect(self.log_page.panel.add_line)
        services.logger.install_gui_handler(self._log_bridge.emit_line)

    # -- navigation / status ---------------------------------------------------
    def _show_page(self, index: int) -> None:
        self._stack.setCurrentIndex(index)

    def _set_busy(self, *, busy: bool) -> None:
        self.main_page.set_busy(busy=busy)

    def _log(self, message: str, level: LogLevel = LogLevel.INFO) -> None:
        self._services.logger.log(LogCategory.GUI, level, message)

    # -- settings ---------------------------------------------------------------
    def _on_settings_save(self, values: dict) -> None:
        try:
            saved = self._services.settings_use_case.update(values)
        except ValueError as exc:
            self.settings_page.set_status(str(exc), error=True)
            return
        self.settings_page.set_status("Settings saved.")
        # Reflect normalized values (e.g. empty bw_path -> "bw", absolute output
        # folder) so the form always shows exactly what was persisted.
        self.settings_page.populate(saved)
        self._log("Settings saved.")

    # -- update flow --------------------------------------------------------------
    def trigger_startup_update_check(self) -> None:
        """Deferred startup check (privacy opt-out via update.check_at_startup)."""
        settings = self._services.settings_use_case.get_all()
        if not bool(settings.get("update.check_at_startup", True)):
            return
        QTimer.singleShot(_UPDATE_CHECK_DELAY_MS, self.start_update_check)

    def start_update_check(self) -> None:
        if self._update_check_worker is not None:
            return
        worker = UpdateCheckWorker(self._services.check_updates_use_case, self)
        worker.finished_result.connect(self._on_update_check_result)
        worker.failed.connect(self._on_update_check_failed)
        self._update_check_worker = worker
        worker.start()

    def _on_update_check_result(self, result: dict) -> None:
        self._update_check_worker = None
        if not result.get("has_update"):
            self.statusBar().showMessage("No update available.", 3000)
            return
        answer = QMessageBox.question(
            self,
            "Update available",
            f"Update available (v{result.get('latest_version')}).\nDownload and install now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._start_update_download(str(result.get("download_url") or ""))

    def _on_update_check_failed(self, message: str) -> None:
        self._update_check_worker = None
        self._log(f"Update check failed: {message}", LogLevel.WARNING)

    def _start_update_download(self, url: str) -> None:
        if not url:
            ErrorDialog("The release does not provide a download URL.", parent=self).exec()
            return
        dialog = QProgressDialog("Downloading update...", None, 0, 100, self)
        dialog.setWindowTitle("Update")
        dialog.setWindowModality(Qt.WindowModality.WindowModal)
        dialog.setAutoClose(True)
        dialog.setMinimumDuration(0)
        self._update_dialog = dialog

        worker = UpdateDownloadWorker(
            self._services.apply_update_use_case,
            url,
            token=self._update_token(),
            parent=self,
        )
        worker.progress.connect(dialog.setValue)
        worker.finished_result.connect(self._on_update_applied)
        worker.failed.connect(self._on_update_failed)
        self._update_download_worker = worker
        worker.start()

    def _update_token(self) -> str:
        settings = self._services.settings_use_case.get_all()
        raw = str(settings.get("update.token") or "")
        decrypt = getattr(self._services, "token_decrypt", None)
        return decrypt(raw) if (raw and callable(decrypt)) else raw

    def _on_update_applied(self, _applied: bool) -> None:  # noqa: FBT001 - bool arrives from the signal
        self._update_download_worker = None
        if self._update_dialog is not None:
            self._update_dialog.close()
        self.statusBar().showMessage("Update applied - restarting...", 5000)
        self._log("Update applied - restarting.")
        restart = getattr(self._services, "restart_app", None)
        if callable(restart):
            restart()

    def _on_update_failed(self, message: str) -> None:
        self._update_download_worker = None
        if self._update_dialog is not None:
            self._update_dialog.close()
        self._log(f"Update failed: {message}", LogLevel.ERROR)
        ErrorDialog(message, title="Update failed", parent=self).exec()

    # -- export flow ---------------------------------------------------------------
    def start_export(self) -> None:
        """Validate settings -> ask passwords -> LoginWorker -> ExportWorker."""
        settings = self._services.settings_use_case.get_all()
        url = str(settings.get("bitwarden.url") or "").strip()
        email = str(settings.get("bitwarden.email") or "").strip()
        output_folder = str(settings.get("output.output_folder") or "").strip()
        if not (url and email and output_folder):
            ErrorDialog(
                "Please fill in the Bitwarden server URL, email and output "
                "folder in Settings first.",
                parent=self,
            ).exec()
            self._show_page(1)
            return

        # bw path + version shape + PATH-hijack warning (never a hard error).
        bw_cli: BwCli = self._services.bw_cli
        try:
            resolved = bw_cli.resolve_and_validate()
        except Exception as exc:
            ErrorDialog(str(exc), parent=self).exec()
            self._show_page(1)
            return
        warning = user_writable_warning(resolved)
        if warning:
            self._log(warning, LogLevel.WARNING)

        password_dialog = PasswordDialog(f"Log in to Bitwarden as {email}")
        password = password_dialog.get_password()
        if password is None:
            return

        self._export_settings = {
            "url": url,
            "email": email,
            "output_folder": Path(output_folder),
            "target_folders": tuple(
                Path(item) for item in (settings.get("output.target_folders") or [])
            ),
            "delete_after_copy": bool(settings.get("output.delete_after_copy")),
        }

        worker = LoginWorker(self._services.login_use_case, url, email, self)
        worker.set_password(password)
        worker.two_factor_required.connect(self._on_two_factor_required)
        worker.progress.connect(self.main_page.set_progress)
        worker.finished_result.connect(self._on_login_finished)
        worker.failed.connect(self._on_login_failed)
        self._login_worker = worker
        self._set_busy(busy=True)
        self._log(f"Logging in to {url} ...")
        worker.start()

    def _on_two_factor_required(self) -> None:
        """GUI slot: show the TOTP dialog and unblock the worker via the queue."""
        if self._login_worker is None:
            return
        dialog = TwoFactorDialog(self)
        code = dialog.get_code()
        self._login_worker.submit_totp(code or "")

    def _on_login_finished(self, _session_payload: object) -> None:
        worker = self._login_worker
        if worker is None:
            return
        # The session is read as an ATTRIBUTE (never transported via signals).
        session = worker.session
        self._export_session = session
        self._login_worker = None
        self._set_busy(busy=False)

        confirm = ConfirmPasswordDialog(
            "Create the master password for the new KeePass database.",
        )
        kp_password = confirm.get_password()
        if kp_password is None:
            self._close_session()
            return

        settings = self._export_settings
        request = ExportRequest(
            url=settings["url"],
            email=settings["email"],
            session=str(session),
            master_password="",  # filled from the bytearray by the worker
            output_folder=settings["output_folder"],
            target_folders=settings["target_folders"],
            delete_after_copy=settings["delete_after_copy"],
        )

        export_worker = ExportWorker(self._services.export_use_case, self)
        export_worker.set_request(request, kp_password)
        export_worker.progress.connect(self.main_page.set_progress)
        export_worker.finished_result.connect(self._on_export_done)
        export_worker.failed.connect(self._on_export_failed)
        self._export_worker = export_worker
        self._set_busy(busy=True)
        self._log("Starting export ...")
        export_worker.start()

    def _on_login_failed(self, message: str) -> None:
        self._login_worker = None
        self._set_busy(busy=False)
        self._log(f"Login failed: {message}", LogLevel.ERROR)
        ErrorDialog(message, title="Login failed", parent=self).exec()

    def _on_export_done(self, result: ExportResult) -> None:
        self._export_worker = None
        self._set_busy(busy=False)
        self._close_session()

        copied = [outcome for outcome in result.copies if outcome.copied]
        skipped = [outcome for outcome in result.copies if outcome.skipped]
        failed = [
            outcome for outcome in result.copies if not outcome.copied and not outcome.skipped
        ]

        name = Path(result.path).name
        summary = f"Export finished: {name}\n"
        summary += f"Identical copies in {len(copied)} destination(s)."
        if skipped:
            summary += f"\nSkipped {len(skipped)} existing file(s)."
        if failed:
            summary += f"\n{len(failed)} destination(s) failed - see the log."
        if result.source_deleted:
            summary += "\nSource file deleted after verified copies."
        self.main_page.set_summary(summary)
        self.statusBar().showMessage("Export finished.", 8000)
        for outcome in failed:
            self._log(
                f"Copy failed for {outcome.destination}: {outcome.error}",
                LogLevel.ERROR,
            )
        self._log(f"Export finished: {name}")

    def _on_export_failed(self, message: str) -> None:
        self._export_worker = None
        self._set_busy(busy=False)
        self._close_session()
        self._log(f"Export failed: {message}", LogLevel.ERROR)
        ErrorDialog(message, title="Export failed", parent=self).exec()

    def _close_session(self) -> None:
        """Best-effort session close (lock + logout) after the export is done."""
        if self._export_session is None:
            return
        try:
            self._services.login_use_case.close(self._export_session)
        except Exception:
            self._log("Could not close the bw session cleanly.", LogLevel.WARNING)
        finally:
            self._export_session = None

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt override name
        """Window close: close an in-flight session (best-effort, idempotent)."""
        self._close_session()
        super().closeEvent(event)
