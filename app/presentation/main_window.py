"""MainWindow - navigation + export/update orchestration (reference pattern).

Wires the use cases/ports handed in as ``services``; owns the worker
lifecycles, the 2FA dialog round-trip and the deferred session close. Secrets
travel only as worker attributes/bytearrays - never via ``pyqtSignal``.

# reference pattern
"""

from __future__ import annotations

import queue
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QMessageBox,
    QProgressDialog,
    QStackedWidget,
)

from app._version import __version__
from app.application.use_cases.export import export_filename
from app.application.use_cases.settings import is_unencrypted_url
from app.domain.entities import ExportRequest, LogCategory, LogLevel
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

#: How long the export worker waits for an answer to the overwrite question.
_PROMPT_TIMEOUT_SECONDS = 600
#: How many skipped items / notices the result dialog lists verbatim.
_MAX_LISTED_LINES = 15


class _LogBridge(QObject):
    """Marshals AppLogger lines to the GUI thread via a queued signal."""

    line_received = pyqtSignal(str)

    def emit_line(self, line: str) -> None:
        self.line_received.emit(line)


class _OverwritePrompt(QObject):
    """Deadlock-free overwrite question (called from the ExportWorker thread).

    ``ask()`` is invoked inside the worker thread while copying; it emits a
    queued signal and BLOCKS on a queue of its own until the GUI thread
    answers the modal QMessageBox. Every question gets its own id and answer
    queue: an answer that arrives after the worker gave up (timeout) is
    dropped and can never be mistaken for the answer to a LATER question.
    No nested event loops in the worker - same pattern as the 2FA round-trip.
    """

    requested = pyqtSignal(int, object)  # request id, Path

    def __init__(self, parent_window: QMainWindow) -> None:
        super().__init__(parent_window)
        self._window = parent_window
        self._lock = threading.Lock()
        self._pending: dict[int, queue.Queue[bool]] = {}
        self._next_id = 0
        self._declining = False
        self.requested.connect(self._on_requested)

    def ask(self, destination: Path) -> bool:
        answers: queue.Queue[bool] = queue.Queue()
        with self._lock:
            if self._declining:
                return False
            self._next_id += 1
            request_id = self._next_id
            self._pending[request_id] = answers
        self.requested.emit(request_id, destination)
        try:
            return answers.get(timeout=_PROMPT_TIMEOUT_SECONDS)
        except queue.Empty:
            # No GUI answer in time: never overwrite - treat as "Skip".
            return False
        finally:
            with self._lock:
                self._pending.pop(request_id, None)

    def decline_all(self) -> None:
        """App is closing: answer every pending and future question with "no"."""
        with self._lock:
            self._declining = True
            pending = list(self._pending.values())
        for answers in pending:
            answers.put(item=False)

    def _on_requested(self, request_id: int, destination: Path) -> None:
        with self._lock:
            if request_id not in self._pending:
                return  # the worker already gave up on this question
        answer = QMessageBox.question(
            self._window,
            "Overwrite file?",
            f"{destination.name} already exists in {destination.parent}.\n"
            "Overwrite it with the new export?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        with self._lock:
            answers = self._pending.get(request_id)
        if answers is not None:
            answers.put(answer == QMessageBox.StandardButton.Yes)


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
        self._export_settings: dict[str, Any] = {}
        self._manual_update_check = False
        self._closing = False

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
        update_action.triggered.connect(lambda: self.start_update_check(manual=True))

        self.main_page.start_button.clicked.connect(self.start_export)
        self.settings_page.save_requested.connect(self._on_settings_save)

        # Show the persisted settings (config/app_config.yaml) in the form. Without
        # this the page starts blank and the next Save would overwrite the stored
        # values with the form defaults.
        self.settings_page.populate(self._services.settings_use_case.get_all())

        # -- logger -> GUI bridge ---------------------------------------------------
        self._log_bridge = _LogBridge(self)
        self._log_bridge.line_received.connect(self.log_page.panel.add_line)
        # Lines logged before the window existed (startup warnings) are replayed.
        history = getattr(services.logger, "history", None)
        if callable(history):
            for line in history():
                self.log_page.panel.add_line(line)
        services.logger.install_gui_handler(self._log_bridge.emit_line)

    # -- navigation / status ---------------------------------------------------
    def _show_page(self, index: int) -> None:
        self._stack.setCurrentIndex(index)

    def _set_busy(self, *, busy: bool) -> None:
        self.main_page.set_busy(busy=busy)

    def _export_in_progress(self) -> bool:
        """True from the login start until the export finished or failed."""
        return (
            self._login_worker is not None
            or self._export_worker is not None
            or self._export_session is not None
        )

    def _log(self, message: str, level: LogLevel = LogLevel.INFO) -> None:
        self._services.logger.log(LogCategory.GUI, level, message)

    # -- settings ---------------------------------------------------------------
    def _on_settings_save(self, values: dict) -> None:
        try:
            saved = self._services.settings_use_case.update(values)
        except ValueError as exc:
            self.settings_page.set_status(str(exc), error=True)
            return
        except Exception as exc:
            # e.g. the config file is not writable - never fail silently.
            self.settings_page.set_status(f"Could not save the settings: {exc}", error=True)
            self._log(f"Could not save the settings: {exc}", LogLevel.ERROR)
            return
        if is_unencrypted_url(str(saved.get("bitwarden.url") or "")):
            self.settings_page.set_status(
                "Settings saved. Warning: the server URL uses http:// - your login "
                "data would be sent unencrypted. Use https:// if at all possible.",
                error=True,
            )
        else:
            self.settings_page.set_status("Settings saved.")
        # Reflect normalized values (e.g. empty bw_path -> "bw", absolute output
        # folder) so the form always shows exactly what was persisted.
        self.settings_page.populate(saved)

    # -- update flow --------------------------------------------------------------
    def trigger_startup_update_check(self) -> None:
        """Deferred startup check (privacy opt-out via update.check_at_startup)."""
        settings = self._services.settings_use_case.get_all()
        if not bool(settings.get("update.check_at_startup", True)):
            return
        # Delay source is the composition root (single definition, see main.py).
        delay_ms = int(getattr(self._services, "update_check_delay_ms", 2000))
        QTimer.singleShot(delay_ms, self.start_update_check)

    def start_update_check(self, *, manual: bool = False) -> None:
        """Check for a newer release; *manual* checks always report their outcome."""
        if self._update_check_worker is not None or self._update_download_worker is not None:
            return
        self._manual_update_check = manual
        worker = UpdateCheckWorker(self._services.check_updates_use_case, self)
        worker.finished_result.connect(self._on_update_check_result)
        worker.failed.connect(self._on_update_check_failed)
        self._update_check_worker = worker
        if manual:
            self.statusBar().showMessage("Checking for updates...")
        worker.start()

    def _on_update_check_result(self, result: dict) -> None:
        self._update_check_worker = None
        self.statusBar().clearMessage()
        if not result.get("has_update"):
            self.statusBar().showMessage("No update available.", 5000)
            if self._manual_update_check:
                QMessageBox.information(
                    self,
                    "Check for Updates",
                    f"You are running the latest version (v{__version__}).",
                )
            return
        if self._export_in_progress():
            # Never interrupt a running export with an update prompt.
            self.statusBar().showMessage(
                "An update is available - check again after the export.",
                8000,
            )
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
        self.statusBar().clearMessage()
        self._log(f"Update check failed: {message}", LogLevel.WARNING)
        if self._manual_update_check:
            ErrorDialog(message, title="Update check failed", parent=self).exec()

    def _start_update_download(self, url: str) -> None:
        if not url:
            ErrorDialog("The release does not provide a download URL.", parent=self).exec()
            return
        if self._export_in_progress():
            ErrorDialog("Please wait until the running export has finished.", parent=self).exec()
            return
        dialog = QProgressDialog("Downloading update...", None, 0, 100, self)
        dialog.setWindowTitle("Update")
        dialog.setWindowModality(Qt.WindowModality.WindowModal)
        # The dialog is closed explicitly once the update is applied or failed;
        # auto-reset would blank the bar as soon as the download hits 100 %.
        dialog.setAutoClose(False)
        dialog.setAutoReset(False)
        dialog.setMinimumDuration(0)
        dialog.setValue(0)
        self._update_dialog = dialog

        worker = UpdateDownloadWorker(
            self._services.apply_update_use_case,
            url,
            parent=self,
        )
        worker.progress.connect(dialog.setValue)
        worker.finished_result.connect(self._on_update_applied)
        worker.failed.connect(self._on_update_failed)
        self._update_download_worker = worker
        worker.start()

    def _close_update_dialog(self) -> None:
        if self._update_dialog is not None:
            self._update_dialog.close()
            self._update_dialog = None

    def _on_update_applied(self, _applied: bool) -> None:  # noqa: FBT001 - bool arrives from the signal
        self._update_download_worker = None
        self._close_update_dialog()
        self._log("Update staged - closing so the new version can be swapped in.")
        if self._closing:
            self._finish_closing()
            return
        QMessageBox.information(
            self,
            "Update installed",
            "The update was downloaded and verified.\n\n"
            "The app closes now so the new version can be put in place. "
            "Please start it again in a few seconds.",
        )
        # A normal shutdown (not os._exit): the bw data folder is wiped and the
        # lock released; the detached helper swaps the exe once we are gone.
        self._closing = True
        self.close()
        QApplication.quit()

    def _on_update_failed(self, message: str) -> None:
        self._update_download_worker = None
        self._close_update_dialog()
        self._log(f"Update failed: {message}", LogLevel.ERROR)
        if self._closing:
            self._finish_closing()
            return
        ErrorDialog(message, title="Update failed", parent=self).exec()

    # -- export flow ---------------------------------------------------------------
    def start_export(self) -> None:
        """Validate settings -> ask passwords -> LoginWorker -> ExportWorker."""
        if self._export_in_progress() or self._update_download_worker is not None:
            return
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

        if not self._confirm_bw_binary():
            return
        if not self._confirm_replace_existing(Path(output_folder)):
            return

        password_dialog = PasswordDialog(f"Log in to Bitwarden as {email}", self)
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
        self.main_page.set_summary("")
        self._set_busy(busy=True)
        self._log(f"Logging in to {url} ...")
        worker.start()

    def _confirm_bw_binary(self) -> bool:
        """Resolve + sanity-check bw; ask before using one from a risky location.

        The bw_cli and the warning callable arrive via services (duck-typed):
        presentation never imports infrastructure.
        """
        try:
            resolved = self._services.bw_cli.resolve_and_validate()
        except Exception as exc:
            ErrorDialog(str(exc), parent=self).exec()
            self._show_page(1)
            return False
        warn = getattr(self._services, "bw_warning", None)
        warning = warn(resolved) if callable(warn) else None
        if not warning:
            return True
        self._log(warning, LogLevel.WARNING)
        answer = QMessageBox.warning(
            self,
            "Check the bw CLI location",
            f"{warning}\n\nYour master password will be handed to this program. Use it anyway?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            self._show_page(1)
            return False
        return True

    def _confirm_replace_existing(self, output_folder: Path) -> bool:
        """Ask before today's earlier export is replaced by a new one."""
        existing = output_folder / export_filename()
        if not existing.exists():
            return True
        answer = QMessageBox.question(
            self,
            "Replace today's export?",
            f"{existing.name} already exists in {existing.parent}.\n"
            "It will be replaced once the new export is complete and verified. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return answer == QMessageBox.StandardButton.Yes

    def _on_two_factor_required(self) -> None:
        """GUI slot: show the TOTP dialog and unblock the worker via the queue."""
        # Keep a local reference: the worker may fail (time out) while the
        # dialog is still open, which resets ``self._login_worker``.
        worker = self._login_worker
        if worker is None:
            return
        if self._closing:
            worker.submit_totp("")
            return
        dialog = TwoFactorDialog(self)
        code = dialog.get_code()
        worker.submit_totp(code or "")

    def _on_login_finished(self, _session_payload: object) -> None:
        worker = self._login_worker
        if worker is None:
            return
        # The session is read as an ATTRIBUTE (never transported via signals).
        session = worker.session
        self._export_session = session
        self._login_worker = None
        self._set_busy(busy=False)

        if self._closing:
            self._close_session()
            self._finish_closing()
            return
        if not session:
            self._export_session = None
            ErrorDialog("bw login returned no session.", title="Login failed", parent=self).exec()
            return

        confirm = ConfirmPasswordDialog(
            "Create the master password for the new KeePass database.",
            self,
        )
        kp_password = confirm.get_password()
        if kp_password is None:
            self._close_session()
            return

        settings = self._export_settings
        request = ExportRequest(
            url=settings["url"],
            email=settings["email"],
            session=session,
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
        if self._closing:
            self._finish_closing()
            return
        ErrorDialog(message, title="Login failed", parent=self).exec()

    def _on_export_done(self, result: ExportResult) -> None:
        self._export_worker = None
        self._set_busy(busy=False)
        self._close_session()
        if self._closing:
            self._finish_closing()
            return

        copied = [outcome for outcome in result.copies if outcome.copied]
        skipped_copies = [outcome for outcome in result.copies if outcome.skipped]
        failed = [
            outcome for outcome in result.copies if not outcome.copied and not outcome.skipped
        ]
        skipped_items = list(result.skipped_items)
        notices = list(result.notices)

        name = Path(result.path).name
        summary = f"Export finished: {name}\n"
        summary += f"{result.entry_count} of {result.item_total} vault item(s) exported."
        if skipped_items:
            summary += f"\nNOT exported: {len(skipped_items)} item(s) - see the log."
        if notices:
            summary += f"\n{len(notices)} item detail(s) could not be exported 1:1 - see the log."
        summary += f"\nIdentical copies in {len(copied)} destination(s)."
        if skipped_copies:
            summary += f"\nSkipped {len(skipped_copies)} existing file(s)."
        if failed:
            summary += f"\n{len(failed)} destination(s) failed - see the log."
        if result.source_deleted:
            summary += "\nSource file deleted after all copies were verified."
        self.main_page.set_summary(summary)
        self.statusBar().showMessage("Export finished.", 8000)
        for outcome in failed:
            self._log(
                f"Copy failed for {outcome.destination}: {outcome.error}",
                LogLevel.ERROR,
            )
        self._log(f"Export finished: {name}")

        if skipped_items or notices or failed:
            self._show_incomplete_export(skipped_items, notices, len(failed))

    def _show_incomplete_export(
        self,
        skipped_items: list[str],
        notices: list[str],
        failed_copies: int,
    ) -> None:
        """Tell the user explicitly what is missing from the backup."""

        def listed(lines: list[str]) -> str:
            shown = "\n".join(f"- {line}" for line in lines[:_MAX_LISTED_LINES])
            rest = len(lines) - _MAX_LISTED_LINES
            return shown + (f"\n... and {rest} more (see the log)" if rest > 0 else "")

        parts: list[str] = []
        if skipped_items:
            parts.append(
                f"{len(skipped_items)} vault item(s) could NOT be exported:\n"
                + listed(skipped_items),
            )
        if notices:
            parts.append(
                f"{len(notices)} detail(s) could not be exported 1:1:\n" + listed(notices),
            )
        if failed_copies:
            parts.append(f"{failed_copies} target folder(s) did not receive a copy (see the log).")
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Export finished with warnings")
        box.setText("The export finished, but it is not a complete 1:1 copy of your vault.")
        box.setDetailedText("\n\n".join(parts))
        box.setInformativeText("Open 'Show Details' or the Log page for the full list.")
        box.exec()

    def _on_export_failed(self, message: str) -> None:
        self._export_worker = None
        self._set_busy(busy=False)
        self._close_session()
        self._log(f"Export failed: {message}", LogLevel.ERROR)
        if self._closing:
            self._finish_closing()
            return
        self.main_page.set_status("Export failed.")
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

    # -- shutdown --------------------------------------------------------------------
    def _finish_closing(self) -> None:
        """Quit once a close was requested and no worker is running any more."""
        if (
            self._closing
            and self._login_worker is None
            and self._export_worker is None
            and self._update_download_worker is None
        ):
            self.close()
            QApplication.quit()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt override name
        """Window close: never tear the app down under a running worker.

        A running login/export is cancelled first (the export stops at its
        next step and removes its partial file); the window hides and the app
        quits as soon as the worker has returned and the session is closed.
        """
        working = self._login_worker is not None or self._export_worker is not None
        if self._update_download_worker is not None:
            working = True
        if not working:
            self._close_session()
            super().closeEvent(event)
            return

        if not self._closing:
            answer = QMessageBox.question(
                self,
                "Quit?",
                "An export or update is still running.\nCancel it and quit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self._closing = True
            self._overwrite_prompt.decline_all()
            if self._export_worker is not None:
                self._export_worker.requestInterruption()
            if self._login_worker is not None:
                self._login_worker.submit_totp("")  # unblock a pending 2FA wait
            self._log("Quit requested - waiting for the running task to stop.")
        # Stay alive (hidden) until the worker's finished/failed slot ran.
        event.ignore()
        self.hide()
