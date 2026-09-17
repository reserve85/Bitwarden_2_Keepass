# ruff: noqa: SLF001 - GUI tests intentionally drive private member internals

"""MainWindow smoke tests (offscreen) - construction, navigation, settings save."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtCore import QTimer

from app._version import __version__
from app.application.use_cases.settings import SettingsUseCase
from app.domain.entities import (
    ExportPhase,
    ExportProgress,
    ExportRequest,
    ExportResult,
    LogCategory,
    LogLevel,
)
from app.presentation.main_window import MainWindow
from tests.fakes import FakeBwCli, FakeSettings, RecordingLogger

#: Number of stacked pages: Start Export / Settings / Log.
_PAGE_COUNT = 3
_PAGE_MAIN = 0
_PAGE_SETTINGS = 1
_PAGE_LOG = 2

if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


class _FakeServices:
    def __init__(self) -> None:
        self.logger = RecordingLogger()
        self.settings = FakeSettings(
            initial={
                "bitwarden.url": "https://bitwarden.eu",
                "bitwarden.email": "user@example.com",
                "bitwarden.bw_path": "bw",
                "output.output_folder": "C:\\export",
                "output.target_folders": [],
                "output.delete_after_copy": False,
                "update.check_at_startup": True,
                "update.token": None,
            },
        )
        self.settings_use_case = SettingsUseCase(self.settings, self.logger)
        self.bw_cli = FakeBwCli()
        self.bw_warning = lambda _resolved_path: None
        self.login_use_case = object()
        self.export_use_case = object()
        self.check_updates_use_case = object()
        self.apply_update_use_case = object()
        self.update_adapter = object()


@pytest.mark.offscreen
class TestMainWindow:
    def test_smoke_construction_and_navigation(self) -> None:
        services = _FakeServices()
        window = MainWindow(services)

        assert window.windowTitle() == f"Bitwarden 2 KeePass v{__version__}"
        assert window._stack.count() == _PAGE_COUNT

        window._show_page(_PAGE_SETTINGS)
        assert window._stack.currentIndex() == _PAGE_SETTINGS
        window._show_page(_PAGE_LOG)
        assert window._stack.currentIndex() == _PAGE_LOG
        window._show_page(_PAGE_MAIN)
        assert window._stack.currentIndex() == _PAGE_MAIN

    def test_logger_bridge_delivers_lines_to_panel(self, qapp: QApplication) -> None:
        services = _FakeServices()
        window = MainWindow(services)

        services.logger.log(LogCategory.GUI, LogLevel.INFO, "hello from logger")
        qapp.processEvents()

        assert "hello from logger" in window.log_page.panel.to_plain_text()

    def test_settings_page_populated_from_persisted_config_on_startup(self) -> None:
        """The form must show the loaded settings, not start blank (regression)."""
        services = _FakeServices()
        window = MainWindow(services)

        page = window.settings_page
        assert page._url.text() == "https://bitwarden.eu"
        assert page._email.text() == "user@example.com"
        assert page._bw_path.text() == "bw"
        assert page._output_folder.text() == "C:\\export"
        assert page._check_at_startup.isChecked() is True
        assert page._delete_after_copy.isChecked() is False

    def test_settings_save_flow(self) -> None:
        services = _FakeServices()
        window = MainWindow(services)

        window._on_settings_save(
            {"bitwarden.url": "https://vault.example.com", "output.delete_after_copy": True},
        )

        assert services.settings.updated_keys
        assert services.settings.to_dict()["bitwarden.url"] == "https://vault.example.com"
        assert "Settings saved" in window.settings_page._status.text()
        # the form reflects the persisted (normalized) values
        assert window.settings_page._url.text() == "https://vault.example.com"
        assert window.settings_page._delete_after_copy.isChecked() is True

    def test_settings_save_reports_value_error(self) -> None:
        services = _FakeServices()
        window = MainWindow(services)

        window._on_settings_save({"bitwarden.url": "ftp://nope"})

        assert "http" in window.settings_page._status.text()
        assert services.settings.updated_keys == []

    def test_startup_update_check_skipped_when_disabled(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        services = _FakeServices()
        services.settings.set("update.check_at_startup", value=False)
        window = MainWindow(services)
        calls: list[tuple[int, Any]] = []
        monkeypatch.setattr(
            QTimer,
            "singleShot",
            staticmethod(lambda ms, callback: calls.append((ms, callback))),
        )

        window.trigger_startup_update_check()

        assert calls == []

    def test_startup_update_check_scheduled_when_enabled(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        services = _FakeServices()
        window = MainWindow(services)
        scheduled: list[int] = []
        monkeypatch.setattr(
            QTimer,
            "singleShot",
            staticmethod(lambda ms, _callback: scheduled.append(ms)),
        )

        window.trigger_startup_update_check()

        assert scheduled == [2000]

    def test_export_guard_jumps_to_settings_when_incomplete(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        services = _FakeServices()
        services.settings.set("output.output_folder", "")
        window = MainWindow(services)
        shown: list[str] = []
        monkeypatch.setattr(
            "app.presentation.main_window.ErrorDialog.exec",
            lambda self, *_: shown.append(self.redacted_message) or 0,
        )

        window.start_export()

        assert shown
        assert window._stack.currentIndex() == _PAGE_SETTINGS  # Settings page shown


class _FlowLoginUseCase:
    """Mirror of ``BwLoginUseCase.run/close`` (used by ``LoginWorker``)."""

    def __init__(self, session: str = "session-flow") -> None:
        self.session = session
        self.closed: list[str] = []
        self.run_count = 0

    def run(
        self,
        _url: str,
        _email: str,
        _password: bytearray,
        _request_totp: object,
    ) -> str:
        self.run_count += 1
        return self.session

    def close(self, session: str) -> None:
        self.closed.append(session)


class _FlowExportUseCase:
    """Mirror of ``ExportVaultUseCase.run`` (used by ``ExportWorker``)."""

    def __init__(self) -> None:
        self.requests: list[ExportRequest] = []

    def run(self, request: ExportRequest, progress: object) -> ExportResult:
        self.requests.append(request)
        progress(
            ExportProgress(
                phase=ExportPhase.DONE,
                current=1,
                total=1,
                message="done",
                fraction=1.0,
            ),
        )
        return ExportResult(
            path=str(request.output_folder / "flow.kdbx"),
            copies=[],
            source_deleted=False,
        )


@pytest.mark.offscreen
def test_full_start_export_flow(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Click-to-complete chain: start_export -> LoginWorker -> dialogs -> ExportWorker.

    Password dialogs are patched and the use cases are scripted doubles; the bw
    session must reach the export request and be closed (lock + logout) after
    the export finishes.
    """
    services = _FakeServices()
    login = _FlowLoginUseCase()
    export = _FlowExportUseCase()
    services.login_use_case = login
    services.export_use_case = export
    services.settings.set("output.output_folder", str(tmp_path / "out"))

    monkeypatch.setattr(
        "app.presentation.dialogs.password_dialog.PasswordDialog.get_password",
        lambda _self: bytearray(b"bw-pw"),
    )
    monkeypatch.setattr(
        "app.presentation.dialogs.confirm_password_dialog.ConfirmPasswordDialog.get_password",
        lambda _self: bytearray(b"kp-pw"),
    )

    window = MainWindow(services)
    window.start_export()

    # Wait for the DEFINITIVE end-of-flow marker (session closed after the
    # export finished) - `_export_worker` is None both before the login worker
    # started and after completion, so it alone cannot gate the wait.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not login.closed:
        qapp.processEvents()
        time.sleep(0.01)

    # Join any still-running worker so a failing assertion can never leave a
    # QThread alive past the test teardown.
    for worker in (window._login_worker, window._export_worker):
        if worker is not None:
            worker.wait(2000)

    assert login.closed == ["session-flow"]
    assert login.run_count == 1
    assert export.requests, "export use case never ran"
    assert export.requests[0].session == "session-flow"
    assert export.requests[0].master_password == "kp-pw"
