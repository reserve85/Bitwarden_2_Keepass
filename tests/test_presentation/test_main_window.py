# ruff: noqa: SLF001 - GUI tests intentionally drive private member internals

"""MainWindow smoke tests (offscreen) - construction, navigation, settings save."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtCore import QTimer

from app._version import __version__
from app.application.use_cases.settings import SettingsUseCase
from app.domain.entities import LogCategory, LogLevel
from app.presentation.main_window import MainWindow
from tests.fakes import FakeBwCli, FakeSettings, RecordingLogger

#: Number of stacked pages: Start Export / Settings / Log.
_PAGE_COUNT = 3
_PAGE_MAIN = 0
_PAGE_SETTINGS = 1
_PAGE_LOG = 2

if TYPE_CHECKING:
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

    def test_settings_save_flow(self) -> None:
        services = _FakeServices()
        window = MainWindow(services)

        window._on_settings_save(
            {"bitwarden.url": "https://vault.example.com", "output.delete_after_copy": True},
        )

        assert services.settings.updated_keys
        assert services.settings.to_dict()["bitwarden.url"] == "https://vault.example.com"
        assert "Settings saved" in window.settings_page._status.text()

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
