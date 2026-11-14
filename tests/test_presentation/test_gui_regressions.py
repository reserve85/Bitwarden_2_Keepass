# ruff: noqa: SLF001, ANN401 - GUI tests drive private members and untyped Qt doubles

"""GUI regressions (offscreen): prompts, dialogs, shutdown and the update flow."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import QDialogButtonBox, QMainWindow, QMessageBox

import app.presentation.main_window as window_module
from app.application.use_cases.export import export_filename
from app.application.use_cases.settings import SettingsUseCase
from app.domain.entities import (
    CopyOutcome,
    ExportCancelled,
    ExportPhase,
    ExportProgress,
    ExportRequest,
    ExportResult,
)
from app.presentation.dialogs.twofactor_dialog import TwoFactorDialog
from app.presentation.main_window import MainWindow, _OverwritePrompt
from app.presentation.pages.main_page import MainPage
from app.presentation.workers import ExportWorker
from tests.fakes import FakeBwCli, FakeSettings, RecordingLogger

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication

pytestmark = pytest.mark.offscreen

_YES = QMessageBox.StandardButton.Yes
_NO = QMessageBox.StandardButton.No


class _Services:
    def __init__(self, tmp_path: Path) -> None:
        self.logger = RecordingLogger()
        self.settings = FakeSettings(
            initial={
                "bitwarden.url": "https://vault.example.com",
                "bitwarden.email": "user@example.com",
                "bitwarden.bw_path": "bw",
                "output.output_folder": str(tmp_path / "out"),
                "output.target_folders": [],
                "output.delete_after_copy": False,
                "update.check_at_startup": True,
            },
        )
        self.settings_use_case = SettingsUseCase(self.settings, self.logger)
        self.bw_cli = FakeBwCli()
        self.bw_warning = lambda _resolved_path: None
        self.login_use_case = object()
        self.export_use_case = object()
        self.check_updates_use_case = object()
        self.apply_update_use_case = object()


def _pump(qapp: QApplication, condition: Any, seconds: float = 5.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not condition():
        qapp.processEvents()
        time.sleep(0.01)


def _patch_boxes(monkeypatch: pytest.MonkeyPatch, answer: Any = _YES) -> list[str]:
    """Replace every modal box/dialog with a recorder (no blocking exec)."""
    shown: list[str] = []

    def record(kind: str) -> Any:
        def box(_parent: object, title: str, text: str = "", *_args: object) -> Any:
            shown.append(f"{kind}:{title}:{text}")
            return answer

        return staticmethod(box)

    for kind in ("question", "warning", "information"):
        monkeypatch.setattr(QMessageBox, kind, record(kind))
    monkeypatch.setattr(
        window_module.ErrorDialog,
        "exec",
        lambda self, *_: shown.append(f"error:{self.windowTitle()}:{self.redacted_message}") or 0,
    )
    monkeypatch.setattr(QMessageBox, "exec", lambda self, *_: shown.append(f"box:{self.text()}"))
    return shown


# -- overwrite prompt ----------------------------------------------------------


def test_late_overwrite_answer_never_reaches_the_next_question(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: a "Yes" given after the timeout was applied to the NEXT file."""
    monkeypatch.setattr(window_module, "_PROMPT_TIMEOUT_SECONDS", 0.2)
    answers = iter([_YES, _NO])

    def slow_question(*_args: object) -> Any:
        time.sleep(0.5)  # the user answers after the worker gave up
        return next(answers)

    monkeypatch.setattr(QMessageBox, "question", staticmethod(slow_question))
    prompt = _OverwritePrompt(QMainWindow())
    results: list[bool] = []

    def worker() -> None:
        results.append(prompt.ask(Path("X:/a/first.kdbx")))
        time.sleep(0.6)
        results.append(prompt.ask(Path("X:/b/second.kdbx")))

    thread = threading.Thread(target=worker)
    thread.start()
    _pump(qapp, lambda: not thread.is_alive())
    thread.join(5)

    assert results == [False, False]


def test_overwrite_prompt_declines_everything_while_closing(qapp: QApplication) -> None:
    prompt = _OverwritePrompt(QMainWindow())
    prompt.decline_all()

    assert prompt.ask(Path("X:/a/file.kdbx")) is False
    qapp.processEvents()


# -- 2FA dialog ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("typed", "expected"),
    [
        ("12", None),
        ("12345", None),
        ("123456", "123456"),
        ("123 456", "123456"),
        ("12345678", "12345678"),
    ],
)
def test_two_factor_dialog_only_accepts_complete_codes(typed: str, expected: str | None) -> None:
    dialog = TwoFactorDialog()
    dialog._line.insert(typed)  # like typing/pasting: goes through the validator
    ok = dialog._buttons.button(QDialogButtonBox.StandardButton.Ok)

    assert ok.isEnabled() is (expected is not None)
    assert dialog._collect(accepted=True) == expected


def test_two_factor_answer_after_login_failure_does_not_crash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Regression: the worker reference was gone when the dialog returned."""
    window = MainWindow(_Services(tmp_path))
    submitted: list[str] = []

    class Worker:
        def submit_totp(self, code: str) -> None:
            submitted.append(code)

    window._login_worker = Worker()  # type: ignore[assignment]

    def get_code(_self: TwoFactorDialog) -> str:
        window._login_worker = None  # the login failed while the dialog was open
        return "123456"

    monkeypatch.setattr(TwoFactorDialog, "get_code", get_code)

    window._on_two_factor_required()

    assert submitted == ["123456"]


# -- settings ----------------------------------------------------------------------


def test_settings_save_failure_is_shown_to_the_user(tmp_path: Path) -> None:
    services = _Services(tmp_path)
    window = MainWindow(services)

    def fail(_key: str, _value: object) -> None:
        message = "config file is read-only"
        raise OSError(message)

    services.settings.set = fail  # type: ignore[method-assign]

    window._on_settings_save({"bitwarden.email": "user@example.com"})

    assert "read-only" in window.settings_page._status.text()


def test_settings_save_warns_about_unencrypted_http(tmp_path: Path) -> None:
    window = MainWindow(_Services(tmp_path))

    window._on_settings_save({"bitwarden.url": "http://nas.local"})

    assert "unencrypted" in window.settings_page._status.text()


def test_startup_log_lines_are_replayed_into_the_log_page(tmp_path: Path) -> None:
    services = _Services(tmp_path)
    services.logger.history = lambda: ["early startup warning"]  # type: ignore[attr-defined]

    window = MainWindow(services)

    assert "early startup warning" in window.log_page.panel.to_plain_text()


# -- export flow -------------------------------------------------------------------


def test_risky_bw_location_asks_before_the_password_prompt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    services = _Services(tmp_path)
    services.bw_warning = lambda _path: "bw was resolved to Downloads"
    shown = _patch_boxes(monkeypatch, answer=_NO)
    asked_password: list[bool] = []
    monkeypatch.setattr(
        "app.presentation.dialogs.password_dialog.PasswordDialog.get_password",
        lambda _self: asked_password.append(True),
    )
    window = MainWindow(services)

    window.start_export()

    assert any("Downloads" in text for text in shown)
    assert asked_password == []  # declined -> the master password is never requested
    assert window._login_worker is None


def test_existing_export_of_today_requires_confirmation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / export_filename()).write_bytes(b"earlier")
    shown = _patch_boxes(monkeypatch, answer=_NO)
    window = MainWindow(_Services(tmp_path))

    window.start_export()

    assert any("Replace today's export?" in text for text in shown)
    assert window._login_worker is None


def test_export_summary_reports_skipped_items_and_notices(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Regression: the summary said "Export finished" even with dropped items."""
    shown = _patch_boxes(monkeypatch)
    window = MainWindow(_Services(tmp_path))
    result = ExportResult(
        path=str(tmp_path / "x.kdbx"),
        copies=[CopyOutcome(destination="D:/a/x.kdbx", copied=True)],
        item_total=10,
        entry_count=9,
        skipped_items=("Bank: cannot write this one",),
        notices=("Mail: passkey not exported",),
    )

    window._on_export_done(result)

    summary = window.main_page._summary.text()
    assert "9 of 10" in summary
    assert "NOT exported: 1" in summary
    assert any(text.startswith("box:") and "not a complete" in text for text in shown)


def test_clean_export_shows_no_warning_box(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    shown = _patch_boxes(monkeypatch)
    window = MainWindow(_Services(tmp_path))

    window._on_export_done(
        ExportResult(path=str(tmp_path / "x.kdbx"), copies=[], item_total=3, entry_count=3),
    )

    assert shown == []
    assert "3 of 3" in window.main_page._summary.text()


def test_progress_bar_follows_the_fraction(tmp_path: Path) -> None:
    page = MainPage()
    values = []
    for fraction in (0.8, 0.85, 0.9, 1.0):
        page.set_progress(ExportProgress(ExportPhase.SAVE, 1, 1, "x", fraction))
        values.append(page._progress.value())

    assert values == [80, 85, 90, 100]
    assert tmp_path  # fixture keeps the signature uniform


# -- shutdown ----------------------------------------------------------------------


class _BlockingExport:
    """Export double that keeps running until released (or cancelled)."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.cancelled = False

    def run(self, _request: ExportRequest, progress: Any) -> ExportResult:
        while not self.release.wait(0.02):
            try:
                progress(ExportProgress(ExportPhase.ITEMS, 1, 2, "Writing item", 0.5))
            except ExportCancelled:
                self.cancelled = True
                raise
        return ExportResult(path="x", copies=[])


class _Login:
    def __init__(self) -> None:
        self.closed: list[str] = []

    def close(self, session: str) -> None:
        self.closed.append(session)


def _start_blocking_export(window: MainWindow, export: _BlockingExport, tmp_path: Path) -> None:
    worker = ExportWorker(export, window)  # type: ignore[arg-type]
    request = ExportRequest(
        url="u",
        email="e",
        session="session-1",
        master_password="",
        output_folder=tmp_path,
        target_folders=(),
    )
    worker.set_request(request, bytearray(b"pw"))
    worker.finished_result.connect(window._on_export_done)
    worker.failed.connect(window._on_export_failed)
    window._export_worker = worker
    window._export_session = "session-1"
    worker.start()


def test_close_during_export_cancels_it_and_closes_the_session(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Regression: closing tore the app down under a running worker thread."""
    shown = _patch_boxes(monkeypatch, answer=_YES)
    quits: list[bool] = []
    monkeypatch.setattr(
        window_module.QApplication, "quit", staticmethod(lambda: quits.append(True))
    )
    services = _Services(tmp_path)
    login = _Login()
    services.login_use_case = login
    window = MainWindow(services)
    export = _BlockingExport()
    _start_blocking_export(window, export, tmp_path)
    worker = window._export_worker

    event = QCloseEvent()
    window.closeEvent(event)

    assert event.isAccepted() is False  # stays alive until the worker returned
    assert any("Quit?" in text for text in shown)
    _pump(qapp, lambda: bool(quits))
    assert worker is not None
    assert worker.wait(5000)

    assert export.cancelled is True
    assert login.closed == ["session-1"]  # bw session is logged out
    assert quits == [True]
    assert not any(text.startswith("error:") for text in shown)  # no dialog while quitting


def test_close_during_export_can_be_declined(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_boxes(monkeypatch, answer=_NO)
    services = _Services(tmp_path)
    services.login_use_case = _Login()
    window = MainWindow(services)
    export = _BlockingExport()
    _start_blocking_export(window, export, tmp_path)
    worker = window._export_worker

    event = QCloseEvent()
    window.closeEvent(event)

    assert event.isAccepted() is False
    assert window._closing is False
    assert export.cancelled is False

    export.release.set()
    assert worker is not None
    assert worker.wait(5000)
    _pump(qapp, lambda: window._export_worker is None)


def test_close_when_idle_is_accepted(tmp_path: Path) -> None:
    window = MainWindow(_Services(tmp_path))
    event = QCloseEvent()

    window.closeEvent(event)

    assert event.isAccepted() is True


# -- update flow -------------------------------------------------------------------


class _Check:
    def __init__(self, result: dict | None = None, error: str = "") -> None:
        self._result = result
        self._error = error

    def run(self) -> dict:
        if self._error:
            raise RuntimeError(self._error)
        return self._result or {"has_update": False}


def _run_check(qapp: QApplication, window: MainWindow, *, manual: bool) -> None:
    window.start_update_check(manual=manual)
    worker = window._update_check_worker
    assert worker is not None
    assert worker.wait(5000)
    _pump(qapp, lambda: window._update_check_worker is None)


def test_manual_update_check_reports_failure(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Regression: an offline check claimed "No update available"."""
    shown = _patch_boxes(monkeypatch)
    services = _Services(tmp_path)
    services.check_updates_use_case = _Check(error="Could not check for updates: offline")
    window = MainWindow(services)

    _run_check(qapp, window, manual=True)

    assert any(text.startswith("error:Update check failed") and "offline" in text for text in shown)


def test_startup_update_check_failure_stays_quiet(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    shown = _patch_boxes(monkeypatch)
    services = _Services(tmp_path)
    services.check_updates_use_case = _Check(error="offline")
    window = MainWindow(services)

    _run_check(qapp, window, manual=False)

    assert shown == []
    assert any("Update check failed" in message for message in services.logger.messages)


def test_manual_update_check_confirms_latest_version(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    shown = _patch_boxes(monkeypatch)
    services = _Services(tmp_path)
    services.check_updates_use_case = _Check()
    window = MainWindow(services)

    _run_check(qapp, window, manual=True)

    assert any("latest version" in text for text in shown)


def test_update_prompt_is_suppressed_while_an_export_runs(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    shown = _patch_boxes(monkeypatch)
    services = _Services(tmp_path)
    services.check_updates_use_case = _Check({"has_update": True, "latest_version": "9.9.9"})
    window = MainWindow(services)
    window._export_session = "session-1"  # an export is in progress

    _run_check(qapp, window, manual=False)

    assert shown == []
    window._export_session = None
