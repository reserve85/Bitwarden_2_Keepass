# ruff: noqa: SLF001 - GUI tests intentionally drive private member internals

"""Worker tests (offscreen) - 2FA queue round-trip, password wiping, delegation."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import pytest

from app.domain.entities import ExportRequest
from app.presentation.workers import (
    ExportWorker,
    LoginWorker,
    UpdateCheckWorker,
    UpdateDownloadWorker,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


class FakeLoginUseCase:
    def __init__(self, *, two_factor: bool = False, session: str = "session-1") -> None:
        self.two_factor = two_factor
        self.session = session
        self.run_count = 0
        self.captured_email: str | None = None
        self.closed: list[str] = []
        self.totp_codes: list[str] = []

    def run(self, _url: str, email: str, _password: bytearray, request_totp: object) -> str:
        self.run_count += 1
        self.captured_email = email
        if self.two_factor and self.run_count == 1:
            # mimics BwLoginUseCase: 2FA prompts happen INSIDE use_case.run
            self.totp_codes.append(request_totp())
        return self.session

    def close(self, session: str) -> None:
        self.closed.append(session)


class FakeExportUseCase:
    def __init__(self, result: object) -> None:
        self.result = result
        self.request: ExportRequest | None = None

    def run(self, request: ExportRequest, _progress: object) -> object:
        self.request = request
        return self.result


@pytest.mark.offscreen
class TestLoginWorker:
    def test_success_and_password_wiped(self, qapp: QApplication) -> None:
        use_case = FakeLoginUseCase()
        worker = LoginWorker(use_case, "https://bitwarden.eu", "user@example.com")
        worker.set_password(bytearray(b"pw"))
        results: list[None] = []
        worker.finished_result.connect(results.append)

        worker.start()
        assert worker.wait(10_000)
        qapp.processEvents()

        # the session is a wake-up ONLY - it rides the attribute, never the signal
        assert results == [None]
        assert worker.session == "session-1"
        assert use_case.captured_email == "user@example.com"
        # hand-off attribute survives for the MainWindow
        assert worker.session == "session-1"
        # the worker does NOT close the session (MainWindow does after export)
        assert use_case.closed == []
        assert len(worker._password) == 0  # wiped in run()'s finally

    def test_two_factor_round_trip(self, qapp: QApplication) -> None:
        use_case = FakeLoginUseCase(two_factor=True)
        worker = LoginWorker(use_case, "url", "email")
        worker.set_password(bytearray(b"pw"))
        fired: list[bool] = []
        worker.two_factor_required.connect(lambda: fired.append(True))
        results: list[None] = []
        worker.finished_result.connect(results.append)

        worker.start()
        deadline = time.monotonic() + 5
        while not fired and not results and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(0.01)

        assert fired, "two_factor_required was never emitted"
        worker.submit_totp("123456")

        assert worker.wait(10_000)
        qapp.processEvents()
        assert results == [None]  # session travels as an attribute, never a payload
        assert worker.session == "session-1"
        assert use_case.run_count == 1  # 2FA prompts happen inside use_case.run
        assert use_case.totp_codes == ["123456"]

    def test_cancelled_code_reports_failure(self, qapp: QApplication) -> None:
        use_case = FakeLoginUseCase(two_factor=True)
        worker = LoginWorker(use_case, "url", "email")
        worker.set_password(bytearray(b"pw"))
        errors: list[str] = []
        worker.failed.connect(errors.append)

        worker.start()
        deadline = time.monotonic() + 5
        while not errors and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(0.01)

        # simulate the user closing the dialog without a code
        worker.submit_totp("")
        assert worker.wait(10_000)
        qapp.processEvents()

        assert errors
        assert "cancelled" in errors[0]


@pytest.mark.offscreen
class TestExportWorker:
    def test_decodes_password_and_wipes_after_run(self, qapp: QApplication, tmp_path: Path) -> None:
        result = object()
        use_case = FakeExportUseCase(result)
        worker = ExportWorker(use_case)  # type: ignore[arg-type]
        request = ExportRequest(
            url="https://bitwarden.eu",
            email="u@example.com",
            session="session-1",
            master_password="",
            output_folder=tmp_path,
            target_folders=(),
            delete_after_copy=False,
        )
        worker.set_request(request, bytearray(b"kp-password"))
        results: list[Any] = []
        worker.finished_result.connect(results.append)

        worker.start()
        assert worker.wait(10_000)
        qapp.processEvents()

        assert results == [result]
        assert use_case.request.master_password == "kp-password"
        assert len(worker._master_password) == 0  # wiped

    def test_without_request_fails_cleanly(self, qapp: QApplication) -> None:
        worker = ExportWorker(FakeExportUseCase(object()))  # type: ignore[arg-type]
        errors: list[str] = []
        worker.failed.connect(errors.append)

        worker.start()
        assert worker.wait(10_000)
        qapp.processEvents()

        assert errors
        assert "request" in errors[0]


@pytest.mark.offscreen
class TestUpdateWorkers:
    def test_update_check_worker_delivers_result(self, qapp: QApplication) -> None:
        class FakeCheck:
            def run(self) -> dict:
                return {"has_update": False}

        worker = UpdateCheckWorker(FakeCheck())  # type: ignore[arg-type]
        results: list[dict] = []
        worker.finished_result.connect(results.append)

        worker.start()
        assert worker.wait(10_000)
        qapp.processEvents()

        assert results == [{"has_update": False}]

    def test_update_download_worker_delivers_result(self, qapp: QApplication) -> None:
        class FakeApply:
            def run(
                self,
                _url: str,
                _token: str,
                progress_callback: Callable[[int, int], None],
            ) -> bool:
                progress_callback(50, 100)
                return True

        worker = UpdateDownloadWorker(FakeApply(), "https://example.com/x.zip")  # type: ignore[arg-type]
        progress: list[tuple[int, int]] = []
        results: list[bool] = []
        worker.progress.connect(lambda current, total: progress.append((current, total)))
        worker.finished_result.connect(results.append)

        worker.start()
        assert worker.wait(10_000)
        qapp.processEvents()

        assert results == [True]
        assert progress == [(50, 100)]
