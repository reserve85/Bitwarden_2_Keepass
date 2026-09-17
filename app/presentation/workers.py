"""QThread workers - all bw/network/file work, signals marshalled to the GUI.

Security invariants:
- No secret ever travels via a ``pyqtSignal``. The BW master password is a
  ``bytearray`` attribute set BEFORE ``start()``; the bw session is passed to
  the ``ExportWorker`` as an attribute (never a signal payload - the login
  worker's ``finished_result`` carries no payload at all); both are wiped in
  ``finally`` paths.
- The KeePass master password is a worker ``bytearray``; the ``str`` copy it
  must hand to pykeepass (``ExportRequest.master_password``) is created once,
  inside ``run()``, and the bytearray is wiped afterwards.

2FA round-trip (deadlock-free): ``LoginWorker.run`` calls the login use case
with ``request_totp`` = emit ``two_factor_required`` (queued to the GUI
thread) then BLOCK on a thread-safe ``queue.Queue``. The GUI slot shows
``TwoFactorDialog`` and calls ``submit_totp(code)`` (a queue put). No nested
event loop, no ``QThread.wait``, no modal-on-worker deadlock.

# reference pattern
"""

from __future__ import annotations

import queue
from dataclasses import replace
from typing import TYPE_CHECKING

from PyQt6.QtCore import QThread, pyqtSignal

from app.domain.entities import ExportPhase, ExportProgress, ExportRequest, TwoFactorRequired
from app.infrastructure.secure import redact_secrets, wipe

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from app.application.use_cases.auth import BwLoginUseCase
    from app.application.use_cases.export import ExportVaultUseCase
    from app.application.use_cases.updates import (
        ApplyUpdateUseCase,
        CheckForUpdatesUseCase,
    )

_TWO_FACTOR_TIMEOUT_SECONDS = 60


class LoginWorker(QThread):
    """Fresh bw login; 2FA via the two_factor_required <-> submit_totp queue."""

    two_factor_required = pyqtSignal()
    progress = pyqtSignal(object)  # ExportProgress, phase == LOGIN
    # Wake-up only - the session rides the ``session`` attribute, NEVER payloads.
    finished_result = pyqtSignal(object)
    failed = pyqtSignal(str)  # redacted message

    def __init__(
        self,
        use_case: BwLoginUseCase,
        url: str,
        email: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._use_case = use_case
        self._url = url
        self._email = email
        self._password = bytearray()
        self._session: str | None = None
        self._totp_queue: queue.Queue[str] = queue.Queue()

    def set_password(self, password: bytearray) -> None:
        self._password = password

    @property
    def session(self) -> str | None:
        """RAM-only session key - read by MainWindow AFTER ``run()`` returns.

        Deliberately passed as an ATTRIBUTE, not as a signal payload (a queued
        signal would also be deliverable after the worker finished - the
        attribute is the explicit, secret-aware hand-off).
        """
        return self._session

    def submit_totp(self, code: str) -> None:
        """GUI slot: hand the 2FA code to the blocked worker thread."""
        self._totp_queue.put(code)

    def run(self) -> None:
        try:
            self.progress.emit(self._sample(0, 1, "Logging in...", 0.1))
            session = self._use_case.run(
                self._url,
                self._email,
                self._password,
                self._request_totp,
            )
            self._session = session
            self.progress.emit(self._sample(1, 1, "Logged in.", 1.0))
            # The session is NEVER transported as a signal payload - a queued
            # signal would hold the secret in Qt's event queue until dispatch.
            # ``finished_result`` is only a wake-up; MainWindow reads the
            # session from the ``session`` attribute (see "Security invariants").
            self.finished_result.emit(None)
        except Exception as exc:
            self.failed.emit(redact_secrets(str(exc)))
        finally:
            # NOTE: the session is NOT closed/cleared here - closing it would
            # kill the session before the ExportWorker uses it (the finished
            # signal is queued and processed after run() returns), and the
            # session attribute is the explicit READ HAND-OFF for MainWindow.
            # MainWindow calls use_case.close(session) after the export.
            wipe(self._password)

    def _request_totp(self) -> str:
        """Blocked 2FA hand-shake: emit, then queue.get in the worker thread."""
        self.two_factor_required.emit()
        try:
            code = self._totp_queue.get(timeout=_TWO_FACTOR_TIMEOUT_SECONDS)
        except queue.Empty as exc:
            raise TwoFactorRequired(
                "Two-factor code entry timed out.",
            ) from exc
        if not code:
            raise TwoFactorRequired("Two-factor code entry was cancelled.")
        return code

    @staticmethod
    def _sample(current: int, total: int, message: str, fraction: float) -> ExportProgress:
        return ExportProgress(
            phase=ExportPhase.LOGIN,
            current=current,
            total=total,
            message=message,
            fraction=fraction,
        )


class ExportWorker(QThread):
    """Runs ExportVaultUseCase; the KeePass password bytearray is wiped at the end."""

    progress = pyqtSignal(object)  # ExportProgress
    finished_result = pyqtSignal(object)  # ExportResult
    failed = pyqtSignal(str)

    def __init__(self, use_case: ExportVaultUseCase, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._use_case = use_case
        self._request: ExportRequest | None = None
        self._master_password = bytearray()

    def set_request(self, request: ExportRequest, master_password: bytearray) -> None:
        self._request = request
        self._master_password = master_password

    def run(self) -> None:
        request = self._request
        if request is None:
            self.failed.emit("ExportWorker was started without a request.")
            return
        try:
            password = self._master_password.decode("utf-8")
            export_request = replace(request, master_password=password)
            result = self._use_case.run(export_request, self.progress.emit)
            self.finished_result.emit(result)
        except Exception as exc:
            self.failed.emit(redact_secrets(str(exc)))
        finally:
            wipe(self._master_password)
            self._request = None


class UpdateCheckWorker(QThread):
    """Checks GitHub for a newer release in the background."""

    finished_result = pyqtSignal(object)  # dict (as_dict bridge)
    failed = pyqtSignal(str)

    def __init__(self, use_case: CheckForUpdatesUseCase, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._use_case = use_case

    def run(self) -> None:
        try:
            self.finished_result.emit(self._use_case.run())
        except Exception as exc:
            self.failed.emit(redact_secrets(str(exc)))


class UpdateDownloadWorker(QThread):
    """Downloads (sha256-gated) and applies the update; reports progress."""

    progress = pyqtSignal(int, int)  # current, total
    finished_result = pyqtSignal(bool)
    failed = pyqtSignal(str)

    def __init__(
        self,
        use_case: ApplyUpdateUseCase,
        url: str,
        token: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._use_case = use_case
        self._url = url
        self._token = token

    def run(self) -> None:
        try:
            applied = self._use_case.run(self._url, self._token, self.progress.emit)
            self.finished_result.emit(applied)
        except Exception as exc:
            self.failed.emit(redact_secrets(str(exc)))
