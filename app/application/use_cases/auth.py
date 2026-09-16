"""BW login orchestration - fresh login per export, 2FA round-trip, RAM session.

The session key is returned to the caller and never persisted or logged. The
caller owns the lifecycle: every ``run()`` must be wrapped in ``try``/``finally``
with ``close(session)`` in the ``finally`` (enforced by ``LoginWorker``).

2FA flow (deadlock-free): ``run`` raises nothing for 2FA - it calls the
``request_totp`` callback the GUI injected. The GUI shows the dialog and the
worker thread blocks on a thread-safe queue until the code arrives.

# ported from bitwarden-to-keepass auth orchestration
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.domain.entities import LogCategory, LogLevel, TwoFactorRequired

if TYPE_CHECKING:
    from collections.abc import Callable

    from app.application.ports import BwAuthPort, LoggerPort


class BwLoginUseCase:
    def __init__(self, bw: BwAuthPort, logger: LoggerPort) -> None:
        self._bw = bw
        self._logger = logger

    def run(
        self,
        url: str,
        email: str,
        password: bytearray,
        request_totp: Callable[[], str],
    ) -> str:
        """Log in fresh against Bitwarden and return the RAM-only session key.

        *password* is a single mutable ``bytearray`` (``secure_password_from_str``)
        that the *caller* wipes in its ``finally`` path. On a 2FA demand the
        ``request_totp`` callback is invoked to obtain the code from the GUI
        dialog; the code is never logged.
        """
        self._bw.resolve_and_validate()
        self._bw.config_server(url)
        try:
            return self._bw.login(email, password)
        except TwoFactorRequired:
            phase = LogCategory.TOTP
            self._logger.log(phase, LogLevel.INFO, "Two-factor code required.")
            code = request_totp()
            return self._bw.login(email, password, method="totp", code=code)

    def close(self, _session: str) -> None:
        """Close the session (best-effort): lock + logout server-side.

        Single owner of the session lifecycle - see module docstring. The
        session value itself is not needed here (bw knows its own session);
        the parameter documents the contract to callers.
        """
        # bw lock clears the unlocked vault; logout revokes the session. Both
        # are best-effort: a failed close must not mask the export outcome.
        self._bw.lock()
        self._bw.logout()
