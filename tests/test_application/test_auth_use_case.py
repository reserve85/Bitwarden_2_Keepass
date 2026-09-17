"""BwLoginUseCase tests - fresh login, 2FA round-trip, session-close lifecycle."""

from __future__ import annotations

from app.application.use_cases.auth import BwLoginUseCase
from app.domain.entities import LogCategory
from tests.fakes import FakeBwCli, RecordingLogger

#: One initial attempt + one retry after the 2FA code is supplied.
_TOTAL_LOGIN_ATTEMPTS = 2


def test_login_success_returns_session_and_configures_server() -> None:
    bw = FakeBwCli()
    use_case = BwLoginUseCase(bw, RecordingLogger())

    session = use_case.run(
        "https://bitwarden.eu",
        "user@example.com",
        bytearray(b"pw"),
        request_totp=lambda: "123456",
    )

    assert session == "session-fake"
    assert bw.configured_server == "https://bitwarden.eu"
    assert bw.calls == ["resolve_and_validate", "config_server https://bitwarden.eu", "login"]


def test_login_two_factor_prompts_once_and_retries_with_code() -> None:
    bw = FakeBwCli(two_factor_on_login=True)
    logger = RecordingLogger()
    use_case = BwLoginUseCase(bw, logger)
    codes: list[str] = []

    def collect_code() -> str:
        codes.append("123456")
        return "123456"

    session = use_case.run(
        "https://bitwarden.eu",
        "user@example.com",
        bytearray(b"pw"),
        request_totp=collect_code,
    )

    assert session == "session-fake"
    assert bw.last_login_attempt == _TOTAL_LOGIN_ATTEMPTS
    # numeric provider id "0" = authenticator-app TOTP (the uniclient CLI
    # rejects symbolic method names such as "totp").
    assert bw.login_methods == [(None, None), ("0", "123456")]
    assert codes == ["123456"]
    # the code is never logged
    assert LogCategory.TOTP in [category for category, _, _ in logger.records]
    assert all("123456" not in message for _, _, message in logger.records)


def test_close_is_best_effort_lock_and_logout() -> None:
    bw = FakeBwCli()
    use_case = BwLoginUseCase(bw, RecordingLogger())

    use_case.close("session-fake")

    assert bw.calls == ["lock", "logout"]
