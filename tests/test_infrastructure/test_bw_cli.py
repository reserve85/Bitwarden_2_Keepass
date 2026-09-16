"""BwCli/BwClient tests - command shapes, password/session hygiene, redaction.

The bw binary is NOT available in CI, so every test fakes ``subprocess.run``
and ``shutil.which`` and asserts on the *invocation contract*: which commands
are built, that secrets only ever travel via stdin / BW_SESSION, and that
failures are redacted.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

import app.infrastructure.bw.bw_cli as bw_module
from app.domain.entities import TwoFactorRequired
from app.infrastructure.bw.bw_cli import (
    COMMAND_TIMEOUT_SECONDS,
    BwCli,
    BwClient,
    BwCliError,
    user_writable_warning,
)

_VERSION = "Bitwarden CLI v2024.11.0"

#: A stale interactive session is kicked out and the login retried exactly once.
_RETRY_COUNT = 2


def _result(
    returncode: int = 0,
    stdout: str | bytes = b"",
    stderr: str | bytes = b"",
) -> subprocess.CompletedProcess:
    """Fake CompletedProcess; BwCli uses text mode, BwClient bytes."""
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def _fake_run(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[subprocess.CompletedProcess],
) -> list[dict[str, Any]]:
    """Fake ``subprocess.run`` consuming *responses* in order; records every call."""
    calls: list[dict[str, Any]] = []

    def fake(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
        calls.append({"cmd": list(args[0]), "kwargs": kwargs})
        return responses.pop(0)

    monkeypatch.setattr(bw_module.subprocess, "run", fake)
    monkeypatch.setattr(bw_module.shutil, "which", lambda _name: "/usr/bin/bw")
    return calls


def _login_responses(
    *login_results: subprocess.CompletedProcess,
) -> list[subprocess.CompletedProcess]:
    """Prepend the ``--version`` + ``lock`` calls that every login makes."""
    return [_result(stdout=_VERSION), _result(), *login_results]


# -- resolve_and_validate -----------------------------------------------------


def test_resolve_and_validate_finds_and_checks_version(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = _fake_run(monkeypatch, [_result(stdout=_VERSION)])

    resolved = BwCli("bw", tmp_path).resolve_and_validate()

    assert resolved == Path("/usr/bin/bw")
    assert calls[0]["cmd"] == ["bw", "--version"]
    env = calls[0]["kwargs"]["env"]
    assert env["BW_DATA_FOLDER"] == str(tmp_path)
    assert env["BW_CONFIG_FILE"] == str(tmp_path / "config.json")
    assert env["NO_COLOR"] == "1"
    assert calls[0]["kwargs"]["timeout"] == COMMAND_TIMEOUT_SECONDS


def test_resolve_and_validate_missing_binary_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """No PATH entry and no winget install -> clear error hinting at winget."""
    monkeypatch.setattr(bw_module.shutil, "which", lambda _name: None)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "no-winget"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "no-winget"))

    with pytest.raises(BwCliError, match="winget"):
        BwCli("bw", tmp_path).resolve_and_validate()


def test_resolve_and_validate_winget_fallback_finds_bw_exe(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """winget installs bw.exe off PATH (never added to PATH) - still found."""
    winget = tmp_path / "localappdata" / "Microsoft" / "WinGet"
    package_dir = winget / "Packages" / "Bitwarden.CLI_Microsoft.Winget.Source_abc12345"
    package_dir.mkdir(parents=True)
    bw_exe = package_dir / "bw.exe"
    bw_exe.write_bytes(b"fake-binary")
    recorded: dict[str, Any] = {}

    def fake_run(*args: object, **_kwargs: object) -> subprocess.CompletedProcess:
        recorded["cmd"] = list(args[0])
        return _result(stdout=_VERSION)

    monkeypatch.setattr(bw_module.shutil, "which", lambda _name: None)
    monkeypatch.setattr(bw_module.subprocess, "run", fake_run)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "no-winget"))

    resolved = BwCli("bw", tmp_path).resolve_and_validate()

    assert resolved == bw_exe
    assert recorded["cmd"] == ["bw", "--version"]


def test_resolve_and_validate_winget_fallback_picks_newest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """winget keeps old versions; the newest bw.exe must win."""
    old_dir = tmp_path / "localappdata" / "Microsoft" / "WinGet" / "Packages" / "old"
    new_dir = tmp_path / "localappdata" / "Microsoft" / "WinGet" / "Packages" / "new"
    old_dir.mkdir(parents=True)
    new_dir.mkdir(parents=True)
    old_bw = old_dir / "bw.exe"
    new_bw = new_dir / "bw.exe"
    old_bw.write_bytes(b"old")
    new_bw.write_bytes(b"new")
    os.utime(old_bw, (1_000_000, 1_000_000))
    os.utime(new_bw, (2_000_000, 2_000_000))

    monkeypatch.setattr(bw_module.shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        bw_module.subprocess,
        "run",
        lambda *_args, **_kwargs: _result(stdout=_VERSION),
    )
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "no-winget"))

    resolved = BwCli("bw", tmp_path).resolve_and_validate()

    assert resolved == new_bw


def test_resolve_and_validate_does_not_substitute_explicit_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A configured absolute path is reported as-is - no winget guessing."""
    monkeypatch.setattr(bw_module.shutil, "which", lambda _name: None)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "no-winget"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "no-winget"))

    with pytest.raises(BwCliError, match="nope"):
        BwCli(tmp_path / "nope" / "bw.exe", tmp_path).resolve_and_validate()


def test_resolve_and_validate_wrong_version_shape_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _fake_run(monkeypatch, [_result(stdout="garbled output")])

    with pytest.raises(BwCliError, match="Unexpected"):
        BwCli("bw", tmp_path).resolve_and_validate()


# -- login --------------------------------------------------------------------


def test_login_returns_session_and_password_only_via_stdin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    password = bytearray(b"hunter2")
    calls = _fake_run(monkeypatch, _login_responses(_result(stdout="session-key-abc\n")))

    session = BwCli("bw", tmp_path).login("user@example.com", password)

    assert session == "session-key-abc"
    login = next(c for c in calls if c["cmd"][1] == "login")
    assert login["cmd"][1:] == ["login", "user@example.com", "--raw"]
    # the very same backing store goes to stdin - no extra immutable bytes copy.
    assert login["kwargs"]["input"] is password
    assert "hunter2" not in "|".join(login["cmd"])


def test_login_two_factor_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _fake_run(
        monkeypatch,
        _login_responses(_result(stderr="Two-step login\n! Master password: ...")),
    )

    with pytest.raises(TwoFactorRequired):
        BwCli("bw", tmp_path).login("user@example.com", bytearray(b"pw"))


def test_login_with_method_and_code_flags(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _fake_run(monkeypatch, _login_responses(_result(stdout="session-key-2\n")))

    BwCli("bw", tmp_path).login(
        "user@example.com",
        bytearray(b"pw"),
        method="totp",
        code="123456",
    )

    login = next(c for c in calls if c["cmd"][1] == "login")
    assert login["cmd"][1:] == [
        "login",
        "user@example.com",
        "--raw",
        "--method",
        "totp",
        "--code",
        "123456",
    ]


def test_login_already_logged_in_logs_out_and_retries_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = _fake_run(
        monkeypatch,
        _login_responses(
            _result(stderr="You are already logged in as user@example.com"),
            _result(),  # logout
            _result(stdout="session-key-3\n"),
        ),
    )

    session = BwCli("bw", tmp_path).login("user@example.com", bytearray(b"pw"))

    assert session == "session-key-3"
    commands = [c["cmd"][1:] for c in calls]
    assert commands.count(["login", "user@example.com", "--raw"]) == _RETRY_COUNT
    assert ["logout"] in commands


def test_login_timeout_wraps_into_bw_cli_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake(*args: object, **_kwargs: object) -> subprocess.CompletedProcess:
        cmd = list(args[0])
        if cmd[-1] == "--version":
            return _result(stdout=_VERSION)
        raise subprocess.TimeoutExpired(cmd, timeout=1)

    monkeypatch.setattr(bw_module.subprocess, "run", fake)
    monkeypatch.setattr(bw_module.shutil, "which", lambda _name: "/usr/bin/bw")

    with pytest.raises(BwCliError, match="timed out"):
        BwCli("bw", tmp_path).login("user@example.com", bytearray(b"pw"))


def test_login_error_message_is_redacted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _fake_run(
        monkeypatch,
        _login_responses(_result(returncode=1, stderr="login failed password=supersecret")),
    )

    with pytest.raises(BwCliError) as exc_info:
        BwCli("bw", tmp_path).login("user@example.com", bytearray(b"pw"))

    assert "supersecret" not in str(exc_info.value)
    assert "***" in str(exc_info.value)


def test_lock_and_logout_are_best_effort(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess:
        return _result(returncode=1, stderr="boom")

    monkeypatch.setattr(bw_module.subprocess, "run", fake)
    cli = BwCli("bw", tmp_path)

    cli.lock()  # must not raise
    cli.logout()  # must not raise


# -- config_server ------------------------------------------------------------


def test_config_server_strips_slashes_and_logs_out_on_change(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = _fake_run(
        monkeypatch,
        [
            _result(stdout="https://bitwarden.com\n"),  # current server
            _result(),  # logout
            _result(),  # config server <url>
        ],
    )

    BwCli("bw", tmp_path).config_server("https://bitwarden.eu/")

    assert calls[0]["cmd"][1:] == ["config", "server"]
    assert calls[1]["cmd"][1:] == ["logout"]
    assert calls[2]["cmd"][1:] == ["config", "server", "https://bitwarden.eu"]


def test_config_server_same_url_is_a_no_op(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _fake_run(monkeypatch, [_result(stdout="https://bitwarden.eu\n")])

    BwCli("bw", tmp_path).config_server("https://bitwarden.eu/")

    assert len(calls) == 1  # only the current-server probe


# -- BwClient (vault data) ----------------------------------------------------


def test_bw_client_session_via_env_never_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    recorded: dict[str, Any] = {}

    def fake(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
        recorded["cmd"] = list(args[0])
        recorded["env"] = kwargs["env"]
        return _result(stdout=b"[]")

    monkeypatch.setattr(bw_module.subprocess, "run", fake)
    client = BwClient("bw", "session-key-xyz", tmp_path)

    assert client.list_folders() == []
    assert recorded["cmd"] == ["bw", "list", "folders"]
    assert recorded["env"]["BW_SESSION"] == "session-key-xyz"
    assert "session-key-xyz" not in "|".join(recorded["cmd"])
    assert recorded["env"]["BW_DATA_FOLDER"] == str(tmp_path)


def test_bw_client_sync_runs_sync_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    recorded: dict[str, Any] = {}

    def fake(*args: object, **_kwargs: object) -> subprocess.CompletedProcess:
        recorded["cmd"] = list(args[0])
        return _result()

    monkeypatch.setattr(bw_module.subprocess, "run", fake)
    client = BwClient("bw", "session-key-xyz", tmp_path)

    client.sync()
    assert recorded["cmd"] == ["bw", "sync"]


def test_bw_client_list_items_parses_json(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = [{"id": "i1", "name": "Vault", "type": 1}]
    monkeypatch.setattr(
        bw_module.subprocess,
        "run",
        lambda *_args, **_kwargs: _result(stdout=json.dumps(payload).encode()),
    )

    client = BwClient("bw", "s", Path())
    assert client.list_items() == payload


def test_bw_client_get_attachment_returns_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"\x00\x01attachment-data"
    recorded: dict[str, Any] = {}

    def fake(*args: object, **_kwargs: object) -> subprocess.CompletedProcess:
        recorded["cmd"] = list(args[0])
        return _result(stdout=payload)

    monkeypatch.setattr(bw_module.subprocess, "run", fake)
    client = BwClient("bw", "s", Path())

    assert client.get_attachment("item-1", "att-1") == payload
    assert recorded["cmd"] == ["bw", "get", "attachment", "att-1", "--itemid", "item-1"]


def test_bw_client_error_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        bw_module.subprocess,
        "run",
        lambda *_args, **_kwargs: _result(
            returncode=1,
            stderr=b"session has expired password=hunter2pleasehide",
        ),
    )
    client = BwClient("bw", "s", Path())

    with pytest.raises(BwCliError) as exc_info:
        client.list_folders()

    assert "hunter2pleasehide" not in str(exc_info.value)
    assert "***" in str(exc_info.value)


# -- PATH-hijack guard --------------------------------------------------------


def test_user_writable_warning_silent_for_system_dir() -> None:
    assert user_writable_warning(Path("/opt/bitwarden/bw")) is None


def test_user_writable_warning_flags_cwd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    assert user_writable_warning(tmp_path / "bw.exe") is not None


def test_user_writable_warning_flags_temp_dir() -> None:
    assert user_writable_warning(Path(tempfile.gettempdir()) / "bw.exe") is not None


def test_user_writable_warning_flags_downloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    assert user_writable_warning(tmp_path / "Downloads" / "bw.exe") is not None
