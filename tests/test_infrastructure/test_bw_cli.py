"""BwCli/BwClient tests - command shapes, password/session hygiene, redaction.

The bw binary is NOT available in CI, so every test fakes ``subprocess.run``
and ``shutil.which`` and asserts on the *invocation contract*: which commands
are built, that secrets only ever travel via env vars / BW_SESSION, and that
failures are redacted.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
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

#: What the faked PATH lookup resolves a bare "bw" to. The adapter only ever
#: spawns the resolved ABSOLUTE path - never the bare name.
_BW = str(Path("/usr/bin/bw").absolute())


@pytest.fixture(autouse=True)
def _bw_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default: ``bw`` is found on PATH (no real bw installation is consulted)."""
    monkeypatch.setattr(bw_module.shutil, "which", lambda _name: "/usr/bin/bw")


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

    assert resolved == Path(_BW)
    assert calls[0]["cmd"] == [_BW, "--version"]
    env = calls[0]["kwargs"]["env"]
    # The variable the bw CLI really reads - isolates it from the user's profile.
    assert env["BITWARDENCLI_APPDATA_DIR"] == str(tmp_path)
    assert "BW_DATA_FOLDER" not in env
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
    assert recorded["cmd"] == [str(bw_exe), "--version"]


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


def test_bare_name_is_never_spawned_only_the_resolved_binary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A bare "bw" handed to the OS loader would be searched in the app and
    working directory first - every spawn must use the resolved absolute path."""
    winget = tmp_path / "localappdata" / "Microsoft" / "WinGet"
    package_dir = winget / "Packages" / "Bitwarden.CLI_Microsoft.Winget.Source_abc12345"
    package_dir.mkdir(parents=True)
    bw_exe = package_dir / "bw.exe"
    bw_exe.write_bytes(b"fake-binary")
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
        calls.append(cmd)
        return _result(stdout=_VERSION if "--version" in cmd else b"[]")

    monkeypatch.setattr(bw_module.shutil, "which", lambda _name: None)
    monkeypatch.setattr(bw_module.subprocess, "run", fake_run)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "no-winget"))

    assert BwCli("bw", tmp_path).resolve_and_validate() == bw_exe
    assert BwClient("bw", "s", tmp_path).list_folders() == []

    assert calls == [[str(bw_exe), "--version"], [str(bw_exe), "list", "folders"]]


def test_working_directory_hit_is_not_used_for_a_bare_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A bw.exe that merely lies in the working directory must not be picked up."""
    planted = tmp_path / "bw.exe"
    planted.write_bytes(b"planted")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "elsewhere"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "no-winget"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "no-winget"))
    monkeypatch.setattr(bw_module.shutil, "which", lambda _name: str(planted))

    with pytest.raises(BwCliError, match="not found"):
        BwCli("bw", tmp_path / "data").resolve_and_validate()


def test_explicit_path_is_used_as_is(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    explicit = tmp_path / "tools" / "bw.exe"
    explicit.parent.mkdir()
    explicit.write_bytes(b"fake-binary")
    calls = _fake_run(monkeypatch, [_result(stdout=_VERSION)])

    resolved = BwCli(str(explicit), tmp_path / "data").resolve_and_validate()

    assert resolved == explicit.resolve()
    assert calls[0]["cmd"][0] == str(explicit.resolve())


def test_bw_path_callable_is_re_read_on_every_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A path changed in Settings must apply without restarting the app."""
    first = tmp_path / "a" / "bw.exe"
    second = tmp_path / "b" / "bw.exe"
    for binary in (first, second):
        binary.parent.mkdir()
        binary.write_bytes(b"fake-binary")
    current = {"path": str(first)}
    calls = _fake_run(monkeypatch, [_result(stdout=_VERSION), _result(stdout=_VERSION)])
    cli = BwCli(lambda: current["path"], tmp_path / "data")

    cli.resolve_and_validate()
    current["path"] = str(second)
    cli.resolve_and_validate()

    assert [call["cmd"][0] for call in calls] == [str(first.resolve()), str(second.resolve())]


def test_data_folder_is_created_before_every_spawn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The app wipes the folder at startup/shutdown; bw needs it to exist."""
    data = tmp_path / "bw_data"
    _fake_run(monkeypatch, [_result(stdout=_VERSION)])

    BwCli("bw", data).resolve_and_validate()

    assert data.is_dir()


def test_login_without_session_output_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _fake_run(monkeypatch, _login_responses(_result(stdout="\n")))

    with pytest.raises(BwCliError, match="no session"):
        BwCli("bw", tmp_path).login("user@example.com", bytearray(b"pw"))


def test_run_feeds_bytearray_password_in_binary_mode(tmp_path: Path) -> None:
    """Regression: errors='replace' flipped subprocess into text mode and broke
    bytearray stdin ("write() argument must be str, not bytearray").

    Belt-and-braces: ``login`` itself now uses ``--passwordenv``, but the stdin
    path must stay binary for any future stdin-fed command. Runs a REAL
    subprocess (the interpreter itself) to verify the pipe end-to-end.
    """
    script = "import sys; sys.stdout.buffer.write(b'got:' + sys.stdin.buffer.read(64))"
    cli = BwCli(sys.executable, tmp_path)

    result = cli._run("-c", script, input_bytes=bytearray(b"hunter2"))  # noqa: SLF001

    assert result.returncode == 0
    assert cli._stdout_text(result) == "got:hunter2"  # noqa: SLF001


# -- login --------------------------------------------------------------------


def test_login_password_via_env_var_never_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    password = bytearray(b"hunter2")
    calls = _fake_run(monkeypatch, _login_responses(_result(stdout="session-key-abc\n")))

    session = BwCli("bw", tmp_path).login("user@example.com", password)

    assert session == "session-key-abc"
    login = next(c for c in calls if c["cmd"][1] == "login")
    assert login["cmd"][1:] == [
        "login",
        "user@example.com",
        "--raw",
        "--passwordenv",
        "B2KP_BW_PASSWORD",
        "--nointeraction",
    ]
    # modern bw ignores piped stdin for `login`, so the password travels in the
    # child ENV (named by --passwordenv) - never argv, stdin or a log.
    assert login["kwargs"]["env"]["B2KP_BW_PASSWORD"] == "hunter2"
    # The uniclient CLI must never drop into an invisible interactive prompt
    # (it would BLOCK on the 2FA code instead of letting the GUI ask).
    assert login["kwargs"]["env"]["BW_NOINTERACTION"] == "true"
    assert login["kwargs"]["input"] is None
    assert "hunter2" not in "|".join(login["cmd"])


def test_login_two_factor_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _fake_run(
        monkeypatch,
        _login_responses(_result(stderr="Two-step login\n! Master password: ...")),
    )

    with pytest.raises(TwoFactorRequired):
        BwCli("bw", tmp_path).login("user@example.com", bytearray(b"pw"))


@pytest.mark.parametrize(
    "stderr_fragment",
    [
        # newer uniclient CLI (2025.x+): fails fast instead of prompting
        "Code is required.",
        "Login failed. No provider selected.",
        "Two-step login code:",
        # older CLI generations
        "Two-step login required. Run the same command with the --method and --code flags.",
        "Two-factor authentication required",
    ],
)
def test_login_signals_two_factor_required_on_any_cli_generation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stderr_fragment: str,
) -> None:
    _fake_run(monkeypatch, _login_responses(_result(stderr=stderr_fragment)))

    with pytest.raises(TwoFactorRequired):
        BwCli("bw", tmp_path).login("user@example.com", bytearray(b"pw"))


def test_login_with_method_and_code_flags(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _fake_run(monkeypatch, _login_responses(_result(stdout="session-key-2\n")))

    BwCli("bw", tmp_path).login(
        "user@example.com",
        bytearray(b"pw"),
        method="0",
        code="123456",
    )

    login = next(c for c in calls if c["cmd"][1] == "login")
    assert login["cmd"][1:] == [
        "login",
        "user@example.com",
        "--raw",
        "--passwordenv",
        "B2KP_BW_PASSWORD",
        "--nointeraction",
        "--method",
        "0",
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
    expected_login = [
        "login",
        "user@example.com",
        "--raw",
        "--passwordenv",
        "B2KP_BW_PASSWORD",
        "--nointeraction",
    ]
    assert commands.count(expected_login) == _RETRY_COUNT
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
    assert recorded["cmd"] == [_BW, "list", "folders"]
    assert recorded["env"]["BW_SESSION"] == "session-key-xyz"
    assert "session-key-xyz" not in "|".join(recorded["cmd"])
    assert recorded["env"]["BITWARDENCLI_APPDATA_DIR"] == str(tmp_path)


def test_bw_client_sync_runs_sync_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    recorded: dict[str, Any] = {}

    def fake(*args: object, **_kwargs: object) -> subprocess.CompletedProcess:
        recorded["cmd"] = list(args[0])
        return _result()

    monkeypatch.setattr(bw_module.subprocess, "run", fake)
    client = BwClient("bw", "session-key-xyz", tmp_path)

    client.sync()
    assert recorded["cmd"] == [_BW, "sync"]


def test_bw_client_list_items_parses_json(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = [{"id": "i1", "name": "Vault", "type": 1}]
    monkeypatch.setattr(
        bw_module.subprocess,
        "run",
        lambda *_args, **_kwargs: _result(stdout=json.dumps(payload).encode()),
    )

    client = BwClient("bw", "s", Path(tempfile.mkdtemp()))
    assert client.list_items() == payload


def test_bw_client_get_attachment_returns_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"\x00\x01attachment-data"
    recorded: dict[str, Any] = {}

    def fake(*args: object, **_kwargs: object) -> subprocess.CompletedProcess:
        recorded["cmd"] = list(args[0])
        return _result(stdout=payload)

    monkeypatch.setattr(bw_module.subprocess, "run", fake)
    client = BwClient("bw", "s", Path(tempfile.mkdtemp()))

    assert client.get_attachment("item-1", "att-1") == payload
    # `--raw` keeps the bytes on stdout - without it the modern uniclient CLI
    # writes the attachment FILE into the working directory ("attachments in
    # the root" bug).
    assert recorded["cmd"] == [
        _BW,
        "get",
        "attachment",
        "att-1",
        "--itemid",
        "item-1",
        "--raw",
    ]


def test_bw_client_error_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        bw_module.subprocess,
        "run",
        lambda *_args, **_kwargs: _result(
            returncode=1,
            stderr=b"session has expired password=hunter2pleasehide",
        ),
    )
    client = BwClient("bw", "s", Path(tempfile.mkdtemp()))

    with pytest.raises(BwCliError) as exc_info:
        client.list_folders()

    assert "hunter2pleasehide" not in str(exc_info.value)
    assert "***" in str(exc_info.value)


# -- console window suppression ------------------------------------------------


def test_bw_spawns_carry_no_console_window_flag(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Every bw child must hide its console (the packaged GUI has none).

    The ``--windowed`` build spawns the console ``bw`` binary; without
    ``CREATE_NO_WINDOW`` Windows allocates a fresh visible console window per
    command, which flashes all over the screen during an export.
    """
    expected = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    cli_calls = _fake_run(monkeypatch, [_result(stdout=_VERSION)])
    BwCli("bw", tmp_path).resolve_and_validate()
    client_calls = _fake_run(monkeypatch, [_result(stdout=b"[]")])
    BwClient("bw", "session-key-xyz", tmp_path).list_folders()

    assert [call["kwargs"]["creationflags"] for call in cli_calls] == [expected]
    assert [call["kwargs"]["creationflags"] for call in client_calls] == [expected]


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


def test_user_writable_warning_silent_for_winget_packages() -> None:
    """winget is the documented install path - it must not warn on every export."""
    path = Path(
        "C:/Users/test/AppData/Local/Microsoft/WinGet/Packages/Bitwarden/Bitwarden.CLI/bw.exe",
    )
    assert user_writable_warning(path) is None


def test_user_writable_warning_silent_for_program_files() -> None:
    assert user_writable_warning(Path("C:/Program Files/Bitwarden/bw.exe")) is None
