"""bw CLI adapter - auth commands (``BwCli``) and vault data (``BwClient``).

Security model
--------------
- The master password travels ONLY in the ``bw`` subprocess environment,
  referenced by the ``--passwordenv`` variable NAME - never on argv, never in
  a log, never persisted. Modern bw CLI releases no longer read ``login``
  passwords from a piped stdin; without ``--passwordenv`` they drop into an
  interactive masked-input prompt that cannot work headless. The variable
  value exists only in the child environment for the duration of the call.
- ``BwClient`` passes the session through ``BW_SESSION`` (the bw CLI's own
  mechanism) - never on the command line. The session key lives in RAM only.
- Disk hygiene: every invocation runs with ``BITWARDENCLI_APPDATA_DIR`` (the
  variable the bw CLI actually honours) pointed into an app-owned directory
  that the caller wipes at startup and shutdown, so the bw CLI never touches
  the user's own profile (``%APPDATA%\\Bitwarden CLI`` / ``~/.config``).
- The binary is resolved to an absolute path and only that path is ever
  spawned - a bare ``bw`` is never handed to the OS loader, which on Windows
  would search the application and working directory first.
- All error messages are redacted through :func:`redact_secrets` before being
  surfaced, so a failing ``bw login`` can never leak the password or a session
  key into the log/UI.

# ported from bitwarden-to-keepass (src/bitwarden_to_keepass.py) with new auth methods
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from app.domain.entities import TwoFactorRequired  # re-exported for adapter compat
from app.infrastructure.secure import redact_secrets

if TYPE_CHECKING:
    from collections.abc import Callable

#: The environment variable the bw CLI reads its data directory from
#: (``data.json`` with server config, session state and the encrypted vault).
BW_APPDATA_ENV = "BITWARDENCLI_APPDATA_DIR"

COMMAND_TIMEOUT_SECONDS = 600  # plan-internal constant; bw commands are slow
#: Windows creation flags for EVERY ``bw`` spawn (single funnel: ``_run_bw``).
#: The packaged GUI is built ``--windowed`` (console-less), so without this
#: flag Windows allocates a fresh, visibly flashing console window for each bw
#: child (version check, config, login, sync, lists, one per attachment, ...).
#: ``0`` keeps the kwarg valid on POSIX, where a non-zero value is rejected.
_NO_CONSOLE_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

#: Expected shape of ``bw --version`` output. Newer CLI versions print a bare
#: version ("2026.7.0"), older ones "Bitwarden CLI v2024.11.0". Anything else
#: (e.g. "garbled output") is treated as not being the Bitwarden CLI.
_VERSION_PATTERN = re.compile(r"(?i)^(?:bitwarden\s+cli\s+)?v?\d+\.\d+(?:\.\d+)*$")
#: bw announces an active (stale interactive) session on stderr with this text.
_ALREADY_LOGGED_IN = re.compile(r"(?i)already logged in")
#: The uniclient CLI (2025.x+) checks this env var to decide whether it may
#: prompt interactively. Without it, a 2FA-enabled vault makes ``bw login``
#: BLOCK on an invisible interactive "Two-step login code:" prompt instead of
#: failing fast (the prompt is written to stderr, which this adapter captures,
#: so the user would just see "nothing happens"). Every login spawn carries it.
_NOINTERACTION_ENV = "BW_NOINTERACTION"
_NOINTERACTION_FLAG = "--nointeraction"  # global option; belt-and-braces
#: bw signals a 2FA demand on stderr. Both CLI generations are covered: older
#: versions print "Two-step login required. Run the same command with the
#: --method and --code flags."; the uniclient (which is told to never prompt -
#: see ``_NOINTERACTION_ENV``) fails the first attempt with "Code is required."
#: (single provider) or "Login failed. No provider selected." (multiple).
_TWO_STEP = re.compile(
    r"(?i)two[- ]?step|two[- ]?factor|2fa"
    r"|code is required"
    r"|no provider selected"
    r"|enter\s+(your\s+)?(2fa|otp|two[- ]?factor|two[- ]?step).*code",
)


def _find_winget_bw(configured: str) -> str | None:
    """Locate a winget-installed ``bw.exe`` when a bare name is not on PATH.

    ``winget install Bitwarden.CLI`` extracts ``bw.exe`` into a versioned
    package folder (``%LOCALAPPDATA%\\Microsoft\\WinGet\\Packages\\...``) that
    winget does *not* add to PATH, so a PATH lookup for ``bw`` fails even
    though the CLI is installed. This fallback only kicks in for a bare command
    name (``bw`` / ``bw.exe``) - an explicit path the user configured is never
    silently substituted. When several copies exist (winget keeps old versions
    around), the newest ``bw.exe`` wins.
    """
    if Path(configured).name != configured:
        return None  # explicit path - report it as-is
    candidates: list[Path] = []
    for env_name in ("LOCALAPPDATA", "PROGRAMDATA"):
        root = os.environ.get(env_name, "")
        if not root:
            continue
        win_get = Path(root) / "Microsoft" / "WinGet"
        try:
            package_dir = win_get / "Packages"
            if package_dir.is_dir():
                candidates.extend(package_dir.glob("*/bw.exe"))
                candidates.extend(package_dir.glob("*/*/bw.exe"))
            shim = win_get / "Links" / "bw.exe"
            if shim.is_file():
                candidates.append(shim)
        except OSError:
            continue
    candidates = [path for path in candidates if path.is_file()]
    if not candidates:
        return None
    newest = max(candidates, key=lambda path: path.stat().st_mtime)
    return str(newest)


def _in_working_directory_only(found: str) -> bool:
    """True when *found* is a working-directory hit that PATH does not justify.

    ``shutil.which`` on Windows searches the current directory before PATH. A
    ``bw.exe`` that merely happens to lie in the working directory (Downloads,
    a network share, ...) must never be picked up for a bare ``bw``.
    """
    try:
        parent = Path(found).resolve().parent
        if parent != Path.cwd().resolve():
            return False
        for entry in os.environ.get("PATH", "").split(os.pathsep):
            if entry and Path(entry).is_absolute() and Path(entry).resolve() == parent:
                return False  # the directory is deliberately on PATH
    except OSError:
        return False
    return True


def resolve_bw_binary(configured: str) -> str | None:
    """Absolute path of the bw binary for the configured value, or ``None``.

    An explicit path (anything with a directory part) is used as-is when it
    exists - it is never substituted. A bare command name is looked up on PATH
    (ignoring a pure working-directory hit) and then in the winget folders.
    """
    if Path(configured).name != configured:
        path = Path(configured)
        try:
            return str(path.resolve()) if path.is_file() else None
        except OSError:
            return None
    found = shutil.which(configured)
    if found and _in_working_directory_only(found):
        found = None
    if found:
        return str(Path(found).absolute())
    return _find_winget_bw(configured)


def _run_bw(
    binary: str,
    args: tuple[str, ...],
    *,
    env: dict[str, str],
    input_bytes: bytes | bytearray | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess:
    """Run one ``subprocess.run`` against the bw binary.

    ``text=False`` (BwClient, and stdin-feeders like ``bw login``) keeps
    stdout/stderr as ``bytes`` so the caller decodes them itself.
    """
    return subprocess.run(
        [binary, *args],
        capture_output=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
        env=env,
        input=input_bytes,
        encoding="utf-8" if text else None,
        # errors= alone would flip subprocess into text mode and break
        # bytearray stdin (TypeError: write() argument must be str).
        errors="replace" if text else None,
        check=False,  # returncode is inspected by the caller
        creationflags=_NO_CONSOLE_WINDOW,  # no visible console per bw child
    )


class _ResolvedBinaryMixin:
    """Shared bw subprocess plumbing for BwCli and BwClient.

    The configured value (a string, or a callable returning the CURRENT
    setting so a change in Settings takes effect without a restart) is resolved
    to an absolute path before the first spawn; only that resolved path is ever
    executed. ``extra_env`` (e.g. the ``--passwordenv`` variable) is merged
    into the child environment for this invocation only.
    """

    _bw_source: str | Callable[[], str]
    _resolved_bw: str | None
    _resolved_for: str | None
    _data_folder: Path
    _env: dict[str, str]

    def _init_binary(self, bw_path: str | Path | Callable[[], str], data_folder: Path) -> None:
        self._bw_source = bw_path if callable(bw_path) else str(bw_path)
        self._resolved_bw = None
        self._resolved_for = None
        self._data_folder = Path(data_folder)

    @property
    def _bw_path(self) -> str:
        """The configured bw path/name as of now."""
        source = self._bw_source
        return (str(source() or "") if callable(source) else source) or "bw"

    def _binary(self) -> str:
        """Resolved absolute bw path (cached per configured value)."""
        configured = self._bw_path
        if self._resolved_bw is None or self._resolved_for != configured:
            resolved = resolve_bw_binary(configured)
            if resolved is None:
                raise FileNotFoundError(configured)
            self._resolved_bw = resolved
            self._resolved_for = configured
        return self._resolved_bw

    def _spawn(
        self,
        args: tuple[str, ...],
        *,
        input_bytes: bytes | bytearray | None = None,
        text: bool = True,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        """Run the resolved bw binary inside the app-owned data folder."""
        binary = self._binary()
        env = {**self._env, **(extra_env or {})}
        # The caller wipes the folder between runs; bw needs it to exist.
        self._data_folder.mkdir(parents=True, exist_ok=True)
        try:
            return _run_bw(binary, args, env=env, input_bytes=input_bytes, text=text)
        except FileNotFoundError:
            self._resolved_bw = None  # the binary vanished - resolve again next time
            raise


class BwCliError(RuntimeError):
    """A bw CLI invocation failed; the message never contains secrets."""


class BwCli(_ResolvedBinaryMixin):
    """Auth commands against the bw CLI.

    ``data_folder`` is the app-owned folder that becomes the bw CLI's data
    directory (see module docstring). ``bw_path`` may be a callable returning
    the current setting.
    """

    def __init__(self, bw_path: str | Path | Callable[[], str], data_folder: Path) -> None:
        self._init_binary(bw_path, data_folder)
        self._env = {
            **os.environ,
            "NO_COLOR": "1",
            BW_APPDATA_ENV: str(data_folder),
        }

    # -- path resolution -----------------------------------------------------
    def resolve_and_validate(self) -> Path:
        """Resolve the configured bw path and check the ``--version`` shape.

        Returns the absolute path that every later command spawns, or raises
        :class:`BwCliError` when the binary is missing or does not answer like
        the Bitwarden CLI. The version check is a sanity check against a wrong
        path, NOT a trust decision - any program can print a version. The
        returned path may be flagged by :func:`user_writable_warning`.
        """
        try:
            resolved = self._binary()
        except FileNotFoundError:
            resolved = None
        if resolved is None:
            message = (
                f"bw CLI not found (configured path {self._bw_path!r}). "
                "Install the Bitwarden CLI (winget install Bitwarden.CLI) or "
                "set the full path to bw.exe in Settings."
            )
            raise BwCliError(message)
        result = self._run("--version")
        version = self._stdout_text(result)
        if not _VERSION_PATTERN.search(version):
            message = (
                f"Unexpected 'bw --version' output: {version.strip()!r}. "
                "Expected a version like '2026.7.0' or 'Bitwarden CLI v...'."
            )
            raise BwCliError(message)
        return Path(resolved)

    # -- auth / server -------------------------------------------------------
    def config_server(self, url: str) -> None:
        """Point bw at *url* (trailing slashes stripped).

        Changing the server requires a logout first ("Logout required before
        server config update."), so a changed server triggers a best-effort
        logout before reconfiguring.
        """
        url = url.rstrip("/")
        try:
            current = self._stdout_text(self._run("config", "server")).strip()
        except BwCliError:
            current = ""
        if current == url:
            return
        self.logout()  # best-effort; bw refuses a server change while logged in
        self._run("config", "server", url)

    def login(
        self,
        email: str,
        password: bytearray,
        method: str | None = None,
        code: str | None = None,
    ) -> str:
        """Log in and return the RAM-only session key (first ``--raw`` stdout line).

        The password is handed to bw via ``--passwordenv``: an environment
        variable of the subprocess whose NAMED reference is the only thing on
        argv. Every login runs with ``--nointeraction`` /
        ``BW_NOINTERACTION=true``: the uniclient CLI would otherwise BLOCK on an
        invisible interactive 2FA prompt when the vault has 2FA enabled (the
        prompt goes to the captured stderr pipe; the GUI would show no dialog).
        A stale interactive bw session would fail with "already logged in", so
        a best-effort ``bw lock`` runs first and - if the marker is still
        present - a ``bw logout`` + one retry is attempted. 2FA is signaled
        with :class:`TwoFactorRequired`; the caller then retries with
        ``method``/``code`` supplied. ``method`` must be the NUMERIC
        TwoFactorProviderType id (e.g. "0" for the authenticator-app TOTP) -
        the uniclient CLI calls ``parseInt`` on ``--method`` and rejects
        symbolic names like "totp".
        """
        self.resolve_and_validate()
        # The env var NAME is public and appears on argv; the SECRET value goes
        # into extra_env (never argv/logs). noqa: S105 - this is not a secret.
        password_env_name = "B2KP_BW_PASSWORD"  # noqa: S105
        args = [
            "login",
            email,
            "--raw",
            "--passwordenv",
            password_env_name,
            _NOINTERACTION_FLAG,
        ]
        if method and code:
            args += ["--method", method, "--code", code]
        with contextlib.suppress(BwCliError):
            self.lock()

        extra_env = {
            password_env_name: password.decode("utf-8"),
            _NOINTERACTION_ENV: "true",
        }
        result = self._run(*args, check=False, extra_env=extra_env)
        stderr = self._stderr_text(result)
        if _TWO_STEP.search(stderr):
            raise TwoFactorRequired(redact_secrets(stderr))
        if _ALREADY_LOGGED_IN.search(stderr):
            # stale interactive session - kick it out and retry exactly once.
            self.logout()
            result = self._run(*args, check=False, extra_env=extra_env)
            stderr = self._stderr_text(result)
            if _TWO_STEP.search(stderr):
                raise TwoFactorRequired(redact_secrets(stderr))
        if result.returncode != 0:
            message = redact_secrets(stderr) or f"bw login failed (exit {result.returncode})."
            raise BwCliError(message)
        session = self._stdout_text(result).strip()
        if not session:
            raise BwCliError("bw login returned no session key.")
        return session

    def lock(self) -> None:
        """Best-effort ``bw lock`` (clears any stale unlocked vault)."""
        with contextlib.suppress(BwCliError):
            self._run("lock")

    def logout(self) -> None:
        """Best-effort ``bw logout`` (revokes the session server-side)."""
        with contextlib.suppress(BwCliError):
            self._run("logout")

    # -- subprocess plumbing ---------------------------------------------------
    def _run(
        self,
        *args: str,
        input_bytes: bytes | bytearray | None = None,
        check: bool = True,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        """Run a bw command; wrap failures into :class:`BwCliError`.

        Runs in text mode (stdout/stderr are ``str``) unless ``input_bytes`` is
        given - stdin-feeders keep binary output so the caller decodes stdout
        itself after inspecting stderr.
        """
        text: bool = input_bytes is None
        try:
            result = self._spawn(
                args,
                input_bytes=input_bytes,
                text=text,
                extra_env=extra_env,
            )
        except subprocess.TimeoutExpired as exc:
            message = f"bw command timed out after {COMMAND_TIMEOUT_SECONDS} s."
            raise BwCliError(message) from exc
        except FileNotFoundError as exc:
            message = f"bw CLI not found: {self._bw_path}."
            raise BwCliError(message) from exc
        if check and result.returncode != 0:
            stderr = self._stderr_text(result)
            message = redact_secrets(stderr) or f"bw {' '.join(args)} failed."
            raise BwCliError(message)
        return result

    @staticmethod
    def _stdout_text(result: subprocess.CompletedProcess) -> str:
        if isinstance(result.stdout, bytes):
            return result.stdout.decode("utf-8", "replace")
        return result.stdout or ""

    @staticmethod
    def _stderr_text(result: subprocess.CompletedProcess) -> str:
        if isinstance(result.stderr, bytes):
            return result.stderr.decode("utf-8", "replace")
        return result.stderr or ""


class BwClient(_ResolvedBinaryMixin):
    """Vault data commands (old-project port) - session passed via ``BW_SESSION``.

    Never passes the session on argv (argv is visible to other local users).
    """

    def __init__(
        self,
        bw_path: str | Path | Callable[[], str],
        session: str,
        data_folder: Path,
    ) -> None:
        self._init_binary(bw_path, data_folder)
        self._env = {
            **os.environ,
            "NO_COLOR": "1",
            "BW_SESSION": session,
            BW_APPDATA_ENV: str(data_folder),
        }

    def _check_output(self, *args: str, binary: bool = False) -> str | bytes:
        try:
            result = self._spawn(args, text=False)
        except subprocess.TimeoutExpired as exc:
            message = f"bw command timed out after {COMMAND_TIMEOUT_SECONDS} s."
            raise BwCliError(message) from exc
        except FileNotFoundError as exc:
            message = f"bw CLI not found: {self._bw_path}."
            raise BwCliError(message) from exc
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", "replace")
            message = redact_secrets(stderr) or f"bw {' '.join(args)} failed."
            raise BwCliError(message)
        return result.stdout if binary else result.stdout.decode("utf-8", "replace")

    def sync(self) -> None:
        self._check_output("sync")

    def list_folders(self) -> list[dict]:
        return json.loads(self._check_output("list", "folders"))

    def list_items(self) -> list[dict]:
        return json.loads(self._check_output("list", "items"))

    def get_attachment(self, item_id: str, attachment_id: str) -> bytes:
        # `--raw` is REQUIRED: without it the modern uniclient CLI writes the
        # attachment as a FILE into the process working directory (using the
        # attachment's fileName) and prints only a message on stdout. With
        # `--raw` (and no `--output`) the bytes are written to stdout.
        raw = self._check_output(
            "get",
            "attachment",
            attachment_id,
            "--itemid",
            item_id,
            "--raw",
            binary=True,
        )
        return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def user_writable_warning(resolved_path: Path) -> str | None:
    """PATH-hijack guard: warn when the resolved binary lives in a user-writable spot.

    Downloads / temp dir / process cwd are places where a stray or planted
    ``bw`` typically lies. Returns a human warning string, or ``None`` when the
    location looks unremarkable. The per-user WinGet package folder is NOT
    flagged: it is the documented install location (``winget install
    Bitwarden.CLI``) and exactly as user-writable as this app itself. The
    caller asks the user to confirm before the master password is handed over.
    """
    parent = resolved_path.parent
    home = Path.home()
    try:
        if parent == Path.cwd():
            return (
                f"bw was resolved to {resolved_path} (the working directory). "
                "A file there can be overwritten by other software - prefer an "
                "installation dir."
            )
        if parent == Path(tempfile.gettempdir()):
            return (
                f"bw was resolved to {resolved_path} (the temp directory). "
                "Files there are user-writable and can be replaced by an "
                "attacker - prefer an installation dir."
            )
        if parent.name.lower() == "downloads" and home in parent.parents:
            return (
                f"bw was resolved to {resolved_path} (Downloads). Downloaded "
                "files are user-writable but are NOT a safe install location - "
                "install the Bitwarden CLI into a protected dir instead."
            )
    except OSError:
        return None
    return None
