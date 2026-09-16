"""bw CLI adapter - auth commands (``BwCli``) and vault data (``BwClient``).

Security model
--------------
- The master password travels ONLY via the subprocess stdin pipe, never via
  argv or env (argv is readable by other local processes on Windows/Linux).
- ``BwClient`` passes the session through ``BW_SESSION`` (the bw CLI's own
  mechanism) - never on the command line. The session key lives in RAM only.
- Disk hygiene: every invocation runs with ``BW_DATA_FOLDER`` and
  ``BW_CONFIG_FILE`` pointed into an app-owned directory (created per export,
  wiped afterwards by the caller) so the bw CLI never persists vault data or
  session state in ``~/.config/bw`` / ``%APPDATA%\\bw``.
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

from app.domain.entities import TwoFactorRequired  # re-exported for adapter compat
from app.infrastructure.secure import redact_secrets

COMMAND_TIMEOUT_SECONDS = 600  # plan-internal constant; bw commands are slow

#: Expected shape of ``bw --version`` output. Newer CLI versions print a bare
#: version ("2026.7.0"), older ones "Bitwarden CLI v2024.11.0". Anything else
#: (e.g. "garbled output") is treated as not being the Bitwarden CLI.
_VERSION_PATTERN = re.compile(r"(?i)^(?:bitwarden\s+cli\s+)?v?\d+\.\d+(?:\.\d+)*$")
#: bw announces an active (stale interactive) session on stderr with this text.
_ALREADY_LOGGED_IN = re.compile(r"(?i)already logged in")
#: bw asks for a 2FA code on stderr with these markers.
_TWO_STEP = re.compile(
    r"(?i)two[- ]?step|two-factor|2fa|enter\s+(your\s+)?(2fa|otp|two-factor).*code",
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


class BwCliError(RuntimeError):
    """A bw CLI invocation failed; the message never contains secrets."""


class BwCli:
    """Auth commands against the bw CLI.

    ``data_folder`` is the app-owned folder that becomes ``BW_DATA_FOLDER`` /
    ``BW_CONFIG_FILE`` (see module docstring).
    """

    def __init__(self, bw_path: str | Path, data_folder: Path) -> None:
        self._bw_path = str(bw_path)
        self._resolved_bw: str | None = None  # lazy PATH/winget fallback (see _spawn)
        self._env = {
            **os.environ,
            "NO_COLOR": "1",
            "BW_DATA_FOLDER": str(data_folder),
            "BW_CONFIG_FILE": str(data_folder / "config.json"),
        }

    # -- path resolution -----------------------------------------------------
    def resolve_and_validate(self) -> Path:
        """Resolve ``bw_path`` via PATH and check the ``--version`` shape.

        When the configured value is a bare command name that is not on PATH
        (the winget install layout), :func:`_find_winget_bw` locates the
        winget-installed ``bw.exe`` automatically. Returns the resolved
        absolute path, or raises :class:`BwCliError` when the binary is missing
        or does not look like the Bitwarden CLI. The returned path may be
        flagged by :func:`user_writable_warning` (a PATH-hijack guard the
        caller may surface as a warning, never a hard error).
        """
        resolved = shutil.which(self._bw_path)
        if resolved is None:
            resolved = _find_winget_bw(self._bw_path)
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

        The password is fed through stdin. A stale interactive bw session would
        fail with "already logged in", so a best-effort ``bw lock`` runs first
        and - if the marker is still present - a ``bw logout`` + one retry is
        attempted. 2FA is signaled with :class:`TwoFactorRequired`; the caller
        then retries with ``method``/``code`` supplied.
        """
        self.resolve_and_validate()
        args = ["login", email, "--raw"]
        if method and code:
            args += ["--method", method, "--code", code]
        with contextlib.suppress(BwCliError):
            self.lock()

        result = self._run(*args, input_bytes=password, check=False)
        stderr = self._stderr_text(result)
        if _TWO_STEP.search(stderr):
            raise TwoFactorRequired(redact_secrets(stderr))
        if _ALREADY_LOGGED_IN.search(stderr):
            # stale interactive session - kick it out and retry exactly once.
            self.logout()
            result = self._run(*args, input_bytes=password, check=False)
            stderr = self._stderr_text(result)
            if _TWO_STEP.search(stderr):
                raise TwoFactorRequired(redact_secrets(stderr))
        if result.returncode != 0:
            message = redact_secrets(stderr) or f"bw login failed (exit {result.returncode})."
            raise BwCliError(message)
        return self._stdout_text(result).strip()

    def lock(self) -> None:
        """Best-effort ``bw lock`` (clears any stale unlocked vault)."""
        with contextlib.suppress(BwCliError):
            self._run("lock")

    def logout(self) -> None:
        """Best-effort ``bw logout`` (revokes the session server-side)."""
        with contextlib.suppress(BwCliError):
            self._run("logout")

    # -- subprocess plumbing ---------------------------------------------------
    def _spawn(
        self,
        args: tuple[str, ...],
        *,
        input_bytes: bytes | bytearray | None,
        text: bool,
    ) -> subprocess.CompletedProcess:
        """Run the bw binary, retrying once with a resolved path on FileNotFoundError.

        ``resolve_and_validate`` may locate a winget-installed bw.exe (not on
        PATH), but spawning the bare configured name still raises
        FileNotFoundError. On that signal we resolve once - PATH lookup, then
        the winget package folders - and cache the absolute path, so the first
        command works and every later command spawns the resolved binary.
        """
        binary = self._resolved_bw or self._bw_path
        try:
            return subprocess.run(
                [binary, *args],
                capture_output=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
                env=self._env,
                input=input_bytes,
                encoding="utf-8" if text else None,
                errors="replace",
                check=False,  # returncode is inspected below
            )
        except FileNotFoundError:
            if self._resolved_bw is not None:
                raise  # previously resolved binary has vanished - report it
            resolved = shutil.which(self._bw_path) or _find_winget_bw(self._bw_path)
            if resolved is None:
                raise
            self._resolved_bw = resolved
            return subprocess.run(
                [resolved, *args],
                capture_output=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
                env=self._env,
                input=input_bytes,
                encoding="utf-8" if text else None,
                errors="replace",
                check=False,
            )

    def _run(
        self,
        *args: str,
        input_bytes: bytes | bytearray | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run a bw command; wrap failures into :class:`BwCliError`.

        Runs in text mode (stdout/stderr are ``str``) unless ``input_bytes`` is
        given - stdin-feeders keep binary output so the caller decodes stdout
        itself after inspecting stderr.
        """
        text: bool = input_bytes is None
        try:
            result = self._spawn(args, input_bytes=input_bytes, text=text)
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


class BwClient:
    """Vault data commands (old-project port) - session passed via ``BW_SESSION``.

    Never passes the session on argv (argv is visible to other local users).
    """

    def __init__(self, bw_path: str, session: str, data_folder: Path) -> None:
        self._bw_path = str(bw_path)
        self._resolved_bw: str | None = None  # lazy PATH/winget fallback (see _spawn)
        self._env = {
            **os.environ,
            "BW_SESSION": session,
            "BW_DATA_FOLDER": str(data_folder),
            "BW_CONFIG_FILE": str(data_folder / "config.json"),
        }

    def _spawn(self, args: tuple[str, ...]) -> subprocess.CompletedProcess:
        """Run the bw binary, retrying once with a resolved path on FileNotFoundError.

        A bare configured name (``bw``) that resolves only via the winget
        package folders cannot be found by ``shutil.which``; spawning it raises
        FileNotFoundError and is retried with the resolved absolute path. The
        resolved path is cached, so later commands spawn it directly.
        """
        binary = self._resolved_bw or self._bw_path
        try:
            return subprocess.run(
                [binary, *args],
                capture_output=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
                env=self._env,
                check=False,  # returncode is inspected below
            )
        except FileNotFoundError:
            if self._resolved_bw is not None:
                raise  # previously resolved binary has vanished - report it
            resolved = shutil.which(self._bw_path) or _find_winget_bw(self._bw_path)
            if resolved is None:
                raise
            self._resolved_bw = resolved
            return subprocess.run(
                [resolved, *args],
                capture_output=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
                env=self._env,
                check=False,
            )

    def _check_output(self, *args: str, binary: bool = False) -> str | bytes:
        try:
            result = self._spawn(args)
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
        raw = self._check_output(
            "get",
            "attachment",
            attachment_id,
            "--itemid",
            item_id,
            binary=True,
        )
        return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def user_writable_warning(resolved_path: Path) -> str | None:
    """PATH-hijack guard: warn when the resolved binary lives in a user-writable spot.

    Downloads / temp dir / process cwd are exactly the places an attacker can
    drop a fake ``bw`` that gets picked up first on PATH. Returns a human
    warning string, or ``None`` when the location looks safe. This is a warning
    only - the admin may have deliberately installed the CLI there.
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
