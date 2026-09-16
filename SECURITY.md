# Security

This document states the **scoped** security guarantees of Bitwarden 2 KeePass.
Guarantees are honest about the platform reality: Python `str`/`bytes` are
immutable and cannot be physically erased, and the app runs external binaries
(`bw`, the self-updater) whose behavior is trusted. "Best-effort wipe"
everywhere means: minimise copies, clear Qt widgets, wipe mutable buffers in
`finally` paths, never persist, never log - **not** forensic memory erasure.

## 1. Passwords / secrets live in RAM only

- The Bitwarden master password and the KeePass master password are handled as
  single mutable `bytearray` buffers (`app/infrastructure/secure.py`,
  `secure_password_from_str`). No immutable `bytes`/`str` copy is created on
  purpose; the caller wipes the buffer in a `finally` path (`wipe()`).
- Qt widget copies of typed secrets are cleared on dialog accept/cancel
  (`drop_qt_str`).
- 2FA codes are wiped immediately after use and are never logged.
- Attachment bytes flow `bw` -> RAM -> `kp.add_binary` -> kdbx; they are never
  written to temp files and never logged.

## 2. Nothing secret is ever persisted

- The config schema (`config/app_config.yaml`) has **no password keys**.
- The `bw` CLI would persist vault data + session state under the user's
  default config directory. Every `bw` invocation therefore runs with
  `BW_DATA_FOLDER` and `BW_CONFIG_FILE` pointed at an app-owned folder that is
  created per export and wiped (best-effort `rmtree`) afterwards. This makes
  the "nothing persisted to disk" claim true end-to-end - on the validated
  precondition that the used `bw` version honours these environment variables.
- Session keys are passed to `bw` via the `BW_SESSION` environment variable -
  never on the command line. The master password is given to `bw login` only
  through `--passwordenv <NAME>`: an environment variable of the `bw` process.
  The flag carries just the variable name, never the value; modern `bw` CLI
  releases ignore piped stdin for `login` and otherwise fall back to an
  interactive masked prompt.

## 3. The log never contains secrets

- `AppLogger` is the only logging sink: a bounded in-memory ring buffer that
  **never writes to disk** (enforced by `test_app_logger.py::has_disk_handlers`).
- Items are logged by name + counts only; failure payloads pass through
  `_redacted_item()` (deep-copied, sensitive fields replaced).
- `BwCli._redact()` masks values of sensitive field names and long base64
  tokens (session keys, raw `bw login` stdout) before raising user-presentable
  errors. `ErrorDialog` applies the same redaction **internally** - dialog
  messages are treated as untrusted input.

## 4. bw binary trust (PATH-hijack guard)

`BwCli.resolve_and_validate()` runs `bw --version` and requires the expected
"Bitwarden CLI ..." output shape. Resolutions into user-writable locations
(Downloads / temp / cwd) trigger a warning dialog linking to Settings. `bw` is
never invoked before this check. `bw` is **not** bundled; install it yourself
(e.g. `winget install Bitwarden.CLI`) and point the settings at it.

## 5. Update trust model (documented acceptance)

- Transport: TLS against `api.github.com` (the `github-updater` dependency).
- The downloaded EXE is **not code-signed**; the updater trusts the GitHub
  release as published by `reserve85`.
- `github-updater` is pinned to a full 40-hex commit SHA in `requirements.txt`
  (tags can be force-moved).
- When a release's notes publish a sha256 for the asset, `ApplyUpdateUseCase`
  verifies the downloaded file against it **before** the exe is replaced. If no
  sha256 is published, the update is **refused**.

## 6. Repo hygiene

- `.gitignore` excludes `config/` and `output/` (runtime user data).
- `.pre-commit-config.yaml` runs `gitleaks`; CI runs `gitleaks` + `pip-audit`.
- `TokenCrypto` (machine-derived PBKDF2-Fernet key, no key file) is used for
  the optional GitHub token. It is machine-derived **obfuscation**, not
  protection against a same-user attacker.

## 7. Known limitations

- Python `str`/`bytes` are immutable; pykeepass and PyQt6 use `str` internally.
  The enforceable guarantee is "no extra copies, no persistence, no logging",
  not "forensically wiped".
- The `bw` CLI obtains secrets itself on your behalf and is trusted once
  validated. A malicious/local `bw` can read the secrets it processes.
- The self-update flow replaces the running executable; verify the release
  checksum when it is published.