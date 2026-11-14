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
- 2FA codes are cleared from the dialog after use and are never logged.
- Attachment bytes flow `bw` -> RAM -> `kp.add_binary` -> kdbx; they are never
  written to temp files and never logged.

## 2. Nothing secret is ever persisted

- The config schema (`config/app_config.yaml`) has **no password keys**.
- The `bw` CLI would persist vault data + session state under the user's
  own profile (`%APPDATA%\Bitwarden CLI`, `~/.config/Bitwarden CLI`). Every
  `bw` invocation therefore runs with `BITWARDENCLI_APPDATA_DIR` pointed at an
  app-owned folder (`bw_data/`) that is wiped (best-effort `rmtree`) at startup
  and shutdown; after every export the session is locked and logged out, which
  makes `bw` drop the synced vault. The user's own `bw` profile (server
  config, login state) is never read or changed. While an export runs, the
  folder holds the `bw` state file with the (encrypted) vault.
- The export is written to `<name>.kdbx.partial` and renamed only after it
  was saved, re-opened and its entry count verified. A failed or cancelled
  run removes the partial file and leaves earlier exports untouched.
- Session keys are passed to `bw` via the `BW_SESSION` environment variable -
  never on the command line. The master password is given to `bw login` only
  through `--passwordenv <NAME>`: an environment variable of the `bw` process.
  The flag carries just the variable name, never the value; modern `bw` CLI
  releases ignore piped stdin for `login` and otherwise fall back to an
  interactive masked prompt.
- Exported databases are KDBX4, cipher AES-256, key derivation **Argon2**
  (KeePass's modern memory-hard KDF) with the parameters pykeepass's blank
  template ships; KeePass Desktop re-saves with its own tuned settings on the
  first open, so the file's protection only improves from there.

## 3. The log never contains secrets

- `AppLogger` is the only logging sink: a bounded in-memory ring buffer that
  **never writes to disk** (enforced by `test_app_logger.py::has_disk_handlers`).
- Items are logged by name + counts only; an item-level failure or notice
  logs the item name + id and a (redacted) reason - never notes, passwords or
  field values. Item payloads are never logged.
- Every error/log payload passes through `redact_secrets()` (masks values of
  sensitive field names and long base64 tokens - session keys, raw `bw login`
  stdout) before it is raised, logged or shown. `ErrorDialog` applies the same
  redaction **internally** - dialog messages are treated as untrusted input.

## 4. bw binary resolution

The configured `bw` is resolved to an absolute path (explicit path as-is; a
bare name via `PATH`, then the winget package folder) and **only that path is
executed** - a bare `bw` is never handed to the OS loader, and a `bw` that
merely lies in the working directory is ignored. A resolution into Downloads /
temp / the working directory shows a confirmation dialog before the master
password is requested.

`bw --version` is checked as a sanity test against a wrong path. It is **not**
a trust decision: any program can print a version string. `bw` receives your
master password and vault, so its integrity is your responsibility - it is
**not** bundled; install it from a trusted source (e.g.
`winget install Bitwarden.CLI`). The per-user winget folder is as
user-writable as this app's own folder; software running as you can replace
either.

## 5. Update trust model (documented acceptance)

- Transport: TLS against `api.github.com` (the `github-updater` dependency).
- The downloaded EXE is **not code-signed**; the updater trusts the GitHub
  release as published by `reserve85`.
- `github-updater` is pinned to a full 40-hex commit SHA in `requirements.txt`
  (tags can be force-moved).
- When a release's notes publish a sha256 for the asset, `ApplyUpdateUseCase`
  verifies the downloaded file against it **before** the exe is replaced. If no
  sha256 is published, the update is **refused**. This protects against a
  corrupted or truncated download. It does **not** protect against a
  compromised GitHub account or release: the hash and the EXE come from the
  same release. Only a signature made with a key that is not stored on GitHub
  would - this is not implemented.
- The update check is anonymous (public repository); no GitHub token is
  stored or sent.
- Runtime dependencies and PyInstaller are pinned to exact versions, GitHub
  Actions to commit SHAs. Dependency hashes are not pinned.

## 6. Repo hygiene

- `.gitignore` excludes `config/`, `output/`, `bw_data/` and the lock file
  (runtime user data).
- `.pre-commit-config.yaml` runs `gitleaks`; CI runs `gitleaks` + `pip-audit`.

## 7. Known limitations

- Python `str`/`bytes` are immutable; pykeepass and PyQt6 use `str` internally.
  The enforceable guarantee is "no extra copies, no persistence, no logging",
  not "forensically wiped".
- The `bw` CLI obtains secrets itself on your behalf and is trusted once
  validated. A malicious/local `bw` can read the secrets it processes.
- The self-update flow replaces the running executable; verify the release
  checksum when it is published.
- The TOTP 2FA code for `bw login` is passed via `--code <value>` on the child
  process command line (the bw CLI exposes no environment-variable equivalent;
  the master password itself is never on argv). The code is short-lived
  (30-60 s), never logged and never persisted; a local same-user process with
  process-list access could observe it during the login attempt.
- A crash mid-export can leave the app-owned `bw_data/` folder (bw CLI state:
  server config, login state, encrypted vault) and a `.partial` export file on
  disk; `bw_data/` is wiped at the next startup and git-ignored.
- Bitwarden two-step login is supported for authenticator-app codes only.
- Passkeys and the password history are not exported (see README).