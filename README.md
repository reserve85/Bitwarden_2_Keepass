# Bitwarden 2 KeePass

Export your complete [Bitwarden](https://bitwarden.com) / [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
vault into a fresh KeePass (`.kdbx`) database - folders, tags, attachments,
notes, passwords, URLs, custom fields, cards and identities. Optionally copy
the verified result to unlimited target folders (e.g. network drives, NAS
mounts, backup sticks).

The app is a **security-focused** PyQt6 desktop application:

- secrets live in RAM as single mutable `bytearray` buffers and are best-effort
  wiped after use,
- nothing secret is ever written to disk (the `bw` CLI is steered into an
  app-owned data folder that is wiped per export),
- all log output is an in-memory ring buffer without secret content,
- every export runs `bw` against the vault **once per session**: fresh login,
  then `lock` + `logout` in a `finally` path.

> **Scope of the security guarantees** is documented honestly in
> [`SECURITY.md`](SECURITY.md) - read it before putting this into production.
> Python `str`/`bytes` are immutable, so "wiping" means *no extra copies, no
> persistence, no logging* - not forensic memory erasure.

## Features

- Full vault export via the official [Bitwarden CLI](https://bitwarden.com/help/cli/)
  (`bw`), including:
  - folders (nested trees), logins (with URLs + TOTP seeds), secure notes,
  - custom fields (hidden fields become *protected* KeePass fields),
  - attachments, tags, cards and identities (as regular entries with fields),
  - empty/ghost-named items handled gracefully (per-item rollback + skip).
- Session handling: `BW_SESSION` via environment, `BW_DATA_FOLDER` /
  `BW_CONFIG_FILE` pointed at an app-owned folder, wiped after every export.
- 2FA support: TOTP prompt round-trip during login (deadlock-free, in-thread).
- KeePass master password asked (with confirmation) on **every** export, never
  stored.
- One or more destination folders: every copy is **sha256-verified** after
  writing; "delete source after all copies succeeded" is an opt-in checkbox.
- Self-update via GitHub releases (SHA-pinned updater; the EXE sha256 is
  published in every release body and verified before applying).

## Requirements

- **Windows** (the release build is a Windows EXE; the code is layered so other
  platforms work if the `bw` binary is available).
- **Python >= 3.11** only when running from source (the release EXE bundles its
  own interpreter).
- **Bitwarden CLI** (`bw`) - it is deliberately **not** bundled. Install it:

  ```powershell
  winget install Bitwarden.CLI
  ```

  or download the `bw-windows-*.zip` from the
  [Bitwarden releases](https://github.com/bitwarden/cli/releases). The default
  setting `bw_path=bw` resolves `bw` from `PATH`; you can point the app at an
  absolute path in **Settings** if you prefer.

  > **Note (winget):** `winget install Bitwarden.CLI` extracts `bw.exe` into a
  > versioned package folder that winget does *not* add to `PATH`. The app
  > auto-detects that location, so `winget install Bitwarden.CLI` works out of
  > the box. With any other install method, keep the folder containing
  > `bw.exe` on `PATH` (the `bw_path=bw` default) or enter the absolute path in
  > **Settings**. An empty "bw CLI path" field simply means the `bw` default.
  > Verify your install with `bw --version` and check `where bw` if needed.

## Installation

### Portable release (recommended)

1. Download `Bitwarden2KeePass-v<version>.zip` from the
   [releases page](https://github.com/reserve85/bitwarden_2_keepass/releases).
2. Unzip, run `Bitwarden2KeePass.exe`. The app is fully portable - no
   installer, no registry entries; the only runtime folders are the app-owned
   locations described in `SECURITY.md`.

### From source

```powershell
git clone https://github.com/reserve85/bitwarden_2_keepass.git
cd bitwarden_2_keepass
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m app.main
```

(`python app/main.py` works too - the entry point prepends the repository
root to `sys.path` so the `app` package is importable from a plain script.)
## Usage

1. Open **Settings** (menu bar) and configure:
   - **Bitwarden server URL** (default `https://bitwarden.eu`; use
     `https://vault.bitwarden.com` or your Vaultwarden origin for self-hosted),
   - **Email**,
   - **bw CLI path** (default `bw`),
   - **Output folder** (where the fresh `.kdbx` is written),
   - **Target folders** - unlimited extra destinations the verified file is
     copied to (pick a folder or type a path),
   - **Delete the source export file after all copies succeeded** (opt-in),
   - **Check for updates at startup** (on by default; disable for privacy).
   - Press **Save** - nothing is persisted before you save.
2. Hit **Start Export** on the main page.
3. Enter your **Bitwarden master password**. If the vault uses 2FA, a TOTP
   prompt appears; enter the 6-8 digit code.
4. Create the **KeePass master password** for the new database (typed twice).
5. The progress bar shows the phases - sync, folders, items, save, verify,
   copy. Every destination copy is sha256-verified against the source file.
6. The result summary shows the file name, per-target copy outcomes and the
   counts. The **Log** page shows the same details without any secret content.

Export file naming: `YYYYMMDD_bitwarden_export.kdbx` in the output folder.

## Security model

See [`SECURITY.md`](SECURITY.md) for the scoped guarantees:

- RAM-only secrets with best-effort wiping (`bytearray` + `wipe()` in
  finally-paths; Qt widget copies cleared on dialog close).
- The `bw` CLI runs with `BW_DATA_FOLDER`/`BW_CONFIG_FILE` pointed at an
  app-owned directory created per export and wiped afterwards - the vault and
  session state never reach your default `bw` config directory.
- The in-memory ring-buffer logger never writes to disk; `ErrorDialog`
  redacts secrets *internally*; the `bw` error path redacts base64 tokens.
- PATH-hijack guard: `bw --version` is validated before any `bw` call;
  user-writable resolutions trigger a warning with a Settings link.
- `bw` is trusted once validated and is not bundled.

## Updating

- The app checks for updates 2 seconds after startup (if enabled) and via
  **Check for Updates** in the menu. Updates are downloaded from the project's
  GitHub releases and verified against the sha256 published in the release
  notes before the EXE is replaced.

## Development

```powershell
python -m pytest tests/ -q          # full suite (Qt tests run offscreen)
python -m ruff check app/ tests/    # lint gate (CI runs the same)
python -m ruff format --check app/ tests/
```

Pre-commit hooks (ruff + gitleaks) are configured in
`.pre-commit-config.yaml`.

### Building the EXE

The release workflow builds a single-file, windowed EXE:

```powershell
python -m PyInstaller --onefile --windowed --name Bitwarden2KeePass `
  --icon app/resources/Icon.ico --hidden-import github_updater app/main.py
```

`dist\Bitwarden2KeePass.exe` is the portable, self-updating executable.

### CI / CD

- `ci.yml` - lint + tests on Windows / Python 3.11 (also enforces that the
  `github-updater` dependency is pinned to a 40-hex commit SHA).
- `security.yml` - gitleaks (full history, no cap), `pip-audit` on
  `requirements.txt` **and** the installed environment, bandit.
- `release.yml` - on every `v*` tag: build EXE + portable ZIP, publish both
  with the EXE's sha256 in the release body.
- `cleanup.yml` - daily retention for workflow runs / artifacts.

## License

MIT - see [LICENSE](LICENSE).
