# Bitwarden 2 KeePass

Export your complete [Bitwarden](https://bitwarden.com) / [Vaultwarden](https://github.com/dani-garcia/vaultwarden) vault into a fresh KeePass (`.kdbx`) database - folders, logins, notes, custom fields, attachments, cards and identities. Optionally copy the verified result to unlimited target folders (network drives, NAS, backup sticks).

A **security-focused** PyQt6 desktop app, built on the official Bitwarden CLI (`bw`, never bundled):

- Secrets live in RAM only (`bytearray`, best-effort wiped) - nothing secret is ever written to disk.
- Every export uses a fresh `bw` session: login → export → `lock` + `logout`.
- Every output file (and every self-update) is **sha256-verified** before it is accepted.

The guarantees are scoped, not absolute - read [`SECURITY.md`](SECURITY.md) before production use.

## Windows

**1. Install the Bitwarden CLI** (`bw`):

```powershell
winget install Bitwarden.CLI
```

The app auto-detects winget's install location. Installed some other way? Keep `bw` on `PATH` or enter the absolute path in **Settings**.

**2. Download & run**

Grab `Bitwarden2KeePass-v<version>.zip` from the [releases page](https://github.com/reserve85/Bitwarden_2_Keepass/releases), unzip, start `Bitwarden2KeePass.exe`.

> Run it from a **user-writable folder** (e.g. `C:\Tools\Bitwarden2KeePass`): the app keeps `config/`, `output/` and `bw_data/` next to the EXE and aborts in read-only locations (e.g. `C:\Program Files`).

No installer, no registry entries - fully portable and self-updating.

**From source** (Windows, Python ≥ 3.11):

```powershell
git clone https://github.com/reserve85/Bitwarden_2_Keepass.git
cd Bitwarden_2_Keepass
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m app.main
```

## Linux

No prebuilt binary yet - run from source (Python ≥ 3.11):

**1. Install the Bitwarden CLI** (`bw`) and make sure it is on `PATH` - e.g. via [Homebrew](https://brew.sh) (`brew install bitwarden-cli`) or from the [Bitwarden CLI releases](https://github.com/bitwarden/cli/releases) (`bw-linux-*.zip`).

**2. Install & run:**

```bash
git clone https://github.com/reserve85/Bitwarden_2_Keepass.git
cd Bitwarden_2_Keepass
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m app.main
```

A graphical desktop session is required; if the window does not open, your distribution's Qt6 system dependencies for PyQt6 are missing.

## Security

Key properties - the full, honest scoping lives in [`SECURITY.md`](SECURITY.md):

- Secrets stay in RAM as single mutable `bytearray` buffers that are best-effort wiped after use; nothing secret is written to disk.
- The `bw` CLI is isolated in an app-owned data folder (`BW_DATA_FOLDER` / `BW_CONFIG_FILE`), created per export and wiped afterwards - your regular `bw` config and session state are never touched.
- Fresh session per export: login, then `lock` + `logout` in a `finally` path.
- Logging is an in-memory ring buffer with redaction of secrets/tokens - never written to disk.
- Self-updates: the EXE's sha256 is published in every release body and verified against the downloaded file before applying.
- `bw` is trusted only after `bw --version` validation (PATH-hijack guard); user-writable resolutions raise a warning. `bw` is deliberately **not** bundled.
- "Wiping" means no extra copies, no persistence, no logging - **not** forensic memory erasure (Python `str`/`bytes` are immutable).

---

MIT - see [LICENSE](LICENSE).