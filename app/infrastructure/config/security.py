"""GitHub-token encryption - never stored in clear text.

Ported from Gasmeter-Downloader (``app/infrastructure/config/security.py``):
the Fernet key is **derived at runtime** with PBKDF2-HMAC-SHA256
(100 000 iterations) from a machine-specific identifier, so nothing secret is
persisted besides the ciphertext itself - there is deliberately *no* key file
on disk. A config copy that leaves this machine cannot be decrypted elsewhere.

Legacy support: older builds stored a Fernet key file next to the config. Its
ciphertext keeps decrypting through a fallback path, and
``reencrypt_if_legacy`` re-keys such values under the current machine-derived
key so the old key file can be deleted.

# Gasmeter pattern
"""

from __future__ import annotations

import base64
import contextlib
import os
import platform
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEY_FILENAME = ".bitwarden2keepass_token_key"  # legacy key file (removed after migration)

#: App-unique salt - the derived key cannot be replayed against another app.
_SALT = b"Bitwarden2KeePass_v1"
_ITERATIONS = 100_000

#: Every Fernet token starts with this marker; used to detect encrypted values
#: and to migrate legacy clear-text tokens.
_FERNET_PREFIX = "gAAAAA"

#: One KDF run per process (the machine identity is stable), keeps the
#: round-trip cheap for settings dialogs and update checks.
_machine_fernet: Fernet | None = None


def _get_machine_fernet() -> Fernet:
    global _machine_fernet  # noqa: PLW0603 - module-level cache on purpose
    if _machine_fernet is None:
        machine_id = "|".join(
            [
                platform.node(),
                os.environ.get("USERNAME") or os.environ.get("USER") or "",
                platform.machine(),
                platform.processor(),
            ],
        ).encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=_SALT,
            iterations=_ITERATIONS,
        )
        _machine_fernet = Fernet(base64.urlsafe_b64encode(kdf.derive(machine_id)))
    return _machine_fernet


def _decrypt_or_none(fernet: Fernet, encrypted: str) -> str | None:
    """Decrypt with ``fernet``; return ``None`` on any failure (no raise)."""
    try:
        return fernet.decrypt(encrypted.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


class TokenCrypto:
    """Encrypt/decrypt tokens with a machine-derived key.

    ``key_file`` is accepted for backward compatibility only: it is consulted
    as a *fallback* so ciphertext from the old key-file scheme keeps
    decrypting until the value is re-saved (or re-keyed by
    :meth:`reencrypt_if_legacy`). New ciphertext always uses the machine key.
    """

    def __init__(self, key_file: str | Path | None = None) -> None:
        self._legacy_key_file = Path(key_file) if key_file else None

    # -- public API -----------------------------------------------------------
    def encrypt(self, token: str) -> str:
        """Encrypt ``token``; ``""`` stays ``""`` (empty = no token)."""
        if not token:
            return ""
        return _get_machine_fernet().encrypt(token.encode("utf-8")).decode("ascii")

    def decrypt(self, encrypted: str | None) -> str:
        """Plaintext, or ``""`` when missing/undecryptable.

        A legacy *clear-text* value is handed back as-is (it is re-encrypted on
        the next save - see ``SettingsUseCase`` and the startup migration).
        """
        if not encrypted:
            return ""
        if not self.is_encrypted(encrypted):
            return encrypted
        try:
            return _get_machine_fernet().decrypt(encrypted.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError):
            legacy = self._legacy_fernet()
            if legacy is None:
                return ""
            try:
                return legacy.decrypt(encrypted.encode("ascii")).decode("utf-8")
            except (InvalidToken, ValueError):
                return ""

    def reencrypt_if_legacy(self, encrypted: str) -> str | None:
        """Re-encrypt under the current key when ``encrypted`` uses the old key file.

        Returns the new ciphertext, or ``None`` when the value is already
        current-key crypto, empty, or undecryptable.
        """
        if not encrypted:
            return None
        if not self.is_encrypted(encrypted):
            return self.encrypt(encrypted)
        if _decrypt_or_none(_get_machine_fernet(), encrypted) is not None:
            return None  # already encrypted with the current machine key
        legacy = self._legacy_fernet()
        if legacy is None:
            return None
        plain = _decrypt_or_none(legacy, encrypted)
        return None if plain is None else self.encrypt(plain)

    @staticmethod
    def is_encrypted(value: str | None) -> bool:
        """``True`` when ``value`` looks like Fernet ciphertext (starts ``gAAAAA``)."""
        return bool(value) and value.startswith(_FERNET_PREFIX)

    def remove_legacy_key_file(self) -> None:
        """Delete the obsolete key file (best-effort; missing file is fine)."""
        if self._legacy_key_file is not None:
            with contextlib.suppress(OSError):
                self._legacy_key_file.unlink()

    # -- legacy fallback ---------------------------------------------------------
    def _legacy_fernet(self) -> Fernet | None:
        if self._legacy_key_file is None:
            return None
        try:
            raw = self._legacy_key_file.read_bytes().strip()
            return Fernet(raw) if raw else None
        except (OSError, ValueError, TypeError):
            return None
