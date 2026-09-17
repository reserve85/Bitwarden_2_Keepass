"""TokenCrypto tests - machine-derived key, legacy migration, never clear text.

# reference pattern (ported test suite)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.fernet import Fernet

if TYPE_CHECKING:
    from pathlib import Path

from app.application.use_cases.settings import SettingsUseCase
from app.infrastructure.config import security
from app.infrastructure.config.security import TokenCrypto
from app.main import _migrate_legacy_token
from tests.fakes import FakeSettings, RecordingLogger


def _migrate(
    raw_token: str | None,
    key_file: Path,
) -> tuple[FakeSettings, RecordingLogger, TokenCrypto]:
    settings = FakeSettings(initial={"update.token": raw_token})
    logger = RecordingLogger()
    crypto = TokenCrypto(key_file)
    _migrate_legacy_token(SettingsUseCase(settings, logger), crypto, logger)
    return settings, logger, crypto


def test_roundtrip() -> None:
    crypto = TokenCrypto()
    encrypted = crypto.encrypt("ghp_secret123")
    assert TokenCrypto.is_encrypted(encrypted)
    assert encrypted != "ghp_secret123"
    assert crypto.decrypt(encrypted) == "ghp_secret123"


def test_empty_values() -> None:
    crypto = TokenCrypto()
    assert crypto.encrypt("") == ""
    assert crypto.decrypt("") == ""
    assert crypto.decrypt(None) == ""
    assert TokenCrypto.is_encrypted("") is False
    assert TokenCrypto.is_encrypted(None) is False


def test_undecryptable_returns_empty() -> None:
    crypto = TokenCrypto()
    assert crypto.decrypt("gAAAAA" + "x" * 50) == ""  # malformed fernet token


def test_legacy_plaintext_passthrough() -> None:
    """A legacy clear-text token is read as-is and flagged for migration."""
    crypto = TokenCrypto()
    assert TokenCrypto.is_encrypted("ghp_plain") is False
    assert crypto.decrypt("ghp_plain") == "ghp_plain"
    # migration re-encrypts it
    rekeyed = crypto.reencrypt_if_legacy("ghp_plain")
    assert rekeyed is not None
    assert rekeyed != "ghp_plain"
    assert crypto.decrypt(rekeyed) == "ghp_plain"


def test_legacy_key_file_ciphertext_still_decrypts(tmp_path: Path) -> None:
    """Old builds encrypted with a key file; that ciphertext must keep working."""
    key_file = tmp_path / "key_file"
    key = Fernet.generate_key()
    key_file.write_bytes(key)
    old = Fernet(key).encrypt(b"old_token").decode("ascii")

    crypto = TokenCrypto(key_file)
    decrypt = crypto.decrypt(old)
    assert decrypt == "old_token"  # falls back to the legacy key file

    # and is migrated to the machine-derived key - then the key file is obsolete
    rekeyed = crypto.reencrypt_if_legacy(old)
    assert rekeyed is not None
    assert rekeyed != old
    assert crypto.decrypt(rekeyed) == "old_token"


def test_reencrypt_returns_none_when_already_current() -> None:
    crypto = TokenCrypto()
    encrypted = crypto.encrypt("token")
    assert crypto.reencrypt_if_legacy(encrypted) is None


def test_remove_legacy_key_file(tmp_path: Path) -> None:
    key_file = tmp_path / "key"
    key_file.write_bytes(Fernet.generate_key())
    crypto = TokenCrypto(key_file)
    assert key_file.exists()
    crypto.remove_legacy_key_file()
    assert not key_file.exists()
    # removing twice / without a file is harmless
    crypto.remove_legacy_key_file()


def test_machine_key_is_derived_not_a_file(tmp_path: Path) -> None:
    """No key file is created anywhere by the new implementation."""
    crypto = TokenCrypto()
    encrypted = crypto.encrypt("token")
    assert list(tmp_path.iterdir()) == []
    assert security._machine_fernet is not None  # noqa: SLF001
    assert crypto.decrypt(encrypted) == "token"


# -- composition-root integration: _migrate_legacy_token (app.main wiring) -------


def _migrate(
    raw_token: str | None,
    key_file: Path,
) -> tuple[FakeSettings, RecordingLogger, TokenCrypto]:
    settings = FakeSettings(initial={"update.token": raw_token})
    logger = RecordingLogger()
    crypto = TokenCrypto(key_file)
    _migrate_legacy_token(SettingsUseCase(settings, logger), crypto, logger)
    return settings, logger, crypto


def test_startup_migration_rekeys_legacy_plaintext_token(tmp_path: Path) -> None:
    """Composition-root wiring: a legacy clear-text token is re-encrypted at startup."""
    key_file = tmp_path / security.KEY_FILENAME
    key_file.write_bytes(Fernet.generate_key())

    settings, logger, crypto = _migrate("ghp_plain", key_file)

    stored = settings.to_dict()["update.token"]
    assert TokenCrypto.is_encrypted(stored)
    assert stored != "ghp_plain"
    assert crypto.decrypt(stored) == "ghp_plain"
    assert not key_file.exists()  # obsolete key file is removed after re-keying
    assert any("Migrated the update token" in m for m in logger.messages)


def test_startup_migration_rekeys_legacy_key_file_ciphertext(tmp_path: Path) -> None:
    """Old key-file ciphertext keeps decrypting and is re-keyed to the machine key."""
    key_file = tmp_path / security.KEY_FILENAME
    key = Fernet.generate_key()
    key_file.write_bytes(key)
    old = Fernet(key).encrypt(b"old_token").decode("ascii")

    settings, _logger, crypto = _migrate(old, key_file)

    stored = settings.to_dict()["update.token"]
    assert TokenCrypto.is_encrypted(stored)
    assert crypto.decrypt(stored) == "old_token"
    assert not key_file.exists()


def test_startup_migration_leaves_current_ciphertext_untouched(tmp_path: Path) -> None:
    """Already-current ciphertext is not rewritten and nothing is logged."""
    current = TokenCrypto().encrypt("token")

    settings, logger, _crypto = _migrate(current, tmp_path / "no-key-file")

    assert settings.to_dict()["update.token"] == current
    assert settings.updated_keys == []
    assert logger.messages == []


def test_startup_migration_missing_token_is_a_noop(tmp_path: Path) -> None:
    settings, logger, _crypto = _migrate(None, tmp_path / "no-key-file")

    assert settings.updated_keys == []
    assert logger.messages == []


def test_startup_migration_failure_is_logged_not_raised() -> None:
    """A broken legacy token must never block startup - it is logged (redacted)."""

    class _Broken:
        def reencrypt_if_legacy(self, _raw: str) -> str:
            raise OSError("disk full")

        def remove_legacy_key_file(self) -> None:
            return None

    settings = FakeSettings(initial={"update.token": "ghp_plain"})
    logger = RecordingLogger()

    _migrate_legacy_token(  # type: ignore[arg-type]  - intentionally broken crypto
        SettingsUseCase(settings, logger),
        _Broken(),
        logger,
    )

    assert settings.updated_keys == []
    assert any("Could not migrate" in m for m in logger.messages)
