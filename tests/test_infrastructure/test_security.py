"""TokenCrypto tests - machine-derived key, legacy migration, never clear text.

# reference pattern (ported test suite)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.fernet import Fernet

if TYPE_CHECKING:
    from pathlib import Path

from app.infrastructure.config import security
from app.infrastructure.config.security import TokenCrypto


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
