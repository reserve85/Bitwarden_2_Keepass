"""Secure helper tests - wipe, single-buffer password, widget clearing, redaction."""

from __future__ import annotations

from app.infrastructure.secure import (
    _is_sensitive_field_name,
    drop_qt_str,
    redact_secrets,
    secure_password_from_str,
    wipe,
)


def test_wipe_zeroes_and_clears_buffer() -> None:
    buffer = bytearray(b"secret-password-123")
    wipe(buffer)
    # every byte was overwritten; the buffer is additionally drained
    assert all(byte == 0 for byte in buffer)
    assert len(buffer) == 0


def test_wipe_never_raises() -> None:
    wipe(bytearray())
    wipe(bytearray(b"x" * 1000))
    # odd-but-valid buffer kinds
    wipe(bytearray(b"\x00\x01\x02"))


def test_secure_password_from_str_returns_one_mutable_buffer() -> None:
    value = secure_password_from_str("hunter2")
    assert isinstance(value, bytearray)
    assert not isinstance(value, bytes)  # bytes cannot be wiped
    assert bytes(value) == b"hunter2"
    wipe(value)
    assert len(value) == 0


def test_secure_password_from_str_utf8() -> None:
    value = secure_password_from_str("pässwörd-🔑")
    assert bytes(value) == "pässwörd-🔑".encode()
    wipe(value)


def test_drop_qt_str_clears_widget() -> None:
    class FakeField:
        def __init__(self) -> None:
            self.text = "secret"
            self.calls = 0

        def clear(self) -> None:
            self.calls += 1
            self.text = ""

    field = FakeField()
    drop_qt_str(field)
    assert field.calls == 1
    assert field.text == ""


def test_drop_qt_str_noop_on_non_widgets() -> None:
    drop_qt_str(None)
    drop_qt_str(42)
    drop_qt_str("text")


def test_drop_qt_str_never_raises_on_raising_clear() -> None:
    class RaisedClear:
        def clear(self) -> None:
            msg = "boom"
            raise RuntimeError(msg)

    drop_qt_str(RaisedClear())


def test_redact_sensitive_assignments() -> None:
    assert redact_secrets("password=hunter2") == "password=***"
    assert redact_secrets("pass: hunter2") == "pass: ***"
    assert redact_secrets('"token" = "abc"') == '"token" = ***'
    assert redact_secrets("api_key=secret_value") == "api_key=***"
    assert redact_secrets("client_secret: xyz") == "client_secret: ***"
    assert redact_secrets("totp zzz") == "totp zzz"  # no assignment -> untouched


def test_redact_sensitive_assignments_case_insensitive() -> None:
    assert redact_secrets("PassWord=abc") == "PassWord=***"
    assert redact_secrets("PASSWORD: abc") == "PASSWORD: ***"
    assert redact_secrets("SeCrEt=a") == "SeCrEt=***"


def test_redact_long_base64_tokens() -> None:
    session = "A" * 40 + "B" * 10
    assert redact_secrets(f"session={session}") == "session=***"
    bare = "x" * 30
    assert redact_secrets(bare) == "***"


def test_redact_keeps_plain_messages() -> None:
    text = "Export completed successfully. 3 folders, 12 items."
    assert redact_secrets(text) == text


def test_redact_empty() -> None:
    assert redact_secrets("") == ""
    assert redact_secrets(None) is None  # type: ignore[arg-type]


def test_is_sensitive_field_name_matches_secret_like_names() -> None:
    for name in (
        "password",
        "Password",
        "passphrase",
        "totp",
        "TOTP",
        "seed",
        "pin",
        "api_key",
        "client_secret",
        "secret",
    ):
        assert _is_sensitive_field_name(name)
    for name in ("username", "notes", "url", "cardholder name", "brand"):
        assert not _is_sensitive_field_name(name)
