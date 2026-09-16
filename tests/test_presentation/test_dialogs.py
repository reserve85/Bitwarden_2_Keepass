# ruff: noqa: SLF001 - GUI tests intentionally drive private member internals

"""Dialog tests (offscreen) - value collection, field clearing, redaction."""

from __future__ import annotations

import pytest
from PyQt6.QtWidgets import QDialog

from app.presentation.dialogs.confirm_password_dialog import ConfirmPasswordDialog
from app.presentation.dialogs.error_dialog import ErrorDialog
from app.presentation.dialogs.password_dialog import PasswordDialog
from app.presentation.dialogs.twofactor_dialog import TwoFactorDialog


@pytest.mark.offscreen
class TestPasswordDialog:
    def test_accept_returns_bytearray_and_clears_field(self) -> None:
        dialog = PasswordDialog("Login")
        dialog._line.setText("hunter2")

        result = dialog._collect(accepted=True)

        assert bytes(result) == b"hunter2"
        assert isinstance(result, bytearray)
        assert dialog._line.text() == ""

    def test_cancel_returns_none_and_clears_field(self) -> None:
        dialog = PasswordDialog("Login")
        dialog._line.setText("hunter2")

        assert dialog._collect(accepted=False) is None
        assert dialog._line.text() == ""

    def test_empty_accept_returns_none(self) -> None:
        dialog = PasswordDialog("Login")
        assert dialog._collect(accepted=True) is None

    def test_get_password_accept_returns_bytearray(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """get_password() must pass the dialog result on (regression: positional
        call to the keyword-only _collect raised TypeError)."""
        dialog = PasswordDialog("Login")
        monkeypatch.setattr(dialog, "exec", lambda: QDialog.DialogCode.Accepted)
        dialog._line.setText("hunter2")

        result = dialog.get_password()

        assert bytes(result) == b"hunter2"
        assert dialog._line.text() == ""

    def test_get_password_cancel_returns_none(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        dialog = PasswordDialog("Login")
        monkeypatch.setattr(dialog, "exec", lambda: QDialog.DialogCode.Rejected)
        dialog._line.setText("hunter2")

        assert dialog.get_password() is None
        assert dialog._line.text() == ""


@pytest.mark.offscreen
class TestConfirmPasswordDialog:
    def test_ok_enabled_only_when_both_fields_match(self) -> None:
        dialog = ConfirmPasswordDialog("Create")
        ok = dialog._buttons.button(dialog._buttons.StandardButton.Ok)
        assert not ok.isEnabled()

        dialog._password.setText("abc")
        dialog._confirm.setText("abd")
        assert not ok.isEnabled()
        assert not dialog._error.isHidden()

        dialog._confirm.setText("abc")
        assert ok.isEnabled()
        assert not dialog._error.isVisible()

    def test_accept_returns_matching_bytearray_and_clears(self) -> None:
        dialog = ConfirmPasswordDialog("Create")
        dialog._password.setText("abc")
        dialog._confirm.setText("abc")

        result = dialog._collect(accepted=True)

        assert bytes(result) == b"abc"
        assert dialog._password.text() == ""
        assert dialog._confirm.text() == ""

    def test_accept_with_mismatch_returns_none(self) -> None:
        dialog = ConfirmPasswordDialog("Create")
        dialog._password.setText("abc")
        dialog._confirm.setText("abd")

        assert dialog._collect(accepted=True) is None

    def test_get_password_accept_returns_bytearray(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Regression: get_password() fed _collect positionally -> TypeError."""
        dialog = ConfirmPasswordDialog("Create")
        monkeypatch.setattr(dialog, "exec", lambda: QDialog.DialogCode.Accepted)
        dialog._password.setText("abc")
        dialog._confirm.setText("abc")

        result = dialog.get_password()

        assert bytes(result) == b"abc"
        assert dialog._password.text() == ""
        assert dialog._confirm.text() == ""


@pytest.mark.offscreen
class TestTwoFactorDialog:
    def test_accept_returns_code_and_clears_field(self) -> None:
        dialog = TwoFactorDialog()
        dialog._line.setText("123456")

        code = dialog._collect(accepted=True)

        assert code == "123456"
        assert dialog._line.text() == ""

    def test_cancel_returns_none_and_clears_field(self) -> None:
        dialog = TwoFactorDialog()
        dialog._line.setText("123456")

        assert dialog._collect(accepted=False) is None
        assert dialog._line.text() == ""

    def test_get_code_accept_returns_code(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Regression: get_code() fed _collect positionally -> TypeError."""
        dialog = TwoFactorDialog()
        monkeypatch.setattr(dialog, "exec", lambda: QDialog.DialogCode.Accepted)
        dialog._line.setText("123456")

        code = dialog.get_code()

        assert code == "123456"
        assert dialog._line.text() == ""


@pytest.mark.offscreen
class TestErrorDialog:
    def test_redaction_is_internal(self) -> None:
        dialog = ErrorDialog("login failed password=supersecret session key=AAAA...")

        assert "supersecret" not in dialog.redacted_message
        assert "***" in dialog.redacted_message
        assert dialog.windowTitle() == "Error"

    def test_plain_message_passes_through(self) -> None:
        dialog = ErrorDialog("output folder not writable", title="Export failed")

        assert dialog.redacted_message == "output folder not writable"
        assert dialog.windowTitle() == "Export failed"
