"""KeePass master-password dialog with confirmation.

OK is only enabled while both fields are non-empty AND equal; a mismatch shows
an error label that is never logged. The password is returned as a single
``bytearray`` and both Qt line copies are cleared on the way out.

# Gasmeter pattern
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from app.infrastructure.secure import drop_qt_str, secure_password_from_str


class ConfirmPasswordDialog(QDialog):
    def __init__(self, prompt: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("KeePass master password")
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(prompt))

        self._password = QLineEdit(self)
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._password.setPlaceholderText("Master password")
        layout.addWidget(self._password)

        self._confirm = QLineEdit(self)
        self._confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm.setPlaceholderText("Repeat master password")
        layout.addWidget(self._confirm)

        self._error = QLabel("Passwords do not match.")
        self._error.setObjectName("ConfirmPasswordError")
        self._error.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self._error.setStyleSheet("color: #b00020;")
        self._error.setVisible(False)
        layout.addWidget(self._error)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            self,
        )
        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)

        self._password.textChanged.connect(self._validate)
        self._confirm.textChanged.connect(self._validate)
        self._validate()

    def get_password(self) -> bytearray | None:
        """Run the modal loop; return the wiped-copy password or ``None``."""
        accepted = self.exec() == QDialog.DialogCode.Accepted
        return self._collect(accepted)

    def _collect(self, *, accepted: bool) -> bytearray | None:
        """Shared accept/cancel path (testable without the modal loop)."""
        first = self._password.text()
        second = self._confirm.text()
        result = (
            secure_password_from_str(first) if (accepted and first and first == second) else None
        )
        drop_qt_str(self._password)
        drop_qt_str(self._confirm)
        return result

    def _validate(self) -> None:
        first = self._password.text()
        second = self._confirm.text()
        matching = bool(first) and first == second
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(matching)
        # Only nag after the user typed something that disagrees.
        self._error.setVisible(bool(first) and not matching)
