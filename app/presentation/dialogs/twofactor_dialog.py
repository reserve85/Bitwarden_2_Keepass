"""One-time TOTP code dialog (6-8 digits; input cleared after use).

The code is a short-lived secret: the widget copy is cleared on accept/cancel
and the code is never logged by the caller (the login use case only passes it
to the bw CLI).

# reference pattern
"""

from __future__ import annotations

from PyQt6.QtCore import QRegularExpression
from PyQt6.QtGui import QRegularExpressionValidator
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from app.infrastructure.secure import drop_qt_str


class TwoFactorDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Two-factor authentication")
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Enter the two-factor code (6-8 digits):"))

        self._line = QLineEdit(self)
        self._line.setPlaceholderText("123456")
        self._line.setValidator(
            QRegularExpressionValidator(QRegularExpression("[0-9]{6,8}"), self),
        )
        layout.addWidget(self._line)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            self,
        )
        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)

    def get_code(self) -> str | None:
        """Run the modal loop; return the code or ``None``; clear the field."""
        accepted = self.exec() == QDialog.DialogCode.Accepted
        return self._collect(accepted)

    def _collect(self, *, accepted: bool) -> str | None:
        """Shared accept/cancel path (testable without the modal loop)."""
        text = self._line.text()
        result = text.strip() if (accepted and text.strip()) else None
        drop_qt_str(self._line)
        return result
