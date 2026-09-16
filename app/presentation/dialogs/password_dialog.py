"""Master-password dialog returning a single mutable ``bytearray``.

The password is converted with :func:`secure_password_from_str` (ONE mutable
buffer - no immutable ``bytes`` copy) and the Qt line-edit copy is cleared on
the way out. Never stored, never logged.

# reference pattern
"""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from app.infrastructure.secure import drop_qt_str, secure_password_from_str


class PasswordDialog(QDialog):
    def __init__(self, prompt: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Bitwarden master password")
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(prompt))

        self._line = QLineEdit(self)
        self._line.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self._line)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            self,
        )
        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)

    def get_password(self) -> bytearray | None:
        """Run the modal loop; return a wiped-copy ``bytearray`` or ``None``.

        The Qt string copy is cleared whether accepted or cancelled.
        """
        accepted = self.exec() == QDialog.DialogCode.Accepted
        return self._collect(accepted=accepted)

    def _collect(self, *, accepted: bool) -> bytearray | None:
        """Shared accept/cancel path (testable without the modal loop)."""
        text = self._line.text()
        result = secure_password_from_str(text) if (accepted and text) else None
        drop_qt_str(self._line)
        return result
