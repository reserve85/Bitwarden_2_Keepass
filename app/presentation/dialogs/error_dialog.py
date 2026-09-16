"""Error dialog with INTERNAL redaction - the message is treated as untrusted.

Defense-in-depth: even if a caller forgets to redact, the error text shown to
the user never contains secret-like content (passwords, tokens, long base64
session keys, hidden-field values). The redacted text is also what the log
panel / result surfaces use, so a raw secret cannot leak via the dialog copy.

# reference pattern
"""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.infrastructure.secure import redact_secrets


class ErrorDialog(QDialog):
    """Shows ``redact_secrets(message)``; the caller may pass anything."""

    def __init__(self, message: str, title: str = "Error", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        # Redacted INSIDE the dialog - the raw *message* is never displayed.
        self.redacted_message = redact_secrets(message)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(title + ":"))
        view = QPlainTextEdit(self)
        view.setReadOnly(True)
        view.setPlainText(self.redacted_message)
        view.setMaximumHeight(180)
        layout.addWidget(view)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok, self)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
