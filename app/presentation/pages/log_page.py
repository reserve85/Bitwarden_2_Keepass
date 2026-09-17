"""LogPage - hosts the in-memory LogPanel for the whole application."""

from __future__ import annotations

from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget

from app.presentation.log_panel import LogPanel


class LogPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self.panel = LogPanel(self)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Application log (in-memory only - never written to disk):"))
        layout.addWidget(self.panel, 1)
