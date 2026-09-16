"""MainPage - the "Start Export" home page with live progress + last-run summary."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from app.domain.entities import ExportProgress


class MainPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        heading = QLabel("Bitwarden 2 KeePass")
        heading.setStyleSheet("font-size: 20pt; font-weight: bold;")
        instructions = QLabel(
            "Export your complete Bitwarden vault into a fresh KeePass file. "
            "The export file is verified and then copied to your configured "
            "target folders.",
        )
        instructions.setWordWrap(True)

        self.start_button = QPushButton("Start Export", self)
        self.start_button.setMinimumHeight(44)

        self._status = QLabel("Ready.", self)

        self._progress = QProgressBar(self)
        self._progress.setRange(0, 100)
        self._progress.setValue(0)

        self._summary = QLabel("", self)
        self._summary.setWordWrap(True)
        self._summary.setVisible(False)

        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(instructions)
        layout.addSpacing(12)
        layout.addWidget(self.start_button)
        layout.addSpacing(12)
        layout.addWidget(self._status)
        layout.addWidget(self._progress)
        layout.addWidget(self._summary)
        layout.addStretch(1)

    def set_progress(self, progress: ExportProgress) -> None:
        """Apply one progress sample (LOGIN/SYNC/... phases all land here)."""
        self._status.setText(progress.message)
        if progress.total <= 0 and progress.fraction <= 0.0:
            # Indeterminate busy state (e.g. the interactive login prompt).
            self._progress.setRange(0, 0)
            return
        self._progress.setRange(0, 100)
        self._progress.setValue(round(progress.fraction * 100))

    def set_busy(self, *, busy: bool) -> None:
        """Disable the start button and show an indeterminate bar while busy."""
        self.start_button.setEnabled(not busy)
        if busy:
            self._progress.setRange(0, 0)
        else:
            self._progress.setRange(0, 100)
            self._progress.setValue(0)

    def set_summary(self, text: str) -> None:
        """Show the last-run summary text (file, destinations, counts)."""
        self._summary.setText(text)
        self._summary.setVisible(bool(text))

    def set_status(self, text: str) -> None:
        self._status.setText(text)
