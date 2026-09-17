"""LogPanel - the in-memory log viewer (colored levels, clear button).

The AppLogger feeds lines here via ``install_gui_handler(self.add_line)``; the
panel itself never writes to disk. Levels are colored with a syntax highlighter
(reference pattern); the buffer is capped to keep the UI responsive.

# reference pattern
"""

from __future__ import annotations

import re

from PyQt6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

_MAX_LINES = 2000

_LEVEL_PATTERN = re.compile(r"\[(DEBUG|INFO|WARNING|ERROR|CRITICAL)\]")
_LEVEL_COLORS = {
    "DEBUG": "#7f8c8d",
    "INFO": "#2c3e50",
    "WARNING": "#b26a00",
    "ERROR": "#c0392b",
    "CRITICAL": "#c0392b",
}


class _LevelHighlighter(QSyntaxHighlighter):
    """Colors the ``[LEVEL]`` token inside every log line."""

    def __init__(self, document: object) -> None:
        super().__init__(document)

    def highlightBlock(self, text: str) -> None:  # noqa: N802 - Qt override name
        match = _LEVEL_PATTERN.search(text)
        if match is None:
            return
        level = match.group(1)
        char_format = QTextCharFormat()
        char_format.setForeground(QColor(_LEVEL_COLORS.get(level, "#000000")))
        char_format.setFontWeight(QFont.Weight.Bold)
        self.setFormat(match.start(1), len(level), char_format)


class LogPanel(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._view = QPlainTextEdit(self)
        self._view.setReadOnly(True)
        self._view.setMaximumBlockCount(_MAX_LINES)
        _LevelHighlighter(self._view.document())

        self._clear_button = QPushButton("Clear", self)
        self._clear_button.clicked.connect(self._view.clear)

        layout = QVBoxLayout(self)
        layout.addWidget(self._view)
        button_row = QHBoxLayout()
        button_row.addStretch(1)
        button_row.addWidget(self._clear_button)
        layout.addLayout(button_row)

    def add_line(self, line: str) -> None:
        """Append one formatted log line (thread-safe marshaling done upstream)."""
        self._view.appendPlainText(line)

    def clear(self) -> None:
        self._view.clear()

    def to_plain_text(self) -> str:
        return self._view.toPlainText()
