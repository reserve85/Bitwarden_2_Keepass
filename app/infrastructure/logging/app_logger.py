"""In-memory ring-buffer logger - the only logging sink in the application.

Guarantee: **no file output of any kind**. The logger keeps a bounded in-memory
ring buffer and can feed a GUI callback over a signal.

# Gasmeter pattern
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from app.domain.entities import LogCategory, LogLevel

_LOGGER_NAME = "bitwarden2keepass"
_FORMAT = "%(asctime)s [%(levelname)s] <%(category)s> %(message)s"
_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


class _InMemoryHandler(logging.Handler):
    def __init__(self, owner: AppLogger) -> None:
        super().__init__()
        self._owner = owner

    def emit(self, record: logging.LogRecord) -> None:
        message = self.format(record)
        self._owner._push(message)  # noqa: SLF001


class AppLogger:
    """Bounded in-memory logger with an optional GUI callback sink."""

    def __init__(self, max_lines: int = 2000) -> None:
        self._max_lines = max_lines
        self._deque: deque[str] = deque(maxlen=max_lines)
        self._lock = threading.Lock()
        self._callback = None
        self._logger = logging.getLogger(_LOGGER_NAME)
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False
        self._logger.handlers.clear()
        self._handler = _InMemoryHandler(self)
        self._handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_TIME_FORMAT))
        self._logger.addHandler(self._handler)

    # -- EventLogger port --------------------------------------------------------
    def log(self, category: LogCategory, level: LogLevel, message: str) -> None:
        record = self._logger.makeRecord(
            _LOGGER_NAME,
            getattr(logging, level.value, logging.INFO),
            __name__,
            0,
            message,
            None,
            None,
        )
        record.category = category.value
        self._handler.handle(record)

    # -- in-memory sink ----------------------------------------------------------
    def _push(self, line: str) -> None:
        with self._lock:
            self._deque.append(line)
        callback = self._callback
        if callback is not None:
            callback(line)

    def history(self) -> list[str]:
        with self._lock:
            return list(self._deque)

    def clear(self) -> None:
        with self._lock:
            self._deque.clear()

    def install_gui_handler(self, callback: Callable[[str], None]) -> None:
        """Feed the UI log panel. ``callback(str)`` must marshal to the UI thread."""
        self._callback = callback

    def has_disk_handlers(self) -> bool:
        """Test helper: the logger must never have any handler writing to disk."""
        return any(isinstance(h, logging.FileHandler) for h in self._logger.handlers)
