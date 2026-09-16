"""AppLogger tests - in-memory only, categories, bounded history, GUI callback."""

from __future__ import annotations

from app.domain.entities import LogCategory, LogLevel
from app.infrastructure.logging.app_logger import AppLogger

_MAX_LINES = 10
_TOTAL_LOG_LINES = 25


def test_log_writes_formatted_history_with_category() -> None:
    logger = AppLogger(max_lines=100)
    logger.log(LogCategory.AUTH, LogLevel.INFO, "Logging in")
    history = logger.history()
    assert len(history) == 1
    line = history[0]
    assert "[INFO]" in line
    assert "<AUTH>" in line
    assert "Logging in" in line


def test_all_levels_are_formatted() -> None:
    logger = AppLogger(max_lines=100)
    for level in LogLevel:
        logger.log(LogCategory.CONFIG, level, f"message {level.value}")
    history = logger.history()
    assert len(history) == len(LogLevel)
    for level in LogLevel:
        assert any(f"[{level.value}]" in line for line in history)


def test_all_categories_are_formatted() -> None:
    logger = AppLogger(max_lines=100)
    for category in LogCategory:
        logger.log(category, LogLevel.INFO, "x")
    history = logger.history()
    assert len(history) == len(LogCategory)
    for category in LogCategory:
        assert any(f"<{category.value}>" in line for line in history)


def test_history_is_bounded() -> None:
    logger = AppLogger(max_lines=_MAX_LINES)
    for index in range(_TOTAL_LOG_LINES):
        logger.log(LogCategory.EXPORT, LogLevel.DEBUG, f"line {index}")
    history = logger.history()
    assert len(history) == _MAX_LINES
    assert history[0].endswith("line 15")  # oldest dropped
    assert history[-1].endswith("line 24")


def test_clear_empties_history() -> None:
    logger = AppLogger(max_lines=100)
    logger.log(LogCategory.GUI, LogLevel.INFO, "x")
    logger.clear()
    assert logger.history() == []


def test_has_disk_handlers_is_false() -> None:
    logger = AppLogger(max_lines=100)
    assert logger.has_disk_handlers() is False


def test_gui_callback_receives_lines() -> None:
    logger = AppLogger(max_lines=100)
    received: list[str] = []
    logger.install_gui_handler(received.append)
    logger.log(LogCategory.UPDATE, LogLevel.WARNING, "update available")
    assert len(received) == 1
    assert "<UPDATE>" in received[0]
    assert "[WARNING]" in received[0]


def test_gui_callback_may_be_uninstalled() -> None:
    logger = AppLogger(max_lines=100)
    received: list[str] = []
    logger.install_gui_handler(received.append)
    logger.clear()
    logger.install_gui_handler(None)
    logger.log(LogCategory.GUI, LogLevel.INFO, "x")
    assert received == []
