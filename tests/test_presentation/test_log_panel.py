# ruff: noqa: SLF001 - GUI tests intentionally drive private member internals

"""LogPanel tests (offscreen) - append, colored levels, cap, clear."""

from __future__ import annotations

import pytest

from app.presentation.log_panel import LogPanel


@pytest.mark.offscreen
class TestLogPanel:
    def test_appends_lines_and_clears(self) -> None:
        panel = LogPanel()

        panel.add_line("2024-01-01 00:00:00 [INFO] <GUI> hello")
        panel.add_line("2024-01-01 00:00:01 [WARNING] <CONFIG> world")

        assert "hello" in panel.to_plain_text()
        assert "world" in panel.to_plain_text()

        panel.clear()
        assert panel.to_plain_text() == ""

    def test_caps_block_count(self) -> None:
        panel = LogPanel()

        for index in range(panel._view.maximumBlockCount() + 100):
            panel.add_line(f"line {index}")

        text = panel.to_plain_text()
        assert "line 0" not in text  # oldest blocks were dropped
        assert "line 1999" in text or "line 2099" in text

    def test_clear_button_clears(self) -> None:
        panel = LogPanel()
        panel.add_line("something")
        assert panel.to_plain_text() != ""

        panel._clear_button.click()

        assert panel.to_plain_text() == ""
