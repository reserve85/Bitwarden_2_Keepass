"""Shared pytest fixtures: settings, logger, sample vault, fake bw client."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from PyQt6.QtWidgets import QApplication

from tests.fakes import FakeBwCli, RecordingLogger

# GUI tests run headless; the env var must be set before any QApplication.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_SAMPLES = Path(__file__).parent / "samples"


@pytest.fixture
def logger() -> RecordingLogger:
    return RecordingLogger()


@pytest.fixture
def fake_bw() -> FakeBwCli:
    return FakeBwCli()


@pytest.fixture
def sample_vault() -> dict:
    """The mocked full vault from samples/bitwarden_vault.json (folders + items)."""
    return json.loads((_SAMPLES / "bitwarden_vault.json").read_text(encoding="utf-8"))


@pytest.fixture
def sample_folders(sample_vault: dict) -> list[dict]:
    return list(sample_vault["folders"])


@pytest.fixture
def sample_items(sample_vault: dict) -> list[dict]:
    return list(sample_vault["items"])


@pytest.fixture(scope="session", autouse=True)
def qapp() -> QApplication:
    """One offscreen QApplication for all GUI tests (created once)."""
    return QApplication.instance() or QApplication([])
