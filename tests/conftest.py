"""Shared pytest fixtures: settings, logger, sample vault, fake bw client."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import FakeBwCli, RecordingLogger

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
