"""Sample-data spec checks (implementation plan, testing section).

``tests/samples/bitwarden_vault.json`` must keep mirroring a real ``bw list
items`` payload, including the edge cases the export pipe must survive (ghost
folder id, hidden fields, empty names, multiple attachments). These tests pin
that shape so the sample cannot silently drift back to a happy-path fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

_SAMPLES = Path(__file__).resolve().parents[1] / "samples"
_VAULT = json.loads((_SAMPLES / "bitwarden_vault.json").read_text(encoding="utf-8"))

#: The plan spec requires the sample login item to carry two attachments.
_EXPECTED_ATTACHMENT_COUNT = 2


def test_attachment_sample_file_exists_and_is_nonempty() -> None:
    payload = (_SAMPLES / "attachment.bin").read_bytes()
    assert payload


def test_vault_contains_all_plan_item_kinds() -> None:
    types = {item.get("type") for item in _VAULT["items"]}
    # 1 = LOGIN, 2 = SECURE_NOTE, 3 = CARD, 4 = IDENTITY
    assert types >= {1, 2, 3, 4}


def test_vault_contains_nested_folders() -> None:
    assert any("/" in (folder.get("name") or "") for folder in _VAULT["folders"])


def test_login_item_has_two_attachments() -> None:
    login = next(item for item in _VAULT["items"] if item.get("id") == "login-1")
    assert len(login["attachments"]) == _EXPECTED_ATTACHMENT_COUNT
    assert {attachment["id"] for attachment in login["attachments"]} == {
        "att-1",
        "att-2",
    }


def test_vault_contains_a_hidden_field() -> None:
    hidden = [
        field
        for item in _VAULT["items"]
        for field in (item.get("fields") or [])
        if field.get("type") == 1  # HIDDEN
    ]
    assert hidden


def test_vault_contains_ghost_folder_id_item() -> None:
    folder_ids = {folder.get("id") for folder in _VAULT["folders"]}
    ghost = [item for item in _VAULT["items"] if item.get("folderId") not in folder_ids]
    assert ghost  # item whose folder vanished -> root-group fallback


def test_vault_contains_empty_name_item() -> None:
    assert any(not (item.get("name") or "") for item in _VAULT["items"])
