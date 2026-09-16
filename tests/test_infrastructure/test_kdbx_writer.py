"""KdbxWriter tests - real temp kdbx roundtrips (create/load/add/save/verify)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pykeepass import PyKeePass

from app.infrastructure.kdbx.item import CustomFieldType, Item
from app.infrastructure.kdbx.kdbx_writer import (
    BITWARDEN_ID_PROPERTY,
    MAX_TITLE_ATTEMPTS,
    TOTP_SEED_PROPERTY,
    TOTP_SETTINGS_PROPERTY,
    KdbxWriter,
    _redacted_item,
    _sync_attachments,
)

if TYPE_CHECKING:
    from pathlib import Path

_MASTER_PASSWORD = "pw"

#: Documented ceiling for the title-suffix retry loop.
_EXPECTED_MAX_TITLE_ATTEMPTS = 5


def _is_protected(entry: object, name: str) -> bool:
    """True when the custom property's XML Value carries ``Protected="True"``."""
    value = entry._xpath(  # noqa: SLF001
        f'String/Key[text()="{name}"]/../Value',
        first=True,
    )
    return value is not None and value.get("Protected") == "True"


def _login_item(
    name: str,
    item_id: str,
    *,
    password: str = "hunter2",
    folder_id: str | None = None,
) -> dict:
    item: dict = {
        "id": item_id,
        "type": 1,
        "name": name,
        "login": {
            "username": "user@example.com",
            "password": password,
            "uris": [{"uri": "https://example.com"}],
            "totp": "otpauth://totp/Example:user?secret=ABCDEFGHIJ&period=30&digits=6",
        },
        "fields": [],
        "tags": [],
        "attachments": [],
        "notes": "some notes",
    }
    if folder_id is not None:
        item["folderId"] = folder_id
    return item


def _run_export(
    tmp_path: Path,
    items: list[dict],
    folders: list[dict] | None = None,
    *,
    fail_attachment: bool = False,
    attachment_payload: bytes = b"attachment-data",
) -> tuple[Path, int]:
    path = tmp_path / "nested" / "out" / "test.kdbx"
    writer = KdbxWriter()

    def get_attachment(item_id: str, attachment_id: str) -> bytes:
        if fail_attachment:
            message = f"boom: item={item_id} attachment={attachment_id}"
            raise RuntimeError(message)
        return attachment_payload

    writer.set_attachment_source(get_attachment)
    kp = writer.create(path, _MASTER_PASSWORD)
    groups = writer.load_folders(kp, folders or [])
    for item in items:
        writer.add_entry(kp, groups, Item(item))
    writer.save(kp, path)
    return path, writer.verify(path, _MASTER_PASSWORD)


def test_login_entry_full_roundtrip(tmp_path: Path) -> None:
    item = {
        "id": "login-1",
        "type": 1,
        "name": "Example",
        "folderId": "f3",  #  nested folder "Work/Dev" -> group "Dev"
        "login": {
            "username": "user@example.com",
            "password": "hunter2",
            "uris": [
                {"uri": "https://example.com"},
                {"uri": "androidapp://com.example.android"},
            ],
            "totp": "otpauth://totp/Example:user?secret=ABCDEFGHIJ&period=30&digits=6",
        },
        "fields": [
            {"name": "plain", "value": "value", "type": CustomFieldType.TEXT},
            {"name": "secret", "value": "shh", "type": CustomFieldType.HIDDEN},
            {"name": "flag", "value": True, "type": CustomFieldType.BOOLEAN},
        ],
        "tags": ["favorite", "work"],
        "attachments": [{"id": "att-1", "fileName": "note.bin"}],
        "notes": "Some notes",
    }
    path, count = _run_export(
        tmp_path,
        [item],
        folders=[
            {"id": "f1", "name": "Social"},
            {"id": "f2", "name": "Work"},
            {"id": "f3", "name": "Work/Dev"},
        ],
    )
    assert count == 1

    kp = PyKeePass(str(path), password=_MASTER_PASSWORD)
    entry = kp.entries[0]
    assert entry.title == "Example"
    assert entry.username == "user@example.com"
    assert entry.password == "hunter2"
    assert entry.notes == "Some notes"
    assert entry.url == "https://example.com"
    assert entry.group.name == "Dev"  # Work/Dev nested mapping
    assert entry.get_custom_property(TOTP_SEED_PROPERTY) == "ABCDEFGHIJ"
    assert _is_protected(entry, TOTP_SEED_PROPERTY)
    assert entry.get_custom_property(TOTP_SETTINGS_PROPERTY) == "30;6"
    assert entry.get_custom_property("plain") == "value"
    assert entry.get_custom_property("secret") == "shh"
    assert _is_protected(entry, "secret")
    assert entry.get_custom_property("flag") == "true"  # BOOLEAN lowercased
    assert sorted(entry.tags) == ["favorite", "work"]
    assert entry.get_custom_property(BITWARDEN_ID_PROPERTY) == "login-1"
    assert entry.get_custom_property("AndroidApp") == "com.example.android"
    assert len(entry.attachments) == 1
    assert entry.attachments[0].filename == "note.bin"


def test_secure_note_card_identity_entries(tmp_path: Path) -> None:
    secure_note = {"id": "note-1", "type": 2, "name": "Recovery", "notes": "recovery codes"}
    card = {
        "id": "card-1",
        "type": 3,
        "name": "Visa",
        "card": {
            "cardholderName": "Ada",
            "number": "4111111111111111",
            "brand": "Visa",
            "expMonth": "12",
            "expYear": "2028",
            "code": "123",
        },
        "notes": "card notes",
    }
    identity = {
        "id": "id-1",
        "type": 4,
        "name": "Ada Lovelace",
        "identity": {
            "firstName": "Ada",
            "lastName": "Lovelace",
            "ssn": "123-45-6789",
            "passportNumber": "AB123",
            "city": "London",
        },
        "notes": "identity notes",
    }
    path, count = _run_export(tmp_path, [secure_note, card, identity])
    assert count == len([secure_note, card, identity])

    kp = PyKeePass(str(path), password=_MASTER_PASSWORD)
    note = kp.find_entries(title="Recovery", first=True)
    assert note is not None
    assert note.notes == "recovery codes"
    assert note.username is None  # pykeepass: no username -> None
    assert note.get_custom_property(BITWARDEN_ID_PROPERTY) == "note-1"

    card_entry = kp.find_entries(title="Visa", first=True)
    assert card_entry is not None
    assert card_entry.get_custom_property("Cardholder Name") == "Ada"
    assert card_entry.get_custom_property("Number") == "4111111111111111"
    assert _is_protected(card_entry, "Number")
    assert _is_protected(card_entry, "Code")
    assert card_entry.get_custom_property("Brand") == "Visa"
    assert card_entry.notes == "card notes"

    ident = kp.find_entries(title="Ada Lovelace", first=True)
    assert ident is not None
    assert ident.get_custom_property("Identity: firstName") == "Ada"
    assert not _is_protected(ident, "Identity: firstName")
    assert ident.get_custom_property("Identity: ssn") == "123-45-6789"
    assert _is_protected(ident, "Identity: ssn")
    assert ident.get_custom_property("Identity: passportNumber") == "AB123"
    assert _is_protected(ident, "Identity: passportNumber")
    assert ident.get_custom_property("Identity: city") == "London"
    assert ident.notes == "identity notes"


def test_tags_roundtrip_via_raw_dict(tmp_path: Path) -> None:
    """add_entry accepts a raw item dict and wraps it internally."""
    item = {
        "id": "t1",
        "type": 1,
        "name": "Tagged",
        "login": {"username": "u", "password": "p"},
        "tags": ["important"],
    }
    path, count = _run_export(tmp_path, [item])
    assert count == 1
    kp = PyKeePass(str(path), password=_MASTER_PASSWORD)
    entry = kp.entries[0]
    assert entry.tags == ["important"]
    assert entry.get_custom_property(TOTP_SEED_PROPERTY) is None  # no totp -> absent


def test_duplicate_title_is_suffixed(tmp_path: Path) -> None:
    first = _login_item("Vault", "id1")
    second = _login_item("Vault", "id2")
    path, count = _run_export(tmp_path, [first, second])
    assert count == len([first, second])

    kp = PyKeePass(str(path), password=_MASTER_PASSWORD)
    titles = sorted(entry.title for entry in kp.entries)
    assert titles == ["Vault", "Vault - (id2) [1]"]


def test_attachment_failure_rolls_back_entry(tmp_path: Path) -> None:
    item = _login_item("Vault", "id1")
    item["attachments"] = [{"id": "a1", "fileName": "file.txt"}]
    with pytest.raises(RuntimeError, match="boom"):
        _run_export(tmp_path, [item], fail_attachment=True)
    # no half-populated entry survives a failed add
    path = tmp_path / "nested" / "out" / "test.kdbx"
    kp = PyKeePass(str(path), password=_MASTER_PASSWORD)
    assert kp.entries == []


def test_missing_attachment_source_raises(tmp_path: Path) -> None:
    writer = KdbxWriter()  # no attachment source configured
    path = tmp_path / "test.kdbx"
    kp = writer.create(path, _MASTER_PASSWORD)
    groups = writer.load_folders(kp, [])
    item = _login_item("Vault", "id1")
    item["attachments"] = [{"id": "a1", "fileName": "file.txt"}]
    with pytest.raises(RuntimeError, match="attachment source"):
        writer.add_entry(kp, groups, Item(item))
    writer.save(kp, path)
    assert writer.verify(path, _MASTER_PASSWORD) == 0


def test_unknown_folder_falls_back_to_root(tmp_path: Path) -> None:
    item = _login_item("Vault", "id1", folder_id="ghost-folder")
    path, count = _run_export(tmp_path, [item])
    assert count == 1
    kp = PyKeePass(str(path), password=_MASTER_PASSWORD)
    entry = kp.entries[0]
    assert entry.group.is_root_group


def test_verify_wrong_password_raises(tmp_path: Path) -> None:
    writer = KdbxWriter()
    path = tmp_path / "test.kdbx"
    kp = writer.create(path, _MASTER_PASSWORD)
    writer.save(kp, path)
    with pytest.raises(RuntimeError, match="Wrong password"):
        writer.verify(path, "wrong")


def test_item_without_type_raises_and_rolls_back(tmp_path: Path) -> None:
    writer = KdbxWriter()
    path = tmp_path / "test.kdbx"
    kp = writer.create(path, _MASTER_PASSWORD)
    groups = writer.load_folders(kp, [])
    with pytest.raises(RuntimeError):
        writer.add_entry(kp, groups, Item({"id": "bad", "name": "broken"}))
    writer.save(kp, path)
    assert writer.verify(path, _MASTER_PASSWORD) == 0


def test_create_missing_parent_directory(tmp_path: Path) -> None:
    writer = KdbxWriter()
    path = tmp_path / "a" / "b" / "test.kdbx"
    kp = writer.create(path, _MASTER_PASSWORD)
    writer.save(kp, path)
    assert path.is_file()
    assert writer.verify(path, _MASTER_PASSWORD) == 0


def test_sync_attachments_adds_and_removes_stale(tmp_path: Path) -> None:
    writer = KdbxWriter()
    path = tmp_path / "test.kdbx"
    kp = writer.create(path, _MASTER_PASSWORD)
    entry = kp.add_entry(kp.root_group, "Title", "user", "pass")
    old_id = kp.add_binary(b"old")
    entry.add_attachment(old_id, "old.txt")

    item = Item({"id": "x", "attachments": [{"id": "a2", "fileName": "new.txt"}]})
    _sync_attachments(kp, lambda _item_id, _att_id: b"new-data", entry, item)

    assert [attachment.filename for attachment in entry.attachments] == ["new.txt"]


def test_duplicate_title_attempts_capped() -> None:
    """MAX_TITLE_ATTEMPTS guards runaway title-suffix loops."""
    assert MAX_TITLE_ATTEMPTS == _EXPECTED_MAX_TITLE_ATTEMPTS


def test_redacted_item_redacts_secrets() -> None:
    item = {
        "id": "id1",
        "type": 1,
        "name": "Vault",
        "login": {"username": "u", "password": "secret-pw", "totp": "otpauth://..."},
        "notes": "recovery: abc123",
        "fields": [
            {"name": "note", "value": "value", "type": CustomFieldType.TEXT},
            {"name": "secret", "value": "shh", "type": CustomFieldType.HIDDEN},
        ],
        "card": {"number": "4111", "code": "123"},
        "identity": {"ssn": "123-45-6789"},
    }
    redacted = _redacted_item(item)
    assert redacted["login"]["password"] == "***"
    assert "totp" not in redacted["login"]
    assert redacted["notes"] == "***"
    assert redacted["fields"][0]["value"] == "value"
    assert redacted["fields"][1]["value"] == "***"
    assert redacted["card"]["number"] == "***"
    assert redacted["card"]["code"] == "***"
    assert redacted["identity"]["ssn"] == "***"
    # the source item is untouched (deep copy)
    assert item["login"]["password"] == "secret-pw"
