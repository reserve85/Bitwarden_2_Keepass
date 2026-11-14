"""KdbxWriter tests - real temp kdbx roundtrips (create/load/add/save/verify)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pykeepass import PyKeePass

from app.infrastructure.kdbx.item import CustomFieldType, Item
from app.infrastructure.kdbx.kdbx_writer import (
    BITWARDEN_ID_PROPERTY,
    TOTP_RAW_PROPERTY,
    TOTP_SEED_PROPERTY,
    TOTP_SETTINGS_PROPERTY,
    UNNAMED_FIELD_NAME,
    KdbxWriter,
)

if TYPE_CHECKING:
    from pathlib import Path

_MASTER_PASSWORD = "pw"


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


def _add_one(tmp_path: Path, item: dict, *, fail_attachment: bool = False) -> tuple:
    """Write one item; return ``(re-opened entry, notices)``."""
    path = tmp_path / "one.kdbx"
    writer = KdbxWriter()

    def get_attachment(_item_id: str, _attachment_id: str) -> bytes:
        if fail_attachment:
            message = "boom password=supersecret"
            raise RuntimeError(message)
        return b"attachment-data"

    writer.set_attachment_source(get_attachment)
    kp = writer.create(path, _MASTER_PASSWORD)
    notices = writer.add_entry(kp, writer.load_folders(kp, []), item)
    writer.save(kp, path)
    entries = PyKeePass(str(path), password=_MASTER_PASSWORD).entries
    assert len(entries) == 1
    return entries[0], notices


def test_duplicate_titles_are_kept_as_in_bitwarden(tmp_path: Path) -> None:
    first = _login_item("Vault", "id1")
    second = _login_item("Vault", "id2")
    path, count = _run_export(tmp_path, [first, second])
    assert count == len([first, second])

    kp = PyKeePass(str(path), password=_MASTER_PASSWORD)
    assert [entry.title for entry in kp.entries] == ["Vault", "Vault"]
    ids = sorted(entry.get_custom_property(BITWARDEN_ID_PROPERTY) for entry in kp.entries)
    assert ids == ["id1", "id2"]


def test_lossless_item_reports_no_notices(tmp_path: Path) -> None:
    _entry, notices = _add_one(tmp_path, _login_item("Vault", "id1"))
    assert notices == []


def test_attachment_failure_keeps_entry_and_reports_it(tmp_path: Path) -> None:
    item = _login_item("Vault", "id1")
    item["attachments"] = [{"id": "a1", "fileName": "file.txt"}]

    entry, notices = _add_one(tmp_path, item, fail_attachment=True)

    assert entry.password == "hunter2"  # the entry itself is NOT lost
    assert entry.attachments == []
    assert len(notices) == 1
    assert "file.txt" in notices[0]
    assert "supersecret" not in notices[0]  # the error text is redacted


@pytest.mark.parametrize("name", ["Password", "Notes", "URL", "UserName", "Title", "otp"])
def test_field_named_like_a_reserved_keepass_key_is_kept(tmp_path: Path, name: str) -> None:
    """pykeepass refuses these names - the item must not be dropped over it."""
    item = _login_item("Vault", "id1")
    item["fields"] = [{"name": name, "value": "field-value", "type": CustomFieldType.TEXT}]

    entry, _notices = _add_one(tmp_path, item)

    assert entry.password == "hunter2"
    assert entry.get_custom_property(f"{name} (Bitwarden field)") == "field-value"


def test_duplicate_and_unnamed_fields_do_not_overwrite_each_other(tmp_path: Path) -> None:
    item = _login_item("Vault", "id1")
    item["fields"] = [
        {"name": "pin", "value": "1", "type": CustomFieldType.HIDDEN},
        {"name": "pin", "value": "2", "type": CustomFieldType.HIDDEN},
        {"name": None, "value": "3", "type": CustomFieldType.TEXT},
        {"name": "", "value": "4", "type": CustomFieldType.TEXT},
        {"name": BITWARDEN_ID_PROPERTY, "value": "5", "type": CustomFieldType.TEXT},
    ]

    entry, _notices = _add_one(tmp_path, item)

    assert entry.get_custom_property("pin") == "1"
    assert entry.get_custom_property("pin (2)") == "2"
    assert _is_protected(entry, "pin (2)")
    assert entry.get_custom_property(UNNAMED_FIELD_NAME) == "3"
    assert entry.get_custom_property(f"{UNNAMED_FIELD_NAME} (2)") == "4"
    assert entry.get_custom_property(BITWARDEN_ID_PROPERTY) == "id1"  # not overwritten
    assert entry.get_custom_property(f"{BITWARDEN_ID_PROPERTY} (2)") == "5"


def test_control_characters_are_stripped_and_reported(tmp_path: Path) -> None:
    item = _login_item("Vault", "id1")
    item["notes"] = "line1\x00\x0bline2\nline3"

    entry, notices = _add_one(tmp_path, item)

    assert entry.notes == "line1line2\nline3"
    assert any("control characters" in notice for notice in notices)


def test_ssh_key_item_is_exported(tmp_path: Path) -> None:
    item = {
        "id": "ssh-1",
        "type": 5,
        "name": "Deploy key",
        "notes": "server",
        "sshKey": {
            "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "publicKey": "ssh-ed25519 AAAA",
            "keyFingerprint": "SHA256:abc",
        },
    }

    entry, notices = _add_one(tmp_path, item)

    assert notices == []
    assert entry.get_custom_property("SSH Private Key").startswith("-----BEGIN")
    assert _is_protected(entry, "SSH Private Key")
    assert entry.get_custom_property("SSH Public Key") == "ssh-ed25519 AAAA"
    assert entry.get_custom_property("SSH Fingerprint") == "SHA256:abc"


def test_unknown_item_type_is_exported_and_reported(tmp_path: Path) -> None:
    item = {"id": "x1", "type": 99, "name": "Future", "notes": "keep me"}

    entry, notices = _add_one(tmp_path, item)

    assert entry.title == "Future"
    assert entry.notes == "keep me"
    assert any("unknown item type" in notice for notice in notices)


def test_steam_totp_is_exported(tmp_path: Path) -> None:
    item = _login_item("Steam", "id1")
    item["login"]["totp"] = "steam://ABCDEFGH"

    entry, notices = _add_one(tmp_path, item)

    assert notices == []
    assert entry.get_custom_property(TOTP_SEED_PROPERTY) == "ABCDEFGH"
    assert entry.get_custom_property(TOTP_SETTINGS_PROPERTY) == "30;S"


def test_unparseable_totp_is_kept_raw_and_reported(tmp_path: Path) -> None:
    item = _login_item("Odd", "id1")
    item["login"]["totp"] = "otpauth://totp/NoSecret?digits=6"

    entry, notices = _add_one(tmp_path, item)

    assert entry.get_custom_property(TOTP_RAW_PROPERTY) == "otpauth://totp/NoSecret?digits=6"
    assert _is_protected(entry, TOTP_RAW_PROPERTY)
    assert entry.get_custom_property(TOTP_SEED_PROPERTY) is None
    assert any("TOTP" in notice for notice in notices)


def test_otpauth_uri_is_also_stored_for_keepassxc(tmp_path: Path) -> None:
    item = _login_item("Vault", "id1")
    uri = "otpauth://totp/Example:user?secret=ABCDEFGHIJ&algorithm=SHA256&digits=8"
    item["login"]["totp"] = uri

    entry, _notices = _add_one(tmp_path, item)

    assert entry.otp == uri
    assert entry.get_custom_property(TOTP_SETTINGS_PROPERTY) == "30;8"


def test_passkey_is_reported(tmp_path: Path) -> None:
    item = _login_item("Vault", "id1")
    item["login"]["fido2Credentials"] = [{"credentialId": "abc"}]

    _entry, notices = _add_one(tmp_path, item)

    assert any("passkey" in notice for notice in notices)


def test_blank_uris_are_ignored(tmp_path: Path) -> None:
    item = _login_item("Vault", "id1")
    item["login"]["uris"] = [{"uri": None}, {"uri": ""}, {"uri": "https://a.example"}]

    entry, _notices = _add_one(tmp_path, item)

    assert entry.url == "https://a.example"
    assert entry.get_custom_property("KP2A_URL_1") is None


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


def test_failed_item_is_rolled_back(tmp_path: Path) -> None:
    """An item that cannot be written leaves no half-populated entry behind."""
    writer = KdbxWriter()  # no attachment source -> the attachment step raises
    path = tmp_path / "test.kdbx"
    kp = writer.create(path, _MASTER_PASSWORD)
    groups = writer.load_folders(kp, [])
    item = _login_item("Vault", "id1")
    item["attachments"] = [{"id": "a1", "fileName": "file.txt"}]
    with pytest.raises(RuntimeError):
        writer.add_entry(kp, groups, item)
    assert kp.entries == []


def test_create_missing_parent_directory(tmp_path: Path) -> None:
    writer = KdbxWriter()
    path = tmp_path / "a" / "b" / "test.kdbx"
    kp = writer.create(path, _MASTER_PASSWORD)
    writer.save(kp, path)
    assert path.is_file()
    assert writer.verify(path, _MASTER_PASSWORD) == 0
