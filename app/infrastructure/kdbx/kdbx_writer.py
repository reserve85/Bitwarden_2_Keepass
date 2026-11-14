"""KeePass export engine - pykeepass writer implementing ``KdbxPort``.

Pure pykeepass layer; NEVER logs secrets. Item -> KeePass mapping:

- LOGIN: username/password, uris via ``set_kp_entry_urls``, TOTP seed
  (protected) + settings, notes, custom fields, tags, attachments.
- SECURE_NOTE / CARD / IDENTITY / SSH_KEY: notes + type-specific properties
  (see the ``_add_*`` writers) plus the common custom field/tag handling.
- Unknown (future) item types are still exported as a plain entry and
  reported, never dropped.

Nothing is lost silently: whatever cannot be represented 1:1 (a field name
KeePass reserves, control characters, a passkey, a failed attachment download,
...) is adapted and reported back to the caller as a secret-free *notice*.

Every exported entry is stamped with its Bitwarden id for traceability.

# ported from bitwarden-to-keepass (src/bitwarden_to_keepass.py)
"""

from __future__ import annotations

import contextlib
import re
from pathlib import Path
from typing import TYPE_CHECKING

from pykeepass import PyKeePass, create_database
from pykeepass.entry import reserved_keys
from pykeepass.exceptions import CredentialsError

from app.infrastructure.kdbx.folder import load_folders
from app.infrastructure.kdbx.item import CustomFieldType, Item, ItemType
from app.infrastructure.kdbx.set_kp_entry_urls import set_kp_entry_urls
from app.infrastructure.secure import redact_secrets

if TYPE_CHECKING:
    from collections.abc import Callable

    from pykeepass.entry import Entry
    from pykeepass.group import Group as KPGroup

TOTP_SEED_PROPERTY = "TOTP Seed"
TOTP_SETTINGS_PROPERTY = "TOTP Settings"
#: Holds a Bitwarden TOTP value that could not be parsed into a seed.
TOTP_RAW_PROPERTY = "TOTP (raw)"
# Every exported entry is stamped with its Bitwarden id so that an entry can
# be traced back to its vault item.
BITWARDEN_ID_PROPERTY = "Bitwarden ID"
UNNAMED_FIELD_NAME = "Unnamed field"

#: Card property name -> Bitwarden card dict key (all exported protected).
_CARD_PROPERTY_MAP = {
    "Cardholder Name": "cardholderName",
    "Number": "number",
    "Brand": "brand",
    "Exp Month": "expMonth",
    "Exp Year": "expYear",
    "Code": "code",
}

#: Identity fields that are secrets and must be exported protected.
_IDENTITY_SENSITIVE_FIELDS = {"ssn", "passportNumber", "licenseNumber"}

#: Characters XML 1.0 (and therefore a kdbx file) cannot store.
_XML_UNSAFE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")


def _xml_safe(value: object) -> tuple[object, bool]:
    """Deep copy of *value* without XML-incompatible characters.

    Returns ``(clean, changed)``. pykeepass rejects a whole entry over a single
    control character, so they are stripped up front (and reported).
    """
    if isinstance(value, str):
        clean = _XML_UNSAFE.sub("", value)
        return clean, clean != value
    if isinstance(value, dict):
        changed = False
        result = {}
        for key, item in value.items():
            result[key], item_changed = _xml_safe(item)
            changed = changed or item_changed
        return result, changed
    if isinstance(value, list):
        pairs = [_xml_safe(item) for item in value]
        return [clean for clean, _ in pairs], any(changed for _, changed in pairs)
    return value, False


def _destination_group(
    groups_by_id: dict[str | None, KPGroup],
    folder_id: str | None,
) -> KPGroup:
    """Resolve a folder id to a group, falling back to the root group.

    A missing or stale ``folderId`` (folder deleted after ``list_folders``,
    malformed item, ...) must not silently drop an item.
    """
    return groups_by_id.get(folder_id, groups_by_id[None])


def _new_entry(
    kp: PyKeePass,
    groups_by_id: dict[str | None, KPGroup],
    bw_item: Item,
    *,
    username: str = "",
    password: str = "",
) -> Entry:
    """Create the entry with the item's own title.

    ``force_creation`` keeps duplicate titles as they are in Bitwarden (KeePass
    allows them); every entry stays identifiable through its Bitwarden id.
    """
    return kp.add_entry(
        destination_group=_destination_group(groups_by_id, bw_item.get_folder_id()),
        title=bw_item.get_name(),
        username=username,
        password=password,
        notes=bw_item.get_notes(),
        force_creation=True,
    )


def _set_property_if_value(
    entry: Entry,
    name: str,
    value: object,
    *,
    protect: bool = False,
) -> None:
    """Set a custom property unless the value is empty."""
    if value is None or value == "":
        return
    entry.set_custom_property(name, str(value), protect=protect)


def _free_property_name(entry: Entry, name: str) -> str:
    """A custom property name that neither KeePass nor the entry already uses.

    Bitwarden allows unnamed fields, several fields with the same name and
    names KeePass reserves ("Password", "Notes", ...). Each field must still
    end up as its own property instead of overwriting another one.
    """
    base = name.strip() or UNNAMED_FIELD_NAME
    if base in reserved_keys:
        base = f"{base} (Bitwarden field)"
    used = set(entry.custom_properties)
    candidate = base
    number = 2
    while candidate in used:
        candidate = f"{base} ({number})"
        number += 1
    return candidate


def _add_custom_fields(entry: Entry, bw_item: Item) -> None:
    """Store every Bitwarden custom field as its own custom property."""
    for field in bw_item.get_custom_fields():
        value: object = field["value"]
        if field["type"] == CustomFieldType.BOOLEAN:
            value = str(value).lower()
        entry.set_custom_property(
            _free_property_name(entry, field["name"]),
            str(value),
            protect=field["type"] in {CustomFieldType.HIDDEN, CustomFieldType.LINKED},
        )


def _add_attachments(
    kp: PyKeePass,
    get_attachment: Callable[[str, str], bytes] | None,
    entry: Entry,
    bw_item: Item,
) -> list[str]:
    """Attach every file of the item; a failed download is reported, not fatal."""
    wanted = bw_item.get_attachments()
    if not wanted:
        return []
    if get_attachment is None:
        message = "Export engine has no attachment source configured."
        raise RuntimeError(message)
    notices: list[str] = []
    for attachment in wanted:
        filename = attachment.get("fileName") or "attachment"
        try:
            payload = get_attachment(bw_item.get_id(), attachment["id"])
        except Exception as exc:
            notices.append(
                f"attachment {filename!r} could not be exported: {redact_secrets(str(exc))}",
            )
            continue
        entry.add_attachment(kp.add_binary(payload), filename)
    return notices


def _add_totp(entry: Entry, bw_item: Item) -> list[str]:
    """Store the TOTP secret; an unparseable value is kept raw and reported."""
    raw = bw_item.get_totp_raw()
    if not raw:
        return []
    secret, settings = bw_item.get_totp()
    if secret is None:
        entry.set_custom_property(TOTP_RAW_PROPERTY, raw, protect=True)
        return [f"TOTP value could not be parsed; kept as {TOTP_RAW_PROPERTY!r}"]
    entry.set_custom_property(TOTP_SEED_PROPERTY, secret, protect=True)
    _set_property_if_value(entry, TOTP_SETTINGS_PROPERTY, settings)
    if raw.lower().startswith("otpauth://"):
        # KeePassXC / KeePassDX read the full URI (keeps algorithm + digits).
        entry.otp = raw
    return []


class KdbxWriter:
    """Pykeepass export writer - implements ``KdbxPort``.

    Creates a fresh database, maps the folder tree onto groups, writes every
    Bitwarden item type as an entry and saves + re-opens for verification.
    """

    def __init__(self) -> None:
        self._attachment_source: Callable[[str, str], bytes] | None = None

    def set_attachment_source(self, source: Callable[[str, str], bytes]) -> None:
        """Provide the bw data source used to fetch attachment payloads."""
        self._attachment_source = source

    def create(self, path: Path, master_password: str) -> PyKeePass:
        """Create a fresh database; returns the open handle (RAM only password)."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        return create_database(str(path), password=master_password)

    def load_folders(self, kp: PyKeePass, folders: list[dict]) -> dict[str | None, KPGroup]:
        """Map the Bitwarden folder list onto KeePass groups."""
        return load_folders(kp, folders)

    def add_entry(
        self,
        kp: PyKeePass,
        groups_by_id: dict[str | None, KPGroup],
        item: object,
    ) -> list[str]:
        """Write one Bitwarden item as a fresh KeePass entry.

        Accepts an ``Item`` wrapper or a raw item ``dict``. Returns secret-free
        *notices* describing everything that could not be exported 1:1 (empty
        list = lossless). On failure the partially created entry is removed
        and the exception re-raised so the caller can report the item.
        """
        raw_item = item.as_dict() if isinstance(item, Item) else item
        clean_item, had_control_characters = _xml_safe(raw_item)
        bw_item = Item(clean_item)
        notices: list[str] = []
        if had_control_characters:
            notices.append("control characters that KeePass cannot store were removed")

        entry: Entry | None = None
        try:
            item_type = bw_item.item.get("type")
            if item_type == ItemType.LOGIN:
                entry = _add_login_entry(kp, groups_by_id, bw_item)
            elif item_type == ItemType.SECURE_NOTE:
                entry = _new_entry(kp, groups_by_id, bw_item)
            elif item_type == ItemType.CARD:
                entry = _add_card_entry(kp, groups_by_id, bw_item)
            elif item_type == ItemType.IDENTITY:
                entry = _add_identity_entry(kp, groups_by_id, bw_item)
            elif item_type == ItemType.SSH_KEY:
                entry = _add_ssh_key_entry(kp, groups_by_id, bw_item)
            else:
                entry = _add_login_entry(kp, groups_by_id, bw_item)
                notices.append(
                    f"unknown item type {item_type!r}: exported as a plain entry, "
                    "type-specific data may be missing",
                )

            entry.set_custom_property(BITWARDEN_ID_PROPERTY, bw_item.get_id())
            notices += _add_totp(entry, bw_item)
            if bw_item.has_passkeys():
                notices.append("passkey not exported (KeePass cannot store passkeys)")

            set_kp_entry_urls(entry, bw_item.get_uris())
            _add_custom_fields(entry, bw_item)
            notices += _add_attachments(kp, self._attachment_source, entry, bw_item)
            entry.tags = bw_item.get_tags()
        except Exception:
            if entry is not None:
                # Best-effort: a failed rollback must not mask the original error.
                with contextlib.suppress(Exception):
                    kp.delete_entry(entry)
            raise
        return notices

    def save(self, kp: PyKeePass, path: Path) -> None:
        """Persist the database to *path* (filename set explicitly)."""
        kp.filename = str(path)
        kp.save()

    def verify(self, path: Path, master_password: str) -> int:
        """Re-open the database and return the entry count."""
        try:
            kp = PyKeePass(str(path), password=master_password)
        except CredentialsError as exc:
            raise RuntimeError(
                "Wrong password for the freshly created KeePass database.",
            ) from exc
        return len(kp.entries)


def _add_login_entry(
    kp: PyKeePass,
    groups_by_id: dict[str | None, KPGroup],
    bw_item: Item,
) -> Entry:
    """LOGIN: username/password/notes entry (type dispatch target)."""
    return _new_entry(
        kp,
        groups_by_id,
        bw_item,
        username=bw_item.get_username(),
        password=bw_item.get_password(),
    )


def _add_card_entry(
    kp: PyKeePass,
    groups_by_id: dict[str | None, KPGroup],
    bw_item: Item,
) -> Entry:
    """CARD: card properties are exported as protected custom properties."""
    entry = _new_entry(kp, groups_by_id, bw_item)
    card = bw_item.get_card()
    for prop, key in _CARD_PROPERTY_MAP.items():
        _set_property_if_value(entry, prop, card.get(key), protect=True)
    return entry


def _add_identity_entry(
    kp: PyKeePass,
    groups_by_id: dict[str | None, KPGroup],
    bw_item: Item,
) -> Entry:
    """IDENTITY: referenced identity fields are exported as custom properties.

    Sensitive fields (ssn / passport number / license number) are protected.
    """
    entry = _new_entry(kp, groups_by_id, bw_item)
    for field, value in bw_item.get_identity().items():
        _set_property_if_value(
            entry,
            f"Identity: {field}",
            value,
            protect=field in _IDENTITY_SENSITIVE_FIELDS,
        )
    return entry


def _add_ssh_key_entry(
    kp: PyKeePass,
    groups_by_id: dict[str | None, KPGroup],
    bw_item: Item,
) -> Entry:
    """SSH_KEY: private key protected, public key + fingerprint in clear."""
    entry = _new_entry(kp, groups_by_id, bw_item)
    key = bw_item.get_ssh_key()
    _set_property_if_value(entry, "SSH Private Key", key.get("privateKey"), protect=True)
    _set_property_if_value(entry, "SSH Public Key", key.get("publicKey"))
    _set_property_if_value(entry, "SSH Fingerprint", key.get("keyFingerprint"))
    return entry
