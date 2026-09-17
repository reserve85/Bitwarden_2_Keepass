"""KeePass export engine - pykeepass writer implementing ``KdbxPort``.

Pure pykeepass layer; NEVER logs secrets. Item -> KeePass mapping:

- LOGIN: username/password, uris via ``set_kp_entry_urls``, TOTP seed
  (protected) + settings, notes, custom fields, tags, attachments.
- SECURE_NOTE / CARD / IDENTITY: notes + protected card/identity properties
  (see the ``_add_*`` writers) plus the common custom field/tag handling.

Every exported entry is stamped with its Bitwarden id for traceability.

# ported from bitwarden-to-keepass (src/bitwarden_to_keepass.py)
"""

from __future__ import annotations

import contextlib
import copy
from pathlib import Path
from typing import TYPE_CHECKING

from pykeepass import PyKeePass, create_database
from pykeepass.exceptions import CredentialsError

from app.infrastructure.kdbx.folder import load_folders
from app.infrastructure.kdbx.item import CustomFieldType, Item, ItemType
from app.infrastructure.kdbx.set_kp_entry_urls import (
    ANDROID_APP_PROPERTY,
    EXTRA_URL_PROPERTY_PREFIX,
    IOS_APP_PROPERTY_PREFIX,
    set_kp_entry_urls,
)
from app.infrastructure.secure import REDACTED, _is_sensitive_field_name

if TYPE_CHECKING:
    from collections.abc import Callable

    from lxml.etree import _Element
    from pykeepass.entry import Entry
    from pykeepass.group import Group as KPGroup

TOTP_SEED_PROPERTY = "TOTP Seed"
TOTP_SETTINGS_PROPERTY = "TOTP Settings"
# Every exported entry is stamped with its Bitwarden id so that repeated
# exports can be traced back and future in-place updates are possible.
BITWARDEN_ID_PROPERTY = "Bitwarden ID"
MAX_TITLE_ATTEMPTS = 5

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


def _is_duplicate_title_error(exception: Exception) -> bool:
    message = str(exception)
    # pykeepass raises 'An entry "<title>" already exists in "<group>"' when a
    # group already contains an entry with the same title (and username). The
    # prefix guard keeps unrelated "already exists" errors (file collisions,
    # ...) from being mistaken for a title collision.
    return message.startswith('An entry "') and "already exists" in message


def _destination_group(
    groups_by_id: dict[str | None, KPGroup],
    folder_id: str | None,
) -> KPGroup:
    """Resolve a folder id to a group, falling back to the root group.

    A missing or stale ``folderId`` (folder deleted after ``list_folders``,
    malformed item, ...) must not silently drop an item.
    """
    return groups_by_id.get(folder_id, groups_by_id[None])


def _add_entry_with_title_fallback(  # noqa: PLR0913 - one logical entry spec split across args
    kp: PyKeePass,
    groups_by_id: dict[str | None, KPGroup],
    bw_item: Item,
    *,
    username: str,
    password: str,
    notes: str,
) -> Entry:
    """Add the entry, incrementing the title suffix on collisions."""
    destination_group = _destination_group(groups_by_id, bw_item.get_folder_id())
    base_title = bw_item.get_name()
    entry_title = base_title
    for attempt in range(1, MAX_TITLE_ATTEMPTS + 1):
        try:
            return kp.add_entry(
                destination_group=destination_group,
                title=entry_title,
                username=username,
                password=password,
                notes=notes,
            )
        except Exception as exc:
            if not _is_duplicate_title_error(exc):
                raise
            if attempt == MAX_TITLE_ATTEMPTS:
                message = f"Could not add entry titled {base_title!r}: title collisions exhausted."
                raise RuntimeError(message) from exc
            entry_title = f"{base_title} - ({bw_item.get_id()}) [{attempt}]"
    raise AssertionError("Unreachable: the loop above always returns or raises.")


def _set_custom_property_or_remove(
    entry: Entry,
    name: str,
    value: object,
    *,
    protect: bool = False,
) -> None:
    """Set a custom property, or remove it when the value is empty."""
    if value is None or value == "":
        with contextlib.suppress(AttributeError):
            entry.delete_custom_property(name)
        return
    entry.set_custom_property(name, value, protect=protect)


URL_PROPERTY_NAME_PREFIXES = (
    ANDROID_APP_PROPERTY + "_",
    IOS_APP_PROPERTY_PREFIX,
    EXTRA_URL_PROPERTY_PREFIX,
)


def _is_url_property_name(name: str) -> bool:
    """True for the custom properties set_kp_entry_urls manages."""
    return name == ANDROID_APP_PROPERTY or name.startswith(URL_PROPERTY_NAME_PREFIXES)


def _snapshot_entry(entry: Entry) -> _Element:
    """Capture the entry's XML so a failed update can be undone."""
    return copy.deepcopy(entry._element)  # noqa: SLF001


def _restore_entry(entry: Entry, snapshot: _Element, group: KPGroup) -> None:
    """Undo an in-place update by restoring the captured entry element."""
    parent = entry._element.getparent()  # noqa: SLF001
    if parent is not None:
        parent.remove(entry._element)  # noqa: SLF001
    entry._element = snapshot  # noqa: SLF001
    group.append(entry)


def _rollback_entry(
    kp: PyKeePass,
    entry: Entry | None,
    snapshot: _Element | None,
    group: KPGroup | None,
) -> None:
    """Roll back a partially populated entry: delete a fresh entry or restore
    an updated one.

    The update path always holds a snapshot of the pre-update entry, the create
    path never does - so the snapshot's presence selects the restore path.
    """
    if snapshot is not None and entry is not None and group is not None:
        # Best-effort rollback: a failed restore must not mask the original error.
        with contextlib.suppress(Exception):
            _restore_entry(entry, snapshot, group)
    elif entry is not None:
        with contextlib.suppress(Exception):
            kp.delete_entry(entry)


def _sync_custom_fields(
    entry: Entry,
    bw_item: Item,
    *,
    remove_stale: bool,
) -> None:
    """Mirror the item's custom fields onto *entry*.

    With *remove_stale* (the update path) previously exported fields that no
    longer exist in Bitwarden are deleted, so a revoked or rotated secret is
    not carried over on every re-export.
    """
    if remove_stale:
        retained = {
            BITWARDEN_ID_PROPERTY,
            TOTP_SEED_PROPERTY,
            TOTP_SETTINGS_PROPERTY,
        } | {field["name"] for field in bw_item.get_custom_fields()}
        for name in list(entry.custom_properties):
            if name in retained or _is_url_property_name(name):
                continue
            with contextlib.suppress(AttributeError):
                entry.delete_custom_property(name)
    for field in bw_item.get_custom_fields():
        value: object = field["value"]
        if field["type"] == CustomFieldType.BOOLEAN:
            value = str(value).lower()
        entry.set_custom_property(
            field["name"],
            value,
            protect=field["type"] in {CustomFieldType.HIDDEN, CustomFieldType.LINKED},
        )


def _sync_attachments(
    kp: PyKeePass,
    get_attachment: Callable[[str, str], bytes] | None,
    entry: Entry,
    bw_item: Item,
) -> None:
    """Mirror the item's attachments onto *entry*.

    Attachments removed (or renamed) in Bitwarden are deleted from the entry
    and attachments already present from a previous export are not re-added,
    so repeated exports neither keep stale copies nor accumulate duplicates.
    """
    wanted = bw_item.get_attachments()
    if not wanted:
        for attachment in list(entry.attachments):
            entry.delete_attachment(attachment)
        return
    if get_attachment is None:
        message = "Export engine has no attachment source configured."
        raise RuntimeError(message)
    wanted_names = {attachment.get("fileName", "") for attachment in wanted}
    for attachment in entry.attachments:
        if attachment.filename not in wanted_names:
            entry.delete_attachment(attachment)
    present_names = {attachment.filename for attachment in entry.attachments}
    for attachment in wanted:
        if attachment.get("fileName", "") in present_names:
            continue
        attachment_raw = get_attachment(bw_item.get_id(), attachment["id"])
        attachment_id = kp.add_binary(attachment_raw)
        entry.add_attachment(attachment_id, attachment["fileName"])


def _sync_tags(entry: Entry, tags: list[str]) -> None:
    """Mirror the Bitwarden tags onto *entry* (KeePass ``tags`` attribute)."""
    entry.tags = list(tags)


def _redacted_item(item: dict) -> dict:
    """Return a deep copy of *item* with secrets redacted for logging."""
    redacted = copy.deepcopy(item)
    login = redacted.get("login")
    if isinstance(login, dict):
        if "password" in login:
            login["password"] = REDACTED
        login.pop("totp", None)
    # Notes are free-form and frequently hold secrets (recovery codes, API
    # tokens, security answers, ...).
    if isinstance(redacted.get("notes"), str):
        redacted["notes"] = REDACTED
    for field in redacted.get("fields", []):
        name = field.get("name") or ""
        # Redact everything that is not a plain TEXT field: hidden, linked and
        # unknown/forward field types are treated as secret-like (see
        # Item.get_custom_fields), so a fresh Bitwarden field type cannot
        # leak through the failure log.
        if field.get("type") != CustomFieldType.TEXT or _is_sensitive_field_name(
            name,
        ):
            field["value"] = REDACTED
    # Cards and identities carry secret fields too.
    if isinstance(redacted.get("card"), dict):
        for key in ("number", "code"):
            if key in redacted["card"]:
                redacted["card"][key] = REDACTED
    if isinstance(redacted.get("identity"), dict):
        for key in ("ssn", "passportNumber", "licenseNumber"):
            if key in redacted["identity"]:
                redacted["identity"][key] = REDACTED
    return redacted


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
    ) -> None:
        """Dispatch one Bitwarden item onto a fresh KeePass entry.

        Accepts an ``Item`` wrapper or a raw item ``dict``. On failure the
        partially created entry is rolled back and the exception re-raised so
        the caller can log the redacted item and continue.
        """
        bw_item = item if isinstance(item, Item) else Item(item)
        entry: Entry | None = None
        try:
            item_type = bw_item.item.get("type")
            if item_type == ItemType.LOGIN:
                entry = _add_login_entry(kp, groups_by_id, bw_item)
            elif item_type == ItemType.SECURE_NOTE:
                entry = _add_secure_note_entry(kp, groups_by_id, bw_item)
            elif item_type == ItemType.CARD:
                entry = _add_card_entry(kp, groups_by_id, bw_item)
            elif item_type == ItemType.IDENTITY:
                entry = _add_identity_entry(kp, groups_by_id, bw_item)
            else:
                message = f"Item {bw_item.get_name()!r} has unsupported type {item_type!r}."
                raise RuntimeError(message) from None  # noqa: TRY301 - the except rolls back then re-raises

            entry.set_custom_property(BITWARDEN_ID_PROPERTY, bw_item.get_id())

            totp_secret, totp_settings = bw_item.get_totp()
            _set_custom_property_or_remove(
                entry,
                TOTP_SEED_PROPERTY,
                totp_secret,
                protect=True,
            )
            _set_custom_property_or_remove(
                entry,
                TOTP_SETTINGS_PROPERTY,
                totp_settings,
            )

            set_kp_entry_urls(entry, bw_item.get_uris(), reset=True)
            _sync_custom_fields(entry, bw_item, remove_stale=False)
            _sync_attachments(kp, self._attachment_source, entry, bw_item)
            _sync_tags(entry, bw_item.get_tags())
        except Exception:
            _rollback_entry(kp, entry, None, None)
            raise

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
    return _add_entry_with_title_fallback(
        kp,
        groups_by_id,
        bw_item,
        username=bw_item.get_username(),
        password=bw_item.get_password(),
        notes=bw_item.get_notes(),
    )


def _add_secure_note_entry(
    kp: PyKeePass,
    groups_by_id: dict[str | None, KPGroup],
    bw_item: Item,
) -> Entry:
    """SECURE_NOTE: notes-only entry (type dispatch target)."""
    return _add_entry_with_title_fallback(
        kp,
        groups_by_id,
        bw_item,
        username="",
        password="",
        notes=bw_item.get_notes(),
    )


def _add_card_entry(
    kp: PyKeePass,
    groups_by_id: dict[str | None, KPGroup],
    bw_item: Item,
) -> Entry:
    """CARD: card properties are exported as protected custom properties."""
    entry = _add_entry_with_title_fallback(
        kp,
        groups_by_id,
        bw_item,
        username="",
        password="",
        notes=bw_item.get_notes(),
    )
    card = bw_item.get_card()
    for prop, key in _CARD_PROPERTY_MAP.items():
        _set_custom_property_or_remove(entry, prop, card.get(key) or "", protect=True)
    return entry


def _add_identity_entry(
    kp: PyKeePass,
    groups_by_id: dict[str | None, KPGroup],
    bw_item: Item,
) -> Entry:
    """IDENTITY: referenced identity fields are exported as custom properties.

    Sensitive fields (ssn / passport number / license number) are protected.
    """
    entry = _add_entry_with_title_fallback(
        kp,
        groups_by_id,
        bw_item,
        username="",
        password="",
        notes=bw_item.get_notes(),
    )
    for field, value in bw_item.get_identity().items():
        _set_custom_property_or_remove(
            entry,
            f"Identity: {field}",
            value or "",
            protect=field in _IDENTITY_SENSITIVE_FIELDS,
        )
    return entry
