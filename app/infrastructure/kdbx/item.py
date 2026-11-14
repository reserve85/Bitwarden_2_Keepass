"""Typed wrapper around a raw Bitwarden item dict (``bw list items`` payload).

Ported from bitwarden-to-keepass (``src/item.py``) and extended with
tags / card / identity accessors. Unknown field types are treated as HIDDEN so
a fresh Bitwarden field type can never leak in clear text.
"""

from __future__ import annotations

from enum import IntEnum
from urllib.parse import parse_qsl, urlsplit


class ItemType(IntEnum):
    LOGIN = 1
    SECURE_NOTE = 2
    CARD = 3
    IDENTITY = 4
    SSH_KEY = 5


class CustomFieldType(IntEnum):
    TEXT = 0
    HIDDEN = 1
    BOOLEAN = 2
    LINKED = 3  # linked fields are secret-like; treated as protected on export


#: Bitwarden identity field names referenced while building the KeePass entry.
IDENTITY_FIELDS = (
    "title",
    "firstName",
    "middleName",
    "lastName",
    "address1",
    "address2",
    "address3",
    "city",
    "state",
    "postalCode",
    "country",
    "company",
    "email",
    "phone",
    "ssn",
    "username",
    "passportNumber",
    "licenseNumber",
)

#: Card fields that are secrets and must be protected in the KeePass entry.
CARD_FIELDS = (
    "cardholderName",
    "number",
    "brand",
    "expMonth",
    "expYear",
    "code",
)


class Item:
    def __init__(self, item: dict) -> None:
        self.item = item

    def get_id(self) -> str:
        return self.item.get("id", "")

    def get_name(self) -> str:
        return self.item.get("name", "")

    def get_folder_id(self) -> str | None:
        return self.item.get("folderId")

    def _login(self) -> dict:
        """The ``login`` sub-dict, or ``{}`` when absent/malformed."""
        login = self.item.get("login")
        return login if isinstance(login, dict) else {}

    def get_username(self) -> str:
        return self._login().get("username") or ""

    def get_password(self) -> str:
        return self._login().get("password") or ""

    def get_notes(self) -> str:
        return self.item.get("notes") or ""

    def get_uris(self) -> list[str]:
        """Non-empty URIs in vault order (blank/malformed records are dropped)."""
        uris = self._login().get("uris")
        if not isinstance(uris, list):
            return []
        return [uri["uri"] for uri in uris if isinstance(uri, dict) and uri.get("uri")]

    def has_passkeys(self) -> bool:
        """True when the login carries FIDO2 credentials (not exportable)."""
        return bool(self._login().get("fido2Credentials"))

    def get_ssh_key(self) -> dict:
        """Normalized SSH key dict (missing -> empty strings)."""
        key = self.item.get("sshKey")
        if not isinstance(key, dict):
            return {}
        return {
            field: str(key.get(field) or "")
            for field in ("privateKey", "publicKey", "keyFingerprint")
        }

    def get_custom_fields(self) -> list[dict]:
        if not isinstance(self.item.get("fields"), list):
            return []
        fields = []
        for field in self.item["fields"]:
            if not isinstance(field, dict):
                continue
            try:
                field_type = CustomFieldType(field.get("type"))
            except ValueError:
                # Future/unknown field types are treated as hidden so a new
                # "secret-like" type is never exposed in clear text.
                field_type = CustomFieldType.HIDDEN
            fields.append(
                {
                    "name": field.get("name") or "",
                    "value": field.get("value") or "",
                    "type": field_type,
                },
            )
        return fields

    def get_attachments(self) -> list[dict]:
        attachments = self.item.get("attachments")
        if not isinstance(attachments, list):
            return []
        return [attachment for attachment in attachments if isinstance(attachment, dict)]

    def get_tags(self) -> list[str]:
        tags = self.item.get("tags")
        if not isinstance(tags, list):
            return []
        return [str(tag) for tag in tags if tag]

    def get_card(self) -> dict:
        """Normalized card dict with guarded defaults (missing -> empty strings)."""
        card = self.item.get("card")
        if not isinstance(card, dict):
            return {}
        return {field: str(card.get(field) or "") for field in CARD_FIELDS}

    def get_identity(self) -> dict:
        """Normalized identity dict with guarded defaults (missing -> empty strings)."""
        identity = self.item.get("identity")
        if not isinstance(identity, dict):
            return {}
        return {field: str(identity.get(field) or "") for field in IDENTITY_FIELDS}

    def get_totp_raw(self) -> str:
        """The TOTP value exactly as stored in Bitwarden (``""`` when absent)."""
        raw = self._login().get("totp")
        return raw if isinstance(raw, str) else ""

    def get_totp(self) -> tuple[str | None, str | None]:
        """``(seed, "period;digits")`` in the KeeTrayTOTP layout, or ``(None, None)``.

        ``(None, None)`` with a non-empty :meth:`get_totp_raw` means the value
        could not be parsed - the writer then keeps the raw value so nothing
        is lost.
        """
        raw = self.get_totp_raw()
        if not raw:
            return None, None

        if raw.lower().startswith("steam://"):
            # Steam Guard: 5-character codes; KeeTrayTOTP/KeePassXC spell it "S".
            secret = raw[len("steam://") :]
            return (secret, "30;S") if secret else (None, None)

        parsed = urlsplit(raw)
        query = dict(parse_qsl(parsed.query))
        if parsed.scheme:
            # Full otpauth:// URI. A missing secret= query param means we cannot
            # produce a seed - storing the whole URI as the seed would silently
            # break code generation in KeePass, so report "not parseable".
            secret = query.get("secret")
            if not secret:
                return None, None
        else:
            # Legacy/plain raw secret (no otpauth scheme) - use it as-is.
            secret = raw
        period = query.get("period", 30)
        digits = query.get("digits", 6)

        return secret, f"{period};{digits}"

    def as_dict(self) -> dict:
        """Raw payload, used by the KdbxWriter only."""
        return self.item
