"""Item wrapper tests - old-project port + tags/card/identity extensions."""

from __future__ import annotations

from app.infrastructure.kdbx.item import CustomFieldType, Item


def _login_item(**login: object) -> Item:
    return Item({"id": "id1", "login": login})


def test_get_uris_returns_normalized_strings_without_mutation() -> None:
    item = _login_item(uris=[{"uri": "https://example.com"}, {"uri": None}])
    assert item.get_uris() == ["https://example.com", ""]
    # The source item must not be modified by the getter.
    assert item.item["login"]["uris"][1]["uri"] is None


def test_get_uris_without_login_returns_empty() -> None:
    assert Item({"id": "1"}).get_uris() == []


def test_get_uris_tolerates_missing_uri_key() -> None:
    item = _login_item(uris=[{"match": "no uri key"}])
    assert item.get_uris() == [""]


def test_get_custom_fields_does_not_mutate_source() -> None:
    # Custom fields live at the top level of a Bitwarden item.
    item = Item({"id": "id1", "fields": [{"name": None, "value": None, "type": 0}]})
    fields = item.get_custom_fields()
    assert fields == [{"name": "", "value": "", "type": CustomFieldType.TEXT}]
    assert item.item["fields"][0]["name"] is None


def test_get_custom_fields_tolerates_non_list_value() -> None:
    item = Item({"id": "id1", "fields": "malformed"})
    assert item.get_custom_fields() == []


def test_unknown_field_type_is_treated_as_hidden() -> None:
    # A future Bitwarden field type must never be exported in clear text.
    item = Item(
        {"id": "id1", "fields": [{"name": "future", "value": "secret", "type": 9}]},
    )
    fields = item.get_custom_fields()
    assert fields[0]["type"] == CustomFieldType.HIDDEN


def test_linked_field_type_is_mapped() -> None:
    item = Item({"id": "id1", "fields": [{"name": "linked", "value": "v", "type": 3}]})
    assert item.get_custom_fields()[0]["type"] == CustomFieldType.LINKED


def test_custom_field_without_type_is_treated_as_hidden() -> None:
    item = Item({"id": "id1", "fields": [{"name": "x", "value": "y"}]})
    assert item.get_custom_fields()[0]["type"] == CustomFieldType.HIDDEN


def test_get_totp_parses_query_params() -> None:
    totp = "otpauth://totp/Example:user?secret=ABCDEFGHIJ&period=60&digits=8"
    item = _login_item(totp=totp)
    assert item.get_totp() == ("ABCDEFGHIJ", "60;8")


def test_get_totp_falls_back_to_full_uri() -> None:
    totp = "otpauth://totp/Example:user"
    item = _login_item(totp=totp)
    secret, settings = item.get_totp()
    assert secret == totp
    assert settings == "30;6"


def test_get_totp_without_totp_returns_none() -> None:
    assert _login_item().get_totp() == (None, None)


def test_get_username_and_password_fallbacks() -> None:
    assert _login_item().get_username() == ""
    assert _login_item().get_password() == ""
    assert Item({"id": "1"}).get_username() == ""
    assert Item({"id": "1"}).get_password() == ""


def test_get_tags() -> None:
    item = Item({"id": "1", "tags": ["favorite", "", 42]})
    assert item.get_tags() == ["favorite", "42"]


def test_get_tags_non_list_returns_empty() -> None:
    assert Item({"id": "1", "tags": "favorite"}).get_tags() == []
    assert Item({"id": "1"}).get_tags() == []


def test_get_card_normalizes_and_guards_defaults() -> None:
    item = Item(
        {
            "id": "1",
            "card": {
                "cardholderName": "Ada",
                "number": "4111111111111111",
                "brand": "Visa",
            },
        },
    )
    card = item.get_card()
    assert card["cardholderName"] == "Ada"
    assert card["number"] == "4111111111111111"
    assert card["brand"] == "Visa"
    assert card["expMonth"] == ""
    assert card["expYear"] == ""
    assert card["code"] == ""


def test_get_card_missing_returns_empty() -> None:
    assert Item({"id": "1"}).get_card() == {}
    assert Item({"id": "1", "card": "broken"}).get_card() == {}


def test_get_identity_referenced_fields() -> None:
    item = Item(
        {
            "id": "1",
            "identity": {
                "firstName": "Ada",
                "lastName": "Lovelace",
                "ssn": "123-45-6789",
                "city": "London",
                "newInnovation": "left out",  # not a referenced field
            },
        },
    )
    identity = item.get_identity()
    assert identity["firstName"] == "Ada"
    assert identity["lastName"] == "Lovelace"
    assert identity["ssn"] == "123-45-6789"
    assert identity["city"] == "London"
    assert "newInnovation" not in identity
    assert identity["passportNumber"] == ""
    assert identity["postalCode"] == ""


def test_get_identity_missing_returns_empty() -> None:
    assert Item({"id": "1"}).get_identity() == {}
    assert Item({"id": "1", "identity": 7}).get_identity() == {}


def test_id_name_folder_id() -> None:
    item = Item({"id": "abc", "name": "Vault", "folderId": "f1"})
    assert item.get_id() == "abc"
    assert item.get_name() == "Vault"
    assert item.get_folder_id() == "f1"
    assert Item({"id": ""}).get_folder_id() is None
