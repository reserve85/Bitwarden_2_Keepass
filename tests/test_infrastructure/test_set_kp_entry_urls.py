"""URL mapping tests - old-project port."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pykeepass import create_database

from app.infrastructure.kdbx.set_kp_entry_urls import (
    ANDROID_APP_PROPERTY,
    EXTRA_URL_PROPERTY_PREFIX,
    IOS_APP_PROPERTY_PREFIX,
    set_kp_entry_urls,
)

if TYPE_CHECKING:
    from pathlib import Path

    from pykeepass import PyKeePass
    from pykeepass.entry import Entry


def _new_entry(tmp_path: Path) -> tuple[PyKeePass, Entry]:
    kp = create_database(str(tmp_path / "test.kdbx"), password="test")
    return kp, kp.add_entry(kp.root_group, "title", "user", "pass")


def test_first_url_goes_to_url_attribute_and_rest_to_extra_props(tmp_path: Path) -> None:
    kp, entry = _new_entry(tmp_path)
    set_kp_entry_urls(entry, ["https://example.com", "https://second.example.com"])
    assert entry.url == "https://example.com"
    assert entry.get_custom_property(f"{EXTRA_URL_PROPERTY_PREFIX}1") == (
        "https://second.example.com"
    )
    kp.save()


def test_android_and_ios_app_identifiers_are_stored(tmp_path: Path) -> None:
    kp, entry = _new_entry(tmp_path)
    set_kp_entry_urls(
        entry,
        ["androidapp://com.example.android", "iosapp://com.example.ios"],
    )
    assert entry.url is None
    assert entry.get_custom_property(ANDROID_APP_PROPERTY) == "com.example.android"
    assert entry.get_custom_property(f"{IOS_APP_PROPERTY_PREFIX}1") == ("com.example.ios")
    kp.save()


def test_multiple_android_apps_get_numbered_properties(tmp_path: Path) -> None:
    kp, entry = _new_entry(tmp_path)
    set_kp_entry_urls(
        entry,
        ["androidapp://com.a", "androidapp://com.b"],
    )
    assert entry.get_custom_property(ANDROID_APP_PROPERTY) == "com.a"
    assert entry.get_custom_property(f"{ANDROID_APP_PROPERTY}_1") == "com.b"
    kp.save()


def test_reset_clears_previously_stored_urls(tmp_path: Path) -> None:
    kp, entry = _new_entry(tmp_path)
    set_kp_entry_urls(entry, ["https://old.example.com", "https://second.example.com"])
    set_kp_entry_urls(entry, ["https://new.example.com"], reset=True)

    assert entry.url == "https://new.example.com"
    assert entry.get_custom_property(f"{EXTRA_URL_PROPERTY_PREFIX}1") is None
    kp.save()
