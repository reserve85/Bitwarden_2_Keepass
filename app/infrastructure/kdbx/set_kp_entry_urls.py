"""Map Bitwarden URIs onto KeePass URL attributes/custom properties.

# ported from bitwarden-to-keepass (src/set_kp_entry_urls.py) verbatim
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pykeepass.entry import Entry

ANDROID_APP_PROPERTY = "AndroidApp"
IOS_APP_PROPERTY_PREFIX = "iOS app #"
EXTRA_URL_PROPERTY_PREFIX = "KP2A_URL_"


def _remove_stored_url_properties(entry: Entry) -> None:
    for name in list(entry.custom_properties):
        if name == ANDROID_APP_PROPERTY or name.startswith(
            (
                ANDROID_APP_PROPERTY + "_",
                IOS_APP_PROPERTY_PREFIX,
                EXTRA_URL_PROPERTY_PREFIX,
            ),
        ):
            with contextlib.suppress(AttributeError):
                entry.delete_custom_property(name)


def _remove_url_attribute(entry: Entry) -> None:
    """Remove the ``URL`` string field if present.

    pykeepass 4.x has no supported way to *clear* the URL attribute
    (``entry.url = None`` raises ``TypeError``), so the field element is
    removed directly from the entry XML.
    """
    # pykeepass exposes no public API for this, hence the private members.
    url_element = entry._xpath('String/Key[text()="URL"]/..', first=True)  # noqa: SLF001
    if url_element is not None:
        entry._element.remove(url_element)  # noqa: SLF001


def set_kp_entry_urls(
    entry: Entry,
    urls: list[str],
    *,
    reset: bool = False,
) -> None:
    """Store a list of URLs coming from a Bitwarden entry in different
    attributes and custom properties of a KeePass entry, depending on whether
    it's an identifier for an Android or iOS app or it's a generic URL.

    With ``reset=True`` any previously stored app identifiers, extra URLs and
    the URL attribute are removed first, so URLs deleted in Bitwarden do not
    linger in an updated KeePass entry.
    """
    if reset:
        _remove_url_attribute(entry)
        _remove_stored_url_properties(entry)

    android_apps = ios_apps = extra_urls = 0

    for url in urls:
        match url.partition("://"):
            case ("androidapp", "://", app_id):
                # It's an Android app registered by Bitwarden's mobile app
                # Store multiple apps in AndroidApp, AndroidApp_1, etc.
                #  so that KeePassDX's autofill picks it up
                prop_name = (
                    ANDROID_APP_PROPERTY
                    if android_apps == 0
                    else f"{ANDROID_APP_PROPERTY}_{android_apps}"
                )
                android_apps += 1
                entry.set_custom_property(prop_name, app_id)
            case ("iosapp", "://", app_id):
                # It's an iOS app registered by Bitwarden's mobile app
                # Maybe properly set up autofill for a macOS/iPhone/iPad
                #  KeePass-compatible app like StrongBox or Keepassium
                ios_apps += 1
                entry.set_custom_property(
                    f"{IOS_APP_PROPERTY_PREFIX}{ios_apps}",
                    app_id,
                )
            case _:
                # Assume it's a generic URL.
                # First one goes to the standard URL attribute
                #  and the remaining ones go to URL_1, URL_2 and so on
                if entry.url is None:
                    entry.url = url
                else:
                    extra_urls += 1
                    entry.set_custom_property(
                        f"{EXTRA_URL_PROPERTY_PREFIX}{extra_urls}",
                        url,
                    )
