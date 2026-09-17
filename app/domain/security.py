"""Pure (stdlib-only) secret-handling helpers.

RAM hygiene guarantees are scoped honestly: Python ``str``/``bytes`` are
immutable and cannot be physically wiped - the enforceable promise is "no
extra copies, no persistence, no logging". These helpers minimise copies, keep
secrets in one mutable ``bytearray`` and best-effort wipe it in caller
``finally`` paths. All functions are guaranteed not to raise on their
documented inputs.

These helpers live in the domain layer (which depends on nothing) so the
application layer can redact log/error payloads without importing
infrastructure. :mod:`app.infrastructure.secure` re-exports them for backward
compatibility with the reference project's import paths.
"""

from __future__ import annotations

import contextlib
import re

REDACTED = "***"

#: Field names whose values are treated as secrets when a message is redacted.
_SENSITIVE_FIELD_NAME = re.compile(
    r"(?i)(password|passphrase|pass|pw|secret|token|t?otp|seed|pin|"
    r"api[ _-]?key|private[ _-]?key|client[ _-]?(id|secret))",
)

#: ``name=value`` / ``name: value`` / ``"name": "value"`` where the name is sensitive.
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?P<field>[\"']?(?:password|passphrase|pass|pw|secret|token|t?otp|seed|pin|"
    r"api[ _-]?key|private[ _-]?key|client[ _-]?(?:id|secret))[\"']?"
    r"\s*[:=]\s*)"
    r"(?P<value>[\"'][^\"']*[\"']|[^,;|\s&\"']+)",
    re.IGNORECASE,
)

#: Long base64-ish tokens (BW session keys, raw ``bw login`` stdout).
_LONG_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])",
)


def _is_sensitive_field_name(name: str) -> bool:
    return bool(_SENSITIVE_FIELD_NAME.search(name))


def redact_secrets(text: str) -> str:
    """Mask secret-like content in *text* (error messages, log payloads).

    Replaces values of sensitive field names AND long base64 tokens (BW session
    keys, raw ``bw login`` stdout). Over-redaction is the safe direction.
    """
    if not text:
        return text
    text = _LONG_TOKEN.sub(REDACTED, text)
    return _SENSITIVE_ASSIGNMENT.sub(lambda m: f"{m.group('field')}{REDACTED}", text)


def wipe(buffer: bytearray) -> None:
    """Overwrite every byte with 0x00 and clear the buffer - guaranteed no raise."""
    try:
        for index in range(len(buffer)):
            buffer[index] = 0
    finally:
        with contextlib.suppress(Exception):
            del buffer[:]


def secure_password_from_str(value: str) -> bytearray:
    """UTF-8 encode *value* into ONE mutable buffer - no immutable ``bytes``.

    ``bytes``/``str`` cannot be wiped, so the returned ``bytearray`` is the only
    secret copy the caller should keep; it must be wiped in a finally path.
    """
    return bytearray(value.encode("utf-8"))


def drop_qt_str(field: object | None) -> None:
    """Best-effort clear of a QLineEdit widget copy of a secret string.

    Duck-typed: works with any object exposing ``clear()`` (QLineEdit). Never
    raises. Documented best-effort in SECURITY.md.
    """
    if field is None:
        return
    clear = getattr(field, "clear", None)
    if callable(clear):
        with contextlib.suppress(Exception):
            clear()
