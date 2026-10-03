#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unicall_ida.argcodec -- argument text encoding/decoding (IDA-free, testable).

The plugin dialog shows every call argument as an editable text field. This
module defines the text format and converts between text and the values
accepted by unicall's call() (int or bytes).

Text format (per field):
    (empty) or "unknown"   -> unknown, must be filled in before running
    0x1A2B or -12          -> integer (value, or an address inside the image)
    "text"                 -> C string, UTF-8 encoded with a trailing NUL
    9c6e0c3a...            -> raw byte blob given as even-length hex

Integers that consist only of hex digits must use the 0x prefix to avoid
ambiguity with byte blobs.
"""
import re

_HEX_BLOB_RE = re.compile(r"^[0-9a-fA-F]+$")
_INT_RE = re.compile(r"^-?(0[xX][0-9a-fA-F]+|\d+)$")

UNKNOWN_TEXTS = ("", "unknown", "?")


class ArgumentError(ValueError):
    """Raised when an argument field cannot be parsed."""


def parse(text):
    """Parse one argument field. Returns int, bytes, or None (unknown).
    Raises ArgumentError for malformed input."""
    t = (text or "").strip()
    if t.lower() in UNKNOWN_TEXTS:
        return None
    if _INT_RE.match(t):
        return int(t, 0)
    if len(t) >= 2 and t.startswith(("\"", "'")) and t.endswith(t[0]) \
            and len(t) >= 2:
        # quoted C string: encode UTF-8, add NUL terminator
        body = t[1:-1].encode("utf-8").decode("unicode_escape")
        return body.encode("utf-8") + b"\x00"
    if _HEX_BLOB_RE.match(t) and len(t) % 2 == 0:
        return bytes.fromhex(t)
    raise ArgumentError(f"cannot parse argument field: {t!r} "
                        f"(expected 0x.., integer, \"string\", or hex blob)")


def encode(value):
    """Encode a value (int / bytes / str) into its dialog text form."""
    if value is None:
        return ""
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, str):
        return '"' + value + '"'
    raise TypeError(f"cannot encode value of type {type(value)!r}")
