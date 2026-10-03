# -*- coding: utf-8 -*-
"""Tests for the argument codec section of unicall_ida (runs outside IDA)."""
import pytest

from unicall_ida import ArgumentError, encode_arg_text, parse_arg_text


def test_integers():
    assert parse_arg_text("0x1A2B") == 0x1A2B
    assert parse_arg_text("48") == 48
    assert parse_arg_text("-12") == -12
    assert encode_arg_text(0xDEADBEEF) == "0xdeadbeef"


def test_unknown_fields():
    assert parse_arg_text("") is None
    assert parse_arg_text("   ") is None
    assert parse_arg_text("unknown") is None
    assert parse_arg_text("?") is None


def test_strings():
    assert parse_arg_text('"system-daemon"') == b"system-daemon\x00"
    assert parse_arg_text('"a b\\nc"') == b"a b\nc\x00"
    assert encode_arg_text("value") == '"value"'


def test_hex_blobs():
    # even-length hex without 0x prefix -> byte blob (little-endian payload)
    assert parse_arg_text("9c6e0c3a") == b"\x9c\x6e\x0c\x3a"
    assert parse_arg_text("769C29DD") == b"\x76\x9c\x29\xdd"
    assert encode_arg_text(b"\x76\x9c") == "769c"


def test_round_trip():
    # strings gain a trailing NUL on parse, per the C-string convention
    for value in (0x61F2F0, 35, b"\x9c\x6e\x0c"):
        assert parse_arg_text(encode_arg_text(value)) == value
    assert parse_arg_text(encode_arg_text("session-dbus")) \
        == b"session-dbus\x00"


def test_errors():
    with pytest.raises(ArgumentError):
        parse_arg_text("9c6e0")          # odd-length hex
    with pytest.raises(ArgumentError):
        parse_arg_text("not a number")
    with pytest.raises(ArgumentError):
        parse_arg_text('"unterminated')
    with pytest.raises(TypeError):
        encode_arg_text(1.5)


def test_module_imports_outside_ida():
    """The single-file plugin must import cleanly outside IDA (guarded
    imports, lazily loaded Qt), with the plugin class defined."""
    import unicall_ida
    assert unicall_ida._IDA_OK is False
    assert unicall_ida.PLUGIN_ENTRY is not None
