# -*- coding: utf-8 -*-
"""Tests for unicall_ida.argcodec (pure logic, runs outside IDA)."""
import pytest

from unicall_ida import argcodec


def test_integers():
    assert argcodec.parse("0x1A2B") == 0x1A2B
    assert argcodec.parse("48") == 48
    assert argcodec.parse("-12") == -12
    assert argcodec.encode(0xDEADBEEF) == "0xdeadbeef"


def test_unknown_fields():
    assert argcodec.parse("") is None
    assert argcodec.parse("   ") is None
    assert argcodec.parse("unknown") is None
    assert argcodec.parse("?") is None


def test_strings():
    assert argcodec.parse('"system-daemon"') == b"system-daemon\x00"
    assert argcodec.parse('"a b\\nc"') == b"a b\nc\x00"
    assert argcodec.encode("value") == '"value"'


def test_hex_blobs():
    # even-length hex without 0x prefix -> byte blob (little-endian payload)
    assert argcodec.parse("9c6e0c3a") == b"\x9c\x6e\x0c\x3a"
    assert argcodec.parse("769C29DD") == b"\x76\x9c\x29\xdd"
    assert argcodec.encode(b"\x76\x9c") == "769c"


def test_round_trip():
    # strings gain a trailing NUL on parse, per the C-string convention
    for value in (0x61F2F0, 35, b"\x9c\x6e\x0c"):
        assert argcodec.parse(argcodec.encode(value)) == value
    assert argcodec.parse(argcodec.encode("session-dbus")) \
        == b"session-dbus\x00"


def test_errors():
    with pytest.raises(argcodec.ArgumentError):
        argcodec.parse("9c6e0")          # odd-length hex
    with pytest.raises(argcodec.ArgumentError):
        argcodec.parse("not a number")
    with pytest.raises(argcodec.ArgumentError):
        argcodec.parse('"unterminated')
    with pytest.raises(TypeError):
        argcodec.encode(1.5)
