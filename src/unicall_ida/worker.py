#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unicall_ida.worker -- run the emulation off IDA's main thread.

Emulation may loop or take a while; it must never block the UI thread.
A QThread emits Qt signals whose delivery is automatically queued back to
the dialog living on the main thread. Emulator instances are cached per
(sample path, base) so repeated calls reuse the mapped image.
"""
import traceback

try:
    from PySide6 import QtCore
except ImportError:                                    # IDA 7.x
    from PyQt5 import QtCore

import unicall

_EMU_CACHE = {}


def get_emu(sample_path, base):
    """Return a cached Emu for the sample, creating it on first use."""
    key = (sample_path, base)
    if key not in _EMU_CACHE:
        kwargs = {}
        if base:
            kwargs["base"] = base
        _EMU_CACHE[key] = unicall.Emu(sample_path, **kwargs)
    return _EMU_CACHE[key]


class EmulateThread(QtCore.QThread):
    """Executes one unicall call() invocation in a worker thread."""

    done = QtCore.Signal(object)      # str or int result
    fail = QtCore.Signal(str)         # error text

    def __init__(self, sample_path, base, call_ea, args, convention, ret_mode,
                 parent=None):
        super().__init__(parent)
        self.sample_path = sample_path
        self.base = base
        self.call_ea = call_ea
        self.args = args
        self.convention = convention
        self.ret_mode = ret_mode

    def run(self):
        try:
            emu = get_emu(self.sample_path, self.base)
            kwargs = {"ret": self.ret_mode}
            if self.convention:
                kwargs["convention"] = self.convention
            result = emu.call(self.call_ea, self.args, **kwargs)
            self.done.emit(result)
        except Exception as ex:
            text = f"{type(ex).__name__}: {ex}\n\n{traceback.format_exc()}"
            if isinstance(ex, ImportError):
                text += ("\n\nHint: the unicall package must be installed "
                         "into the Python interpreter used by IDA, e.g.\n"
                         "    <ida-python> -m pip install -e <path-to-unicall>")
            self.fail.emit(text)
