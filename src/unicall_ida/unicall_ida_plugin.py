#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""unicall_ida_plugin.py -- IDA plugin entry (thin loader).

IDA does not execute a plugin package's __init__.py as a plugin; it scans
plain .py files inside plugin directories instead. This file is the entry
IDA discovers: it ensures the package directory's parent is importable and
delegates everything to the unicall_ida package.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _path in (_PARENT, _HERE):
    if _path not in sys.path:
        sys.path.insert(0, _path)

try:
    from unicall_ida import PLUGIN_ENTRY  # noqa: F401  re-exported for IDA
except Exception as _ex:                  # surface import errors in Output
    import traceback
    print("[unicall_ida] import failed: %r" % (_ex,))
    traceback.print_exc()
    PLUGIN_ENTRY = None
