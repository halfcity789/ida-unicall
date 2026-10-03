#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unicall_ida -- IDA plugin (single file): emulate a pseudocode call in place
with the unicall package.

Two ways to use the plugin:

  Approach A (pseudocode integration): right-click a call in the Hex-Rays
  pseudocode view and choose "unicall: emulate this call". Arguments are
  recovered from the ctree (numeric literals, image addresses, string
  literals, stack arrays filled with immediates) and pre-filled into the
  parameter dialog; anything unrecognized stays blank.

  Approach B (manual): Edit > Plugins > unicall (or Ctrl-Alt-U) opens the
  same dialog with blank fields and the screen address as the call target.

In both cases the dialog is always shown; emulation only starts after an
explicit "Run".

Installation: copy this single file into the IDA plugins directory. The
`unicall` package must be installed into the Python interpreter IDA uses.

IDA imports are guarded so that the argument-codec helpers remain testable
outside IDA; Qt bindings are imported lazily when the dialog opens.
"""
import os
import re
import traceback

# ---------------------------------------------------------------------------
# IDA environment (guarded: the argument codec below stays importable and
# testable outside IDA)
# ---------------------------------------------------------------------------
_IDA_OK = True
try:
    import ida_bytes
    import ida_idaapi
    import ida_kernwin
    import ida_nalt

    try:
        import ida_hexrays
        HAS_HEXRAYS = ida_hexrays.init_hexrays_plugin()
    except ImportError:                                # hexrays not present
        HAS_HEXRAYS = False
except ImportError:                                    # outside IDA
    _IDA_OK = False
    HAS_HEXRAYS = False

if _IDA_OK:
    from ida_hexrays import (
        cot_add, cot_asg, cot_call, cot_cast, cot_helper, cot_idx, cot_num,
        cot_obj, cot_ptr, cot_ref, cot_str, cot_var,
    )
    _BADADDR = ida_idaapi.BADADDR
else:
    _BADADDR = 0xFFFFFFFFFFFFFFFF

ACTION_ID = "unicall:emulate_call"
MENU_PATH = "unicall/"
HOTKEY_EMULATE = "Ctrl-Alt-E"
HOTKEY_MANUAL = "Ctrl-Alt-U"

_current_vu = [None]
_ACTIVE_DIALOGS = []          # keep dialog references alive (prevent GC)


# ===========================================================================
# argument codec: dialog text <-> unicall call() values (pure logic)
# ===========================================================================
_HEX_BLOB_RE = re.compile(r"^[0-9a-fA-F]+$")
_INT_RE = re.compile(r"^-?(0[xX][0-9a-fA-F]+|\d+)$")

UNKNOWN_TEXTS = ("", "unknown", "?")


class ArgumentError(ValueError):
    """Raised when an argument field cannot be parsed."""


def parse_arg_text(text):
    """Parse one argument field. Returns int, bytes, or None (unknown)."""
    t = (text or "").strip()
    if t.lower() in UNKNOWN_TEXTS:
        return None
    if _INT_RE.match(t):
        return int(t, 0)
    if len(t) >= 2 and t[0] in "\"'" and t.endswith(t[0]):
        body = t[1:-1].encode("utf-8").decode("unicode_escape")
        return body.encode("utf-8") + b"\x00"
    if _HEX_BLOB_RE.match(t) and len(t) % 2 == 0:
        return bytes.fromhex(t)
    raise ArgumentError(f"cannot parse argument field: {t!r} "
                        f"(expected 0x.., integer, \"string\", or hex blob)")


def encode_arg_text(value):
    """Encode a value (int / bytes / str) into its dialog text form."""
    if value is None:
        return ""
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, str):
        return '"' + value + '"'
    raise TypeError(f"cannot encode value of type {type(value)!r}")


# ===========================================================================
# ctree-based call argument extraction (IDA only)
# ===========================================================================
class ArgInfo:
    """One extracted call argument."""

    def __init__(self, kind, value, note=""):
        self.kind = kind        # literal / address / string / stack-bytes / unknown
        self.value = value      # int | bytes | None
        self.note = note


class CallInfo:
    """The call expression selected in the pseudocode view."""

    def __init__(self, ea, callee_ea, args):
        self.ea = ea
        self.callee_ea = callee_ea
        self.args = args


def _unwrap_cast(e):
    while e.op == cot_cast:
        e = e.x
    return e


def _string_at(ea):
    try:
        import ida_nalt
        raw = ida_nalt.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
        if raw:
            return bytes(raw) + b"\x00"
    except Exception:
        pass
    return None


def _elem_size(lvar):
    """Element size in bytes for an indexed local variable (default 8)."""
    try:
        ti = lvar.type()
        if ti.is_array():
            s = ti.get_array_element().get_size()
            if s and 0 < s <= 64:
                return s
        s = ti.get_size()
        if s and 0 < s <= 64:
            return s
    except Exception:
        pass
    return 8


def _collect(cfunc):
    """Walk the ctree once; return (call exprs, assignment pairs, copy fills).

    calls:       list of cot_call cexprs
    assignments: list of (ea, lhs, rhs) for `x = <numeric>` statements
    copy_fills:  list of (ea, dst_var_idx, dst_off, bytes) for helper copies
                 of the form qmemcpy(&var, "literal", n) / memset(&var, c, n)
                 -- Hex-Rays emits these for byte arrays initialized from
                 string literals
    """
    calls, assignments, copy_fills = [], [], []

    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            try:
                if e.op == cot_call:
                    calls.append(e)
                    fill = _parse_copy_fill(e)
                    if fill is not None:
                        copy_fills.append((e.ea,) + fill)
                elif e.op == cot_asg:
                    assignments.append((e.ea, e.x, e.y))
            except Exception:
                pass
            return 0

    try:
        V().apply_to(cfunc.body, None)
    except Exception:
        pass
    return calls, assignments, copy_fills


def _string_literal_bytes(e):
    """Best-effort byte extraction from a cot_str expression. The attribute
    holding the text differs across IDA versions, so try the known names
    and fall back to parsing the rendered form."""
    for attr in ("string", "str"):
        try:
            v = getattr(e, attr)
            if v is None:
                continue
            if isinstance(v, str):
                return v.encode("utf-8", errors="replace")
            if isinstance(v, (bytes, bytearray)):
                return bytes(v)
        except Exception:
            pass
    try:
        rendered = str(e)
        if len(rendered) >= 2 and rendered[0] == '"' and rendered[-1] == '"':
            return rendered[1:-1].encode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def _parse_copy_fill(call_expr):
    """Return (dst_var_idx, data) for a qmemcpy/memset-style helper call
    filling a stack variable, else None."""
    try:
        callee = _unwrap_cast(call_expr.x)
        name = ""
        if callee.op == cot_helper:
            name = str(getattr(callee, "helper", "") or "").lower()
        elif callee.op == cot_obj:
            import ida_name
            name = (ida_name.get_name(callee.obj_ea) or "").lower()
        if not name:                       # last resort: rendered form
            try:
                name = str(callee).lower()
            except Exception:
                return None
        if not any(k in name for k in ("qmemcpy", "memcpy", "memset")):
            return None
        args = list(call_expr.a)
        if len(args) < 2:
            return None

        # destination: accept var, &var, &var[0] and pointer-decay forms
        dst = _unwrap_cast(args[0])
        if dst.op == cot_ref:
            dst = _unwrap_cast(dst.x)
        if dst.op == cot_ptr and dst.x is not None:
            dst = _unwrap_cast(dst.x)
        if dst.op == cot_idx and dst.y is not None:
            y = _unwrap_cast(dst.y)
            if y.op == cot_num and int(y.numval()) == 0:
                dst = _unwrap_cast(dst.x)
        if dst.op != cot_var:
            return None

        # source: string literal or immediate
        src = _unwrap_cast(args[1])
        if src.op == cot_str:
            data = _string_literal_bytes(src)
            if data is None:
                return None
            if len(args) > 2:
                n = _unwrap_cast(args[2])
                if n.op == cot_num:
                    cnt = int(n.numval())
                    if 0 < cnt <= len(data):
                        data = data[:cnt]
        elif src.op == cot_num:
            val = int(src.numval()) & (2**64 - 1)
            size = 8
            if len(args) > 2:
                n = _unwrap_cast(args[2])
                if n.op == cot_num:
                    size = max(1, min(64, int(n.numval())))
            data = val.to_bytes(size, "little")
        else:
            return None
        # the destination lvar is resolved against lvars by the caller
        return (dst.v.idx, data)
    except Exception:
        return None


def find_call(vdui):
    """Locate the call expression under the cursor (the call itself, the
    callee name, or -- when unambiguous -- anywhere in the view)."""
    calls, _, _ = _collect(vdui.cfunc)
    if not calls:
        return None

    # ctree item under the cursor; the attribute name differs across IDA
    # versions (ct in the SDK, ctree_item in some older bindings)
    item = None
    for attr in ("ct", "ctree_item"):
        item = getattr(vdui, attr, None)
        if item is not None:
            break

    if item is not None:
        try:
            if item.is_citem():
                e = item.e
                if e is not None:
                    e = _unwrap_cast(e)
                    if e.op == cot_call:
                        return e
                    if e.op == cot_obj:
                        direct = [c for c in calls if
                                  _unwrap_cast(c.x).op == cot_obj
                                  and c.x.obj_ea == e.obj_ea]
                        if len(direct) == 1:
                            return direct[0]
                        if len(direct) > 1 and e.ea != _BADADDR:
                            for c in direct:
                                if c.ea == e.ea:
                                    return c
                        if direct:
                            return direct[0]
        except Exception:
            pass

    # fallback: cursor address equals a call expression address
    try:
        ea = ida_kernwin.get_screen_ea()
        by_ea = [c for c in calls if c.ea == ea]
        if len(by_ea) == 1:
            return by_ea[0]
    except Exception:
        pass

    # last resort: a single call in the whole view is unambiguous
    if len(calls) == 1:
        return calls[0]
    return None


def _index_of_var(lhs, var_idx):
    """Element index if lhs is var[idx] for var_idx, else None."""
    lhs = _unwrap_cast(lhs)
    if lhs.op == cot_idx and lhs.x.op == cot_var and lhs.x.v.idx == var_idx \
            and lhs.y.op == cot_num:
        try:
            return int(lhs.y.numval())
        except Exception:
            return None
    return None


def _stack_var_bytes(cfunc, var_idx):
    """Assemble a stack buffer built from immediate stores `var[i] = const`.

    Elements are concatenated in ascending index order, little-endian.
    Returns bytes only when the indices are contiguous from 0; gaps leave
    the argument for manual entry."""
    try:
        lvar = cfunc.get_lvars()[var_idx]
    except Exception:
        return None
    esize = _elem_size(lvar)

    _, assignments, _ = _collect(cfunc)
    slots = {}
    for _ea, lhs, rhs in assignments:
        idx = _index_of_var(lhs, var_idx)
        if idx is None:
            continue
        rhs = _unwrap_cast(rhs)
        if rhs.op != cot_num:
            continue
        try:
            val = int(rhs.numval()) & (2**64 - 1)
        except Exception:
            continue
        slots[idx] = val.to_bytes(esize, "little")

    if not slots:
        return None
    n = max(slots)
    if min(slots) != 0 or len(slots) != n + 1 or (n + 1) * esize > 0x8000:
        return None
    return b"".join(slots[i] for i in range(n + 1))


def _stkoff(lvar):
    """Frame offset of a stack variable, or None (registers etc.)."""
    try:
        if lvar.is_stk_var():
            return lvar.location.stkoff()
    except Exception:
        pass
    return None


def _stack_region_bytes(cfunc, var_idx, lo_ea=None, hi_ea=None):
    """Assemble a stack region from immediate assignments to scalar stack
    variables.

    This is the shape Hex-Rays produces when a local byte array is spilled
    into individually named one-byte variables next to a qword holder:
        src_ = 0xC2...53LL; v7 = -33; n37 = 37; ...
    Slots are placed by frame offset relative to the referenced variable;
    the result is the contiguous run starting at that variable.

    lo_ea/hi_ea restrict the collected statements to the (lo, hi] address
    window -- the code feeding one call site. Branches that reuse the same
    scalar variables for a different call write at disjoint addresses, so
    the window keeps the sites from contaminating each other."""
    lvars = cfunc.get_lvars()
    try:
        base = lvars[var_idx]
    except Exception:
        return None
    base_off = _stkoff(base)
    if base_off is None:
        return None

    windowed = lo_ea is not None and hi_ea is not None \
        and hi_ea != _BADADDR

    def in_window(stmt_ea):
        if not windowed:
            return True
        if stmt_ea is None or stmt_ea == _BADADDR:
            return False       # unpositioned stmt in a windowed fn: unsafe
        return lo_ea < stmt_ea <= hi_ea

    _, assignments, copy_fills = _collect(cfunc)
    slots = {}
    for ea, lhs, rhs in assignments:
        if not in_window(ea):
            continue
        lhs = _unwrap_cast(lhs)
        if lhs.op != cot_var or rhs.op != cot_num:
            continue
        try:
            v = lvars[lhs.v.idx]
        except Exception:
            continue
        off = _stkoff(v)
        if off is None or off < base_off:
            continue
        try:
            size = v.type().get_size()
        except Exception:
            size = 0
        if not size or size <= 0 or size > 64:
            continue
        try:
            val = int(rhs.numval()) & ((1 << (size * 8)) - 1)
        except Exception:
            continue
        slots[off] = val.to_bytes(size, "little")

    for ea, dst_idx, data in copy_fills:
        if not in_window(ea):
            continue
        try:
            v = lvars[dst_idx]
        except Exception:
            continue
        off = _stkoff(v)
        if off is None or off < base_off:
            continue
        slots[off] = data

    if base_off not in slots:
        return None
    chunks, off = [], base_off
    while off in slots:
        chunks.append(slots[off])
        off += len(slots[off])
    blob = b"".join(chunks)
    return blob if len(blob) >= 8 else None


def _classify(cfunc, arg, lvars, lo_ea=None, hi_ea=None):
    e = _unwrap_cast(arg)
    op = e.op
    if op == cot_num:
        return ArgInfo("literal", int(e.numval()) & (2**64 - 1))
    if op == cot_ref and e.x.op == cot_obj:
        return ArgInfo("address", int(e.x.obj_ea))
    if op == cot_ref and e.x.op == cot_var and lvars is not None:
        blob = _stack_region_bytes(cfunc, e.x.v.idx, lo_ea, hi_ea)
        if blob is not None:
            return ArgInfo("stack-bytes", blob,
                           note=" (from immediate stores)")
    if op == cot_obj:
        s = _string_at(e.obj_ea)
        if s:
            return ArgInfo("string", s)
        return ArgInfo("address", int(e.obj_ea))
    if op == cot_str:
        try:
            s = str(e).strip('"')
            return ArgInfo("string", s.encode("utf-8") + b"\x00")
        except Exception:
            pass
    if op == cot_var and lvars is not None:
        blob = _stack_var_bytes(cfunc, e.v.idx)
        if blob is not None:
            return ArgInfo("stack-bytes", blob,
                           note=" (from immediate stores)")
    return ArgInfo("unknown", None)


def extract(vdui):
    """Top-level helper: vdui -> CallInfo (or None when no call is found)."""
    call = find_call(vdui)
    if call is None:
        return None
    try:
        callee = call.x.obj_ea if _unwrap_cast(call.x).op == cot_obj else None
    except Exception:
        callee = None
    try:
        lvars = vdui.cfunc.get_lvars()
    except Exception:
        lvars = None

    # statement window for stack-region extraction: assignments belonging
    # to this call site lie between the previous call expression and this
    # one. Branches reusing the same scalar variables write at disjoint
    # addresses, so the window keeps parallel sites from mixing.
    lo_ea = hi_ea = None
    try:
        calls, _, _ = _collect(vdui.cfunc)
        eas = sorted(c.ea for c in calls
                     if c.ea is not None and c.ea != _BADADDR)
        if call.ea is not None and call.ea != _BADADDR:
            hi_ea = call.ea
            prev = [ea for ea in eas if ea < hi_ea]
            lo_ea = prev[-1] if prev else None
    except Exception:
        lo_ea = hi_ea = None

    args = []
    for arg in call.a:
        try:
            args.append(_classify(vdui.cfunc, arg, lvars, lo_ea, hi_ea))
        except Exception:
            args.append(ArgInfo("unknown", None))

    # cross-check a stack blob against the literal length argument: a
    # partially recovered blob would decrypt into garbage silently
    if args and args[0].kind == "stack-bytes" and args[0].value is not None \
            and len(args) > 1 and args[1].kind == "literal" \
            and isinstance(args[1].value, int) \
            and len(args[0].value) != args[1].value:
        args[0] = ArgInfo("unknown", None,
                          note=" (length mismatch, fill manually)")
    return CallInfo(call.ea, callee, args)


# ===========================================================================
# dialog + background worker (Qt bindings loaded lazily, IDA only)
# ===========================================================================
FORMAT_HELP = (
    "Field format:  0x1A2B or -12 = integer/address   |   "
    '"text" = C string   |   9c6e0c3a... = hex byte blob   |   '
    "empty = unknown (fill in before running)")

_QT_CACHE = {}


def _qt():
    if "qt" not in _QT_CACHE:
        try:
            from PySide6 import QtCore, QtWidgets
        except ImportError:                            # IDA 7.x
            from PyQt5 import QtCore, QtWidgets
        _QT_CACHE["qt"] = (QtCore, QtWidgets)
    return _QT_CACHE["qt"]


_EMU_CACHE = {}


def _get_emu(sample_path, base):
    """Cached Emu per (sample path, base); the mapped image is reused."""
    key = (sample_path, base)
    if key not in _EMU_CACHE:
        import unicall
        kwargs = {"base": base} if base else {}
        _EMU_CACHE[key] = unicall.Emu(sample_path, **kwargs)
    return _EMU_CACHE[key]


def _emulate_thread_class():
    QtCore, _ = _qt()
    if "EmulateThread" in _QT_CACHE:
        return _QT_CACHE["EmulateThread"]

    class EmulateThread(QtCore.QThread):
        """Runs one unicall call() invocation off the UI thread."""

        done = QtCore.Signal(object)      # str or int result
        fail = QtCore.Signal(str)         # error text

        def __init__(self, sample_path, base, call_ea, args, convention,
                     ret_mode, parent=None):
            super().__init__(parent)
            self.sample_path = sample_path
            self.base = base
            self.call_ea = call_ea
            self.args = args
            self.convention = convention
            self.ret_mode = ret_mode

        def run(self):
            try:
                import unicall
                emu = _get_emu(self.sample_path, self.base)
                kwargs = {"ret": self.ret_mode}
                if self.convention:
                    kwargs["convention"] = self.convention
                result = emu.call(self.call_ea, self.args, **kwargs)
                self.done.emit(result)
            except Exception as ex:
                text = f"{type(ex).__name__}: {ex}\n\n{traceback.format_exc()}"
                if isinstance(ex, ImportError):
                    text += ("\n\nHint: the unicall-emu package must be "
                             "installed into the Python interpreter used "
                             "by IDA, e.g.\n    <ida-python> -m pip install"
                             " unicall-emu")
                self.fail.emit(text)

    _QT_CACHE["EmulateThread"] = EmulateThread
    return EmulateThread


def _dialog_class():
    QtCore, QtWidgets = _qt()
    EmulateThread = _emulate_thread_class()
    if "ParamDialog" in _QT_CACHE:
        return _QT_CACHE["ParamDialog"]

    class ParamDialog(QtWidgets.QDialog):
        def __init__(self, sample_path, base, emulate_ea, comment_ea=None,
                     arg_infos=None, parent=None):
            super().__init__(parent)
            self.setWindowTitle("unicall - emulate call")
            self.resize(760, 480)
            self.sample_path = sample_path
            self.base = base
            # emulate_ea: the function to call (callee); comment_ea: the
            # call-site instruction the result comment belongs to. The two
            # are independent on purpose.
            self.emulate_ea = emulate_ea
            self.comment_ea = comment_ea or emulate_ea
            self.vdui = None
            self.thread = None
            self.last_result = None

            lay = QtWidgets.QVBoxLayout(self)

            top = QtWidgets.QGridLayout()
            top.addWidget(QtWidgets.QLabel("emulate function"), 0, 0)
            self.ea_edit = QtWidgets.QLineEdit(
                hex(emulate_ea) if emulate_ea else "")
            self.ea_edit.setToolTip(
                "Address of the function to emulate (the callee), not the "
                "call site")
            top.addWidget(self.ea_edit, 0, 1)
            top.addWidget(QtWidgets.QLabel("convention"), 0, 2)
            self.conv_combo = QtWidgets.QComboBox()
            self.conv_combo.addItems(["auto", "sysv", "win", "cdecl"])
            top.addWidget(self.conv_combo, 0, 3)
            top.addWidget(QtWidgets.QLabel("return as"), 0, 4)
            self.ret_combo = QtWidgets.QComboBox()
            self.ret_combo.addItems(["int", "str"])
            top.addWidget(self.ret_combo, 0, 5)
            lay.addLayout(top)

            lay.addWidget(QtWidgets.QLabel("arguments"))
            self.table = QtWidgets.QTableWidget(0, 3)
            self.table.setHorizontalHeaderLabels(
                ["#", "detected kind", "value"])
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.verticalHeader().setVisible(False)
            lay.addWidget(self.table)

            hint = QtWidgets.QLabel(FORMAT_HELP)
            hint.setWordWrap(True)
            lay.addWidget(hint)

            btns = QtWidgets.QHBoxLayout()
            self.run_btn = QtWidgets.QPushButton("Run")
            self.run_btn.setDefault(True)
            btns.addWidget(self.run_btn)
            self.cmt_btn = QtWidgets.QPushButton(
                "Write comment at call site")
            btns.addWidget(self.cmt_btn)
            btns.addStretch(1)
            close_btn = QtWidgets.QPushButton("Close")
            btns.addWidget(close_btn)
            lay.addLayout(btns)

            self.status = QtWidgets.QLabel("Ready.")
            lay.addWidget(self.status)
            self.output = QtWidgets.QPlainTextEdit()
            self.output.setReadOnly(True)
            lay.addWidget(self.output, 1)

            self.run_btn.clicked.connect(self.on_run)
            self.cmt_btn.clicked.connect(self.on_comment)
            close_btn.clicked.connect(self.reject)

            self.set_arg_infos(arg_infos or [])

        def set_arg_infos(self, arg_infos):
            self.table.setRowCount(len(arg_infos))
            for row, info in enumerate(arg_infos):
                idx_item = QtWidgets.QTableWidgetItem(str(row))
                idx_item.setFlags(QtCore.Qt.ItemIsEnabled)
                kind_item = QtWidgets.QTableWidgetItem(info.kind + info.note)
                kind_item.setFlags(QtCore.Qt.ItemIsEnabled)
                value = (encode_arg_text(info.value)
                         if info.value is not None else "")
                self.table.setItem(row, 0, idx_item)
                self.table.setItem(row, 1, kind_item)
                self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(value))
            if arg_infos:
                self.table.setColumnWidth(0, 36)
                self.table.setColumnWidth(1, 220)

        def on_run(self):
            try:
                ea_text = self.ea_edit.text().strip()
                if not ea_text:
                    raise ValueError("call address is empty")
                call_ea = int(ea_text, 0)

                values = []
                for row in range(self.table.rowCount()):
                    item = self.table.item(row, 2)
                    text = item.text() if item else ""
                    try:
                        value = parse_arg_text(text)
                    except ArgumentError as ex:
                        raise ValueError(f"argument {row}: {ex}")
                    if value is None:
                        raise ValueError(
                            f"argument {row} is empty; fill it in or "
                            f"delete the row")
                    values.append(value)

                conv = self.conv_combo.currentText()
                conv = None if conv == "auto" else conv
                ret_mode = self.ret_combo.currentText()

                self.run_btn.setEnabled(False)
                self.status.setText("Emulating...")
                self.thread = EmulateThread(
                    self.sample_path, self.base, call_ea, values, conv,
                    ret_mode, parent=self)
                self.thread.done.connect(self.on_done)
                self.thread.fail.connect(self.on_fail)
                self.thread.start()
            except Exception as ex:
                self.status.setText(f"Error: {ex}")

        def on_done(self, result):
            self.run_btn.setEnabled(True)
            self.status.setText("Done.")
            if isinstance(result, bytes):
                result = result.decode("utf-8", errors="replace")
            if isinstance(result, str):
                self.output.setPlainText(result)
                self.last_result = result
            else:
                self.output.setPlainText(
                    f"return value (RAX/EAX): {result:#x} ({result})")
                self.last_result = f"{result:#x}"

        def on_fail(self, text):
            self.run_btn.setEnabled(True)
            self.status.setText("Emulation failed - see output.")
            self.output.setPlainText(text)

        def on_comment(self):
            text = self.last_result
            if not text:
                self.status.setText("Nothing to comment yet - run first.")
                return
            try:
                if not self.comment_ea:
                    raise ValueError("no call-site address recorded")
                comment = 'unicall: "%s"' % text.replace("\n", "\\n")[:400]
                ida_bytes.set_cmt(self.comment_ea, comment, 0)
                if self.vdui is not None:
                    self.vdui.refresh_view(True)
                self.status.setText(
                    f"Comment written at {self.comment_ea:#x} (call site).")
            except Exception as ex:
                self.status.setText(f"Comment failed: {ex}")

    _QT_CACHE["ParamDialog"] = ParamDialog
    return ParamDialog


def show_dialog(sample_path, base, info=None, vdui=None, manual_ea=None):
    """Open the dialog. `info` is CallInfo (approach A) or None (approach B:
    manual mode with blank fields)."""
    QtCore, QtWidgets = _qt()
    ParamDialog = _dialog_class()

    parent = None
    try:
        parent = QtWidgets.QApplication.activeWindow()
    except Exception:
        pass

    if info is not None:
        # emulate the callee function; comment belongs to the call site
        emulate_ea = info.callee_ea or (
            info.ea if info.ea and info.ea != _BADADDR else 0)
        comment_ea = info.ea if info.ea and info.ea != _BADADDR else emulate_ea
        dialog = ParamDialog(sample_path, base, emulate_ea, comment_ea,
                             info.args, parent=parent)
        dialog.vdui = vdui
    else:
        blanks = [ArgInfo("unknown", None) for _ in range(6)]
        dialog = ParamDialog(sample_path, base, manual_ea or 0, manual_ea or 0,
                             blanks, parent=parent)

    # a parentless dialog with no Python reference would be garbage
    # collected immediately; keep it alive until it is closed
    _ACTIVE_DIALOGS.append(dialog)

    def _cleanup(*_a):
        if dialog in _ACTIVE_DIALOGS:
            _ACTIVE_DIALOGS.remove(dialog)

    dialog.finished.connect(_cleanup)
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()
    return dialog


# ===========================================================================
# IDA plugin integration
# ===========================================================================
_UNICALL_NETNODE = "$ unicall_ida"


def _resolve_sample_path():
    """Resolve the sample binary to map into the emulator.

    get_input_file_path() returns the path recorded in the database, which
    may be stale (the IDB may have been created on another machine).
    Resolution order: valid IDB path -> previously chosen path (persisted
    in the database via a netnode) -> file dialog. A valid choice made in
    the dialog is stored back into the database."""
    candidates = []
    try:
        candidates.append(ida_nalt.get_input_file_path())
    except Exception:
        pass
    try:
        import ida_netnode
        cached = ida_netnode.netnode(_UNICALL_NETNODE).supstr(0)
        if cached:
            candidates.append(cached)
    except Exception:
        pass

    for cand in candidates:
        if cand and os.path.exists(cand):
            return cand

    import ida_kernwin
    default = ""
    for cand in candidates:
        if cand:
            default = os.path.basename(cand)
            break
    chosen = ida_kernwin.ask_file(
        True, default,
        "unicall: select the sample binary to map into the emulator")
    if chosen and os.path.exists(chosen):
        try:
            import ida_netnode
            ida_netnode.netnode(_UNICALL_NETNODE).supset(0, chosen)
        except Exception:
            pass
        return chosen
    return None


def _context():
    """(sample_path, image_base); sample_path is None when unresolvable."""
    return _resolve_sample_path(), ida_nalt.get_imagebase()


def _open_from_vu(vu, manual=False):
    sample, base = _context()
    if not sample:
        ida_kernwin.warning(
            "unicall: the sample binary could not be located.\n"
            "The path recorded in this database does not exist on this "
            "machine and no file was selected.")
        return
    if not manual and vu is not None:
        try:
            info = extract(vu)
        except Exception as ex:
            info = None
            ida_kernwin.warning(
                f"unicall: argument extraction failed: {ex}\n"
                f"Opening the dialog in manual mode.")
        if info is not None:
            show_dialog(sample, base, info=info, vdui=vu)
            return
    show_dialog(sample, base, info=None, vdui=vu,
                manual_ea=ida_kernwin.get_screen_ea())


if _IDA_OK:
    class _EmulateActionHandler(ida_kernwin.action_handler_t):
        def activate(self, ctx):
            vu = _current_vu[0]
            if vu is None and HAS_HEXRAYS:
                widget = ida_kernwin.get_current_widget()
                if widget is not None:
                    vu = ida_hexrays.get_widget_vdui(widget)
            _open_from_vu(vu, manual=(vu is None))
            return 1

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    def _hexrays_callback(event, *args):
        if event == ida_hexrays.hxe_populating_popup:
            form, popup, vu = args[0], args[1], args[2]
            _current_vu[0] = vu
            ida_kernwin.attach_action_to_popup(form, popup, ACTION_ID,
                                               MENU_PATH)
        return 0


if _IDA_OK:
    class unicall_plugin_t(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_KEEP
        comment = "unicall: emulate a single call with Unicorn (PE/ELF)"
        help = ("Right-click a call in the pseudocode view, or Edit > "
                "Plugins > unicall for manual mode.")
        wanted_name = "unicall"
        wanted_hotkey = HOTKEY_MANUAL

        def init(self):
            desc = ida_kernwin.action_desc_t(
                ACTION_ID, "unicall: emulate this call",
                _EmulateActionHandler(), HOTKEY_EMULATE,
                "Emulate the call under the cursor with unicall", -1)
            ida_kernwin.register_action(desc)
            if HAS_HEXRAYS:
                ida_hexrays.install_hexrays_callback(_hexrays_callback)
                print("[unicall_ida] loaded (pseudocode integration "
                      "active).")
            else:
                print("[unicall_ida] loaded (Hex-Rays unavailable; manual "
                      "mode only via Edit > Plugins).")
            return ida_idaapi.PLUGIN_KEEP

        def run(self, arg):
            _open_from_vu(None, manual=True)

        def term(self):
            ida_kernwin.unregister_action(ACTION_ID)

    def PLUGIN_ENTRY():
        return unicall_plugin_t()

else:
    unicall_plugin_t = None

    def PLUGIN_ENTRY():                                # pragma: no cover
        raise ImportError("unicall_ida must be loaded inside IDA")
