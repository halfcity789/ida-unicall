#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unicall_ida.extractor -- recover call arguments from Hex-Rays ctree.

Extraction is best-effort: every argument that cannot be understood is
returned as "unknown" (value None) and left blank in the dialog for manual
entry. Recognized argument shapes:

    numeric literal              48, 35            -> int
    global reference             &dword_61F2F0     -> int (image address)
    global object                unk_4187E0        -> int (image address)
    string literal               "prefix %s"       -> bytes (UTF-8 + NUL)
    stack array of immediates    str_cipher[i]=... -> bytes (assembled)

The stack-array case walks the whole pseudocode of the containing function
and collects numeric assignments `var[i] = <constant>`; the blob is then
assembled little-endian from element 0 upward using the array element size.
"""
try:
    import ida_hexrays
    import ida_idaapi
    import ida_nalt
    from ida_hexrays import (
        cot_call, cot_num, cot_obj, cot_var, cot_ref, cot_cast,
        cot_idx, cot_asg, cot_ptr, cot_add, cot_str,
    )
    _BADADDR = ida_idaapi.BADADDR
    _HR_OK = True
except ImportError:                                    # outside IDA
    _HR_OK = False


class ArgInfo:
    """One extracted call argument."""

    def __init__(self, kind, value, note=""):
        self.kind = kind        # literal / address / string / stack-bytes / unknown
        self.value = value      # int | bytes | None
        self.note = note

    def __repr__(self):         # pragma: no cover - debugging aid
        return f"ArgInfo(kind={self.kind!r}, value={self.value!r})"


class CallInfo:
    """The call expression selected in the pseudocode view."""

    def __init__(self, ea, callee_ea, args):
        self.ea = ea                    # expression address (may be BADADDR)
        self.callee_ea = callee_ea      # direct callee address or None
        self.args = args                # list[ArgInfo]

    @property
    def unknown_count(self):
        return sum(1 for a in self.args if a.value is None)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _unwrap_cast(e):
    while _HR_OK and e.op == cot_cast:
        e = e.x
    return e


def _string_at(ea):
    try:
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
            elem = ti.get_array_element()
            s = elem.get_size()
            if s and 0 < s <= 64:
                return s
        s = ti.get_size()
        if s and 0 < s <= 64:
            return s
    except Exception:
        pass
    return 8


# ---------------------------------------------------------------------------
# ctree walking
# ---------------------------------------------------------------------------
class _CallCollector:
    """Collect every direct call expression of the function (CV_FAST walk)."""

    def __init__(self, cfunc):
        self.calls = []
        try:
            self.assignments = []       # (lhs_expr, rhs_expr) of cot_asg
            visitor = self._make_visitor()
            visitor.apply_to(cfunc.body, None)
        except Exception:
            self.calls = []

    def _make_visitor(self):
        outer = self

        class V(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)

            def visit_expr(self, e):
                try:
                    if e.op == cot_call:
                        outer.calls.append(e)
                    elif e.op == cot_asg:
                        outer.assignments.append((e.x, e.y))
                except Exception:
                    pass
                return 0

        return V()


def find_call(vdui):
    """Locate the call expression under the cursor. Returns a cexpr_t for
    cot_call or None. Accepts the cursor sitting on the call itself, on the
    callee name, or (when the function contains exactly one call) anywhere."""
    item = vdui.ctree_item
    if item is None or not item.is_citem():
        return None
    e = item.e
    if e is None:
        return None
    if e.op == cot_call:
        return e
    e = _unwrap_cast(e)
    if e.op == cot_call:
        return e

    calls = _CallCollector(vdui.cfunc).calls
    # cursor on the callee name -> match calls by callee address
    if e.op == cot_obj:
        direct = [c for c in calls
                  if _unwrap_cast(c.x).op == cot_obj
                  and c.x.obj_ea == e.obj_ea]
        if len(direct) == 1:
            return direct[0]
        if len(direct) > 1:
            # several calls to the same callee: prefer the one whose
            # expression address equals the cursor address
            if e.ea != _BADADDR:
                for c in direct:
                    if c.ea == e.ea:
                        return c
            return direct[0]
    # cursor elsewhere: unambiguous single call in view is a safe fallback
    if len(calls) == 1:
        return calls[0]
    return None


# ---------------------------------------------------------------------------
# argument classification
# ---------------------------------------------------------------------------
def extract_args(cfunc, call):
    """Classify every argument of `call`. Returns a list of ArgInfo."""
    out = []
    lvars = None
    try:
        lvars = cfunc.get_lvars()
    except Exception:
        pass
    for arg in call.a:
        try:
            out.append(_classify(cfunc, _unwrap_cast(arg), lvars))
        except Exception:
            out.append(ArgInfo("unknown", None))
    return out


def _classify(cfunc, e, lvars):
    op = e.op
    if op == cot_num:
        return ArgInfo("literal", int(e.numval()) & (2**64 - 1))
    if op == cot_ref and e.x.op == cot_obj:
        return ArgInfo("address", int(e.x.obj_ea))
    if op == cot_obj:
        s = _string_at(e.obj_ea)
        if s:
            return ArgInfo("string", s)
        return ArgInfo("address", int(e.obj_ea))
    if op == cot_str:
        # some Hex-Rays versions expose string literals this way
        try:
            s = str(e).strip('"')
            return ArgInfo("string", s.encode("utf-8") + b"\x00")
        except Exception:
            pass
    if op == cot_var and lvars is not None:
        blob = _stack_var_bytes(cfunc, e.v.idx, lvars)
        if blob is not None:
            return ArgInfo("stack-bytes", blob,
                           note="assembled from immediate stores")
    return ArgInfo("unknown", None)


def _stack_var_bytes(cfunc, var_idx, lvars):
    """Assemble a stack buffer filled with immediate stores.

    Collects assignments `var[i] = <numeric constant>` for the local
    variable with index var_idx and concatenates the elements in ascending
    index order (little-endian). Returns bytes only when indices are
    contiguous starting at 0; otherwise None (partially known buffers are
    left for manual entry)."""
    try:
        lvar = lvars[var_idx]
    except Exception:
        return None
    esize = _elem_size(lvar)

    slots = {}
    assignments = _collect_assignments(cfunc)
    for lhs, rhs in assignments:
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
    if min(slots) != 0 or len(slots) != n + 1:
        return None                    # gaps: leave for manual entry
    if (n + 1) * esize > 0x8000:
        return None                    # sanity cap
    return b"".join(slots[i] for i in range(n + 1))


def _collect_assignments(cfunc):
    collector = _CallCollector(cfunc)
    return collector.assignments


def _index_of_var(lhs, var_idx):
    """Return the element index if `lhs` is var[idx] for var_idx, else None."""
    lhs = _unwrap_cast(lhs)
    if lhs.op == cot_idx and lhs.x.op == cot_var and lhs.x.v.idx == var_idx \
            and lhs.y.op == cot_num:
        try:
            return int(lhs.y.numval())
        except Exception:
            return None
    if lhs.op == cot_var:              # whole-variable assignment: unknown
        return None
    return None


def extract(vdui):
    """Top-level helper: vdui -> CallInfo (or None when no call is found)."""
    if not _HR_OK:
        return None
    call = find_call(vdui)
    if call is None:
        return None
    try:
        callee = call.x.obj_ea if _unwrap_cast(call.x).op == cot_obj else None
    except Exception:
        callee = None
    args = extract_args(vdui.cfunc, call)
    return CallInfo(call.ea, callee, args)
