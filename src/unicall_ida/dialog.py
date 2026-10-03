#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unicall_ida.dialog -- parameter dialog (approach B) fed by automatic
extraction (approach A).

The dialog is always shown before anything runs: extraction pre-fills the
fields, the analyst reviews/edits them, and only an explicit "Run" starts
the emulation. Fields that could not be extracted stay blank; running with
blank fields is rejected with the offending argument number.
"""
try:
    from PySide6 import QtCore, QtWidgets
except ImportError:                                    # IDA 7.x
    from PyQt5 import QtCore, QtWidgets

from . import argcodec
from .worker import EmulateThread

FORMAT_HELP = (
    "Field format:  0x1A2B or -12 = integer/address   |   "
    '"text" = C string   |   9c6e0c3a... = hex byte blob   |   '
    "empty = unknown (fill in before running)")


def _qt_import_ok():
    return True


class ParamDialog(QtWidgets.QDialog):
    def __init__(self, sample_path, base, call_ea, arg_infos=None,
                 parent=None):
        super().__init__(parent)
        self.setWindowTitle("unicall - emulate call")
        self.resize(760, 480)
        self.sample_path = sample_path
        self.base = base
        self.call_ea = call_ea
        self.vdui = None
        self.thread = None

        lay = QtWidgets.QVBoxLayout(self)

        top = QtWidgets.QGridLayout()
        top.addWidget(QtWidgets.QLabel("call address"), 0, 0)
        self.ea_edit = QtWidgets.QLineEdit(hex(call_ea) if call_ea else "")
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
        self.table.setHorizontalHeaderLabels(["#", "detected kind", "value"])
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
        self.cmt_btn = QtWidgets.QPushButton("Write comment at call site")
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

    # ------------------------------------------------------------- filling
    def set_arg_infos(self, arg_infos):
        """Fill the argument table from extractor.ArgInfo entries."""
        self.table.setRowCount(len(arg_infos))
        for row, info in enumerate(arg_infos):
            idx_item = QtWidgets.QTableWidgetItem(str(row))
            idx_item.setFlags(QtCore.Qt.ItemIsEnabled)
            kind_item = QtWidgets.QTableWidgetItem(info.kind + info.note)
            kind_item.setFlags(QtCore.Qt.ItemIsEnabled)
            value = argcodec.encode(info.value) if info.value is not None else ""
            val_item = QtWidgets.QTableWidgetItem(value)
            self.table.setItem(row, 0, idx_item)
            self.table.setItem(row, 1, kind_item)
            self.table.setItem(row, 2, val_item)
        if arg_infos:
            self.table.setColumnWidth(0, 36)
            self.table.setColumnWidth(1, 220)

    # ------------------------------------------------------------- running
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
                    value = argcodec.parse(text)
                except argcodec.ArgumentError as ex:
                    raise ValueError(f"argument {row}: {ex}")
                if value is None:
                    raise ValueError(f"argument {row} is empty; fill it in "
                                     f"or delete the row")
                values.append(value)

            conv = self.conv_combo.currentText()
            conv = None if conv == "auto" else conv
            ret_mode = self.ret_combo.currentText()

            self.run_btn.setEnabled(False)
            self.status.setText("Emulating...")
            self.thread = EmulateThread(self.sample_path, self.base,
                                        call_ea, values, conv, ret_mode,
                                        parent=self)
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
        else:
            self.output.setPlainText(f"return value (RAX/EAX): "
                                     f"{result:#x} ({result})")
        self.last_result = result if isinstance(result, str) else str(result)

    def on_fail(self, text):
        self.run_btn.setEnabled(True)
        self.status.setText("Emulation failed - see output.")
        self.output.setPlainText(text)

    # ------------------------------------------------------------ comments
    def on_comment(self):
        """Best-effort: write the latest result as a comment at the call
        site and refresh the pseudocode view."""
        text = getattr(self, "last_result", None)
        if not text:
            self.status.setText("Nothing to comment yet - run first.")
            return
        try:
            import ida_bytes
            import ida_kernwin
            ea_text = self.ea_edit.text().strip()
            if not ea_text:
                raise ValueError("call address is empty")
            ea = int(ea_text, 0)
            comment = 'unicall: "%s"' % text.replace("\n", "\\n")[:400]
            ida_bytes.set_cmt(ea, comment, 0)
            if self.vdui is not None:
                self.vdui.refresh_view(True)
            self.status.setText("Comment written.")
        except Exception as ex:
            self.status.setText(f"Comment failed: {ex}")


def show_dialog(sample_path, base, info=None, vdui=None, manual_ea=None):
    """Open the dialog. `info` is extractor.CallInfo (approach A) or None
    (approach B: manual mode with blank fields)."""
    if info is not None:
        call_ea = info.ea if info.ea and info.ea != 0xFFFFFFFFFFFFFFFF \
            else (info.callee_ea or 0)
        dialog = ParamDialog(sample_path, base, call_ea, info.args)
        dialog.vdui = vdui
    else:
        dialog = ParamDialog(sample_path, base, manual_ea or 0,
                             arg_infos=_blank_args(6))
    dialog.setWindowFlags(dialog.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
    dialog.show()
    return dialog


def _blank_args(n):
    from .extractor import ArgInfo
    return [ArgInfo("unknown", None) for _ in range(n)]
