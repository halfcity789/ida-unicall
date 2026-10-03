#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unicall_ida -- IDA plugin entry point.

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

IDA imports are guarded so that pure-logic submodules (argcodec) remain
importable and testable outside IDA.
"""
_IDA_OK = True
try:
    import ida_idaapi
    import ida_kernwin

    try:
        import ida_hexrays
        import ida_nalt
        HAS_HEXRAYS = ida_hexrays.init_hexrays_plugin()
    except ImportError:                                # hexrays not present
        HAS_HEXRAYS = False
except ImportError:                                    # outside IDA
    _IDA_OK = False
    HAS_HEXRAYS = False

ACTION_ID = "unicall:emulate_call"
MENU_PATH = "unicall/"
_HOTKEY = "Ctrl-Alt-U"

if _IDA_OK:
    _current_vu = [None]

    # ------------------------------------------------------------------ helpers
    def _context():
        """(sample_path, image_base) of the current database."""
        sample = ida_nalt.get_input_file_path()
        base = ida_nalt.get_imagebase()
        return sample, base

    def _open_from_vu(vu, manual=False):
        from . import dialog, extractor
        sample, base = _context()
        if not manual and vu is not None:
            try:
                info = extractor.extract(vu)
            except Exception as ex:
                info = None
                ida_kernwin.warning(
                    f"unicall: argument extraction failed: {ex}\n"
                    f"Opening the dialog in manual mode.")
            if info is not None:
                dialog.show_dialog(sample, base, info=info, vdui=vu)
                return
        dialog.show_dialog(sample, base, info=None, vdui=vu,
                           manual_ea=ida_kernwin.get_screen_ea())

    # ------------------------------------------- action + popup integration
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

    # ------------------------------------------------------------------ plugin
    class unicall_plugin_t(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_KEEP
        comment = "unicall: emulate a single call with Unicorn (PE/ELF)"
        help = ("Right-click a call in the pseudocode view, or Edit > "
                "Plugins > unicall for manual mode.")
        wanted_name = "unicall"
        wanted_hotkey = _HOTKEY

        def init(self):
            handler = _EmulateActionHandler()
            desc = ida_kernwin.action_desc_t(
                ACTION_ID, "unicall: emulate this call", handler, _HOTKEY,
                "Emulate the call under the cursor with unicall", -1)
            ida_kernwin.register_action(desc)
            if HAS_HEXRAYS:
                ida_hexrays.install_hexrays_callback(_hexrays_callback)
                print("[unicall_ida] loaded (pseudocode integration active).")
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
