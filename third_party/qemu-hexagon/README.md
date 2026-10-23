# QEMU Hexagon Target

This folder is a modified version of [quic/qemu](https://github.com/quic/qemu) Hexagon target.

Local changes include:

*  Added the plugin's attributes `A_BN_COND_J`, `A_BN_RETURN` and `A_BN_SYSTEM`,
   which `hex_common.add_bn_attribs` derives from the semantics.

*  Replaces `assert`s with `longjmp`s, so decoder fails gracefully for invalid, non-code input.

*  Removed QEMU specific code (`gen_tcg_funcs.py`).

*  Removed QEMU library dependencies.
