# QEMU Hexagon Target

This folder is a modified version of [quic/qemu](https://github.com/quic/qemu) Hexagon target.

The instruction definitions, `imported/` and `attribs_def.h`, come unmodified
from upstream QEMU's `target/hexagon`. `import_upstream.py` refreshes them from
a QEMU checkout and records its commit in `UPSTREAM`. `attribs_def.h` is QEMU's
`attribs_def.h.inc` with the plugin's attributes from `attribs_local_def.h`.
The generators and decoder are an older snapshot, which this plugin keeps
because QEMU now decodes with decodetree.

Local changes include:

*  Added the plugin's attributes `A_BN_COND_J`, `A_BN_RETURN` and `A_BN_SYSTEM`,
   which `hex_common.add_bn_attribs` derives from the semantics. It also marks
   loop ends as indirect jumps.

*  `dectree.py` takes an immediate's width from its encoding when the encoding
   has more bits than the syntax says (V79 `pause`).

*  QEMU's legacy encodings (`LEGACY_DEF_ENC32`), which QEMU leaves out, decode
   as instructions of their own, `TAG_deprecated`, with `TAG`'s semantics and
   `:deprecated` after its syntax, as the PRM writes them
   (`gen_semantics.c`, `gen_dectree_import.c`, `opcodes.c`).

*  Replaces `assert`s with `longjmp`s, so decoder fails gracefully for invalid, non-code input.

*  Removed QEMU specific code (`gen_tcg_funcs.py`).

*  Removed QEMU library dependencies.
