# Binary Ninja Hexagon Processor Plugin

## Overview

This is a new architecture plugin for [Binary Ninja](https://binary.ninja/)
reverse engineering platform. It adds support for Qualcomm's
[Hexagon CPUs](https://en.wikipedia.org/wiki/Qualcomm_Hexagon).

Main features:

1.  **Complete disassembler support**. Plugin decodes individual instructions,
    parses and tokenizes instruction operands, and populates branch information
    for all packets:

![Screenshot1](/docs/images/screenshot1.png)

1.  **Partial decompiler support**. Plugin lifts (a subset of) Hexagon
    instructions to Binary Ninja's
    [Low-Level Intermediate Language](https://docs.binary.ninja/dev/bnil-llil.html)
    (LLIL). Lifter manages clobbered registers, implements ".new" semantics and
    packet level branch semantics. Thanks to BN's IL modules, the LLIL
    representation is lifted to pseudo-C, High-Level IL (HLIL), producing
    readable, decompiled code:

![Screenshot2](/docs/images/screenshot2.png)

## Additional Information

*   [Setup and build](/docs/setup.md) instructions.

*   [High level design](/docs/design.md) document.

## Status

This fork of `google/binja-hexagon` builds against Binary Ninja 6.1 (the
pinned API revision is in [setup](/docs/setup.md)). The plugin is in alpha.

It decodes the instruction set of QEMU's Hexagon target (V67 scalar, V66
HVX), plus the V71 acquire and release instructions. Later scalar additions
and HVX V68 and above are not decoded yet.

Each packet is one Binary Ninja instruction. Of the 2,237 instructions:

*   906 are lifted to LLIL with their semantics. That is 53% of the 1,718
    scalar instructions; no HVX instruction is.
*   1,328 are lifted as intrinsics (809 scalar, 519 HVX). Their registers and
    data flow are right, but the operation is opaque. 240 of them load or
    store memory.
*   3 have their own lifts: `hintjumpr` is a no-op, `trap1` a system call and
    `rte` unimplemented.

Hardware loops (`loopN`, `spNloop0` and `endloop`) are lifted as loops when
Binary Ninja analyses a function.

Feedback, bug reports and PRs are welcome.

## Acknowledgments

This plugin was built using
[QEMU's Hexagon target](https://github.com/quic/qemu) by Taylor Simpson from
Qualcomm Innovation Center.

Instruction lifters are [auto generated](/plugin/gen_il_funcs.py) by parsing
semantics descriptions. These descriptions are preprocessed using
[PCPP](https://github.com/ned14/pcpp) by Niall Douglas and David Beazley, and
parsed using [Lark](https://github.com/lark-parser/lark) by Erez Shinan.

## License

This project is a derivative work of QEMU's Hexagon target, therefore, it is
licensed under GPLv2, as the original work.

