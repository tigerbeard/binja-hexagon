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

It decodes the instructions that Qualcomm's QEMU Hexagon target defines (the
`hex-next` branch of [quic/qemu](https://github.com/quic/qemu), where Hexagon
work is done before it reaches QEMU): scalar instructions to V85, HVX to V81,
the HMX matrix extension and the HLX extension, and QEMU's legacy
(`:deprecated`) encodings. The commit is in
[`third_party/qemu-hexagon/UPSTREAM`](/third_party/qemu-hexagon/UPSTREAM).
The HVX FP8 and `vcvt2` instructions and `memcpy`, which that branch lacks,
come from another of Qualcomm's branches
([`overlay`](/third_party/qemu-hexagon/README.md)).
Hexagon versions only add instructions, so one decoder serves code for any
version from V5 on.

Each packet is one Binary Ninja instruction. Of the 2,774 instructions:

*   1,546 are lifted to LLIL with their semantics. That is 86% of the 1,789
    scalar instructions; no HVX, HMX or HLX instruction is.
*   1,225 are lifted as intrinsics (240 scalar, 664 HVX, 147 HMX, 174 HLX).
    Their general registers and data flow are right, but the operation is
    opaque; HVX, HMX and HLX registers are not modelled. 285 of them load or
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

