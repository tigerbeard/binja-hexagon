// Copyright (C) 2020 Google LLC
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#include "plugin/il_util.h"

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "binaryninjaapi.h"
#include "glog/logging.h"
#include "plugin/hex_regs.h"
#include "plugin/hw_loops.h"
#include "plugin/insn_util.h"
#include "plugin/packet_context.h"
#include "plugin/status_macros.h"
#include "third_party/qemu-hexagon/decode.h"

// Defined in il_funcs_generated.cc.
typedef void (*IlLiftFunc)(BinaryNinja::Architecture *arch, uint64_t pc,
                           const Packet &pkt, const Insn &insn, int insn_num,
                           PacketContext &ctx);

extern const IlLiftFunc opcode_liftptr[XX_LAST_OPCODE];

namespace {

using namespace BinaryNinja;
using absl::Hex;
using absl::StrCat;

absl::Status FillBnInstructionLowLevelImpl(Architecture *arch, uint64_t pc,
                                           const Packet &pkt, const Insn &insn,
                                           int insn_num, PacketContext &ctx) {
  LowLevelILFunction &il = ctx.IL();
  if (opcode_liftptr[insn.opcode] == nullptr) {
    // Every opcode has a lifter (most unlifted ones are intrinsics), so this
    // is unexpected. Unimplemented, unlike Undefined, does not end the IL.
    il.AddInstruction(il.Unimplemented());
#ifndef NDEBUG
    LOG(INFO) << "Unsupported lifter for '" << opcode_names[insn.opcode]
              << "' at " << std::hex << "0x" << pc;
#endif
    return absl::OkStatus();
  }
  opcode_liftptr[insn.opcode](arch, pc, pkt, insn, insn_num, ctx);
  return absl::OkStatus();
}

// Jumps back to the start of the loop that |insn|, an endloop, closes. The
// start address is constant, so Binary Ninja sees the loop's back edge.
// endloop01 continues loop 0 if it has iterations left, otherwise loop 1; the
// endloop lifter left the chosen start in |dest|.
void LiftLoopJump(LowLevelILFunction &il, const Insn &insn,
                  const LoopStarts &loop, uint32_t dest) {
  if (insn.opcode == J2_endloop01 && loop.loop0 && loop.loop1) {
    LowLevelILLabel to_loop0, to_loop1;
    il.AddInstruction(il.If(il.CompareEqual(4, il.Register(4, dest),
                                            il.ConstPointer(4, *loop.loop0)),
                            to_loop0, to_loop1));
    il.MarkLabel(to_loop0);
    il.AddInstruction(il.Jump(il.ConstPointer(4, *loop.loop0)));
    il.MarkLabel(to_loop1);
    il.AddInstruction(il.Jump(il.ConstPointer(4, *loop.loop1)));
  } else if (insn.opcode != J2_endloop1 && loop.loop0) {
    il.AddInstruction(il.Jump(il.ConstPointer(4, *loop.loop0)));
  } else if (insn.opcode != J2_endloop0 && loop.loop1) {
    il.AddInstruction(il.Jump(il.ConstPointer(4, *loop.loop1)));
  } else {
    il.AddInstruction(il.Jump(il.Register(4, dest)));
  }
}

// The loops |insn| ends, if it is an endloop of known loops that loopN set
// up. Such a loop end lifts as a plain count-down (LiftPlainLoopEnd).
const LoopStarts *PlainLoopEnd(const Insn &insn, uint64_t pc) {
  if (!IsLoopEnd(insn)) {
    return nullptr;
  }
  const LoopStarts *loop = CurrentLoopStarts(pc);
  if (loop == nullptr) {
    return nullptr;
  }
  const bool ends0 = insn.opcode != J2_endloop1;
  const bool ends1 = insn.opcode != J2_endloop0;
  if ((ends0 && (!loop->loop0 || loop->pipelined)) ||
      (ends1 && !loop->loop1)) {
    return nullptr;
  }
  return loop;
}

// Lifts the end of loops that loopN set up: while a loop's count is above
// one, count it down and jump back to its start. endloop01 tries loop 0, then
// loop 1. (spNloop0 loops also count down USR.LPCFG; their endloops go
// through the generated lifters.)
void LiftPlainLoopEnd(Architecture *arch, LowLevelILFunction &il,
                      const Insn &insn, const LoopStarts &loop) {
  auto count_down = [arch, &il](uint32_t lc, uint64_t start,
                                LowLevelILLabel &otherwise) {
    LowLevelILLabel again;
    il.AddInstruction(il.If(il.CompareSignedGreaterThan(
                                4, il.Register(4, lc), il.Const(4, 1)),
                            again, otherwise));
    il.MarkLabel(again);
    il.AddInstruction(il.SetRegister(
        4, lc, il.Sub(4, il.Register(4, lc), il.Const(4, 1))));
    // Go to the loop start's label when the function has one. A constant
    // jump would do for a single loop end, but endloop01 has two targets,
    // and Binary Ninja gives each jump of the packet both of them.
    if (BNLowLevelILLabel *label = il.GetLabelForAddress(arch, start)) {
      il.AddInstruction(il.Goto(*label));
    } else {
      il.AddInstruction(il.Jump(il.ConstPointer(4, start)));
    }
  };
  LowLevelILLabel next;
  if (insn.opcode == J2_endloop01) {
    LowLevelILLabel try_loop1;
    count_down(HEX_REG_LC0, *loop.loop0, try_loop1);
    il.MarkLabel(try_loop1);
    count_down(HEX_REG_LC1, *loop.loop1, next);
  } else if (insn.opcode == J2_endloop0) {
    count_down(HEX_REG_LC0, *loop.loop0, next);
  } else {
    count_down(HEX_REG_LC1, *loop.loop1, next);
  }
  il.MarkLabel(next);
}

} // namespace

Packet PreparePacketForLifting(const Packet &src) {
  Packet copy = src;
  decode_remove_extenders(&copy);
  decode_shuffle_for_execution(&copy);
  decode_split_cmpjump(&copy);
  return copy;
}

absl::Status FillBnInstructionLowLevelIL(Architecture *arch, uint64_t pc,
                                         const Packet &src,
                                         LowLevelILFunction &il) {
  if (pc & 3) {
    return absl::InvalidArgumentError(
        StrCat("Got unaligned packet address ", Hex(pc)));
  }

  // Re-order instructions for easier processing.
  Packet pkt = PreparePacketForLifting(src);

  // There are many types of branches:
  //   {conditional, non-conditional} x {direct, indirect} x {call, jump}
  // And a packet can have up to two distinct branch instructions.
  //
  // Branch semantics dictate:
  //   A. Post execution: A branch happens only after all packet instructions
  //   have been executed.
  //   B. Single execution: At exit, the CPU takes only a single branch, even if
  //   there are two branches in the packet.
  //   C. Ordering: Branches have a priority based on their encoding order in
  //   the packet. For example, if a packet has a conditional branch, followed
  //   by a non-conditional branch:
  //       { r1 = add(r1, r1)
  //         if (p0) jump:t 1f
  //         jump 2f }
  //   and the condition is met (p0) - then only the conditional branch is
  //   taken. This is also true for calls:
  //       { r1 = add(r1, r1)
  //         if (p0) call 1f
  //         jump 2f }
  //   If the condition is met (p0) - then the call is performed, and the return
  //   address (LR) is set to the next packet. The non-conditional branch (jump
  //   2f) is skipped.
  //
  // A naive implementation for branch semantics could use a LLIL_TEMP register
  // to track the branch destination and branch type:
  //
  //   lifter_jump():
  //     fWRITE_NPC:
  //      LLIL_TEMP(dest) <- branch dest expression, if LLIL_TEMP(dest) has not
  //      been set.
  //      LLIL_TEMP(type) <- branch type (jump, jumpr, call, callr).
  //   }
  //
  // Then here we would switch on the dest/type:
  //   il.AddInstruction(Il.If( .. ));
  //   il.MarkLabel(jump_case);
  //   il.AddInstruction(Il.Jump(LLIL_TEMP(dest));
  //   il.MarkLabel(call_case);
  //   il.AddInstruction(Il.Call(LLIL_TEMP(dest));
  //   ..
  //
  // However, this implementation gave poor decompilation results.
  //
  // Instead, we have this more involved implementation for branch semantics.
  // We track whether a conditional jump is taken in a symbolic, LLIL_TEMP
  // register, unique for that instruction number (BRANCH_TAKEN_ARRAY+insn_num).
  // In case of an indirect branch (jumpr, callr), we also track branch
  // destination: the branch destination expression result is stored in a unique
  // LLIL_TEMP register.
  // Later, after all packet instructions have been processed, and clobbered
  // registers have been written back, we add Il.If statements that test each
  // conditional result (in order), and perform the branch. In some cases, we
  // use decoder's information to compute the branch destination.
  //
  // For example, the following packet has a conditional call, and an
  // unconditional jump:
  //
  //   { if (P0) call 0x104
  //     jump 0x108
  //     R1 = add(R1,R1) }
  //
  // Its LLIL representation is the following:
  //
  //   0: temp210.b = 0
  //   1: if (P0.d) then 2 else 4
  //   2: temp210.b = 1
  //   3: goto 4
  //   4: temp1.d = R1 + R1
  //   5: R1 = temp1.d
  //   6: if (temp210.b == 1) then 7 else 9
  //   7: call(0x104)
  //   8: goto 10
  //   9: jump(0x108 => 11 @ 0x108)
  //   10: <return> tailcall(0x104)
  //
  // temp210 is the BRANCH_TAKEN flag for instruction number 0 (cond call).
  // When the branch condition passes (line 2), BRANCH_TAKEN is set to 1.
  // Lines 4,5 write back all clobbered registers after all packet instructions
  // have been processed.
  // Line 6 tests the BRANCH_TAKEN flag for instruction 0. If passes, the
  // call on line 7 (branch type + dest received from decoder) is performed.
  // Note the 'goto 10' at line 8: this skips the second, direct jump in the
  // packet (like 9).
  //
  if (pkt.pkt_has_cof) {
    for (int i = 0; i < pkt.num_insns; i++) {
      const Insn &insn = pkt.insn[i];
      if (!insn.part1 && IsCondJump(insn) && !PlainLoopEnd(insn, pc)) {
        il.AddInstruction(
            il.SetRegister(1, BRANCH_TAKEN_ARRAY + i, il.Const(1, 0)));
      }
    }
  }

  // Process packet instructions, in order.
  auto ctx = absl::make_unique<PacketContext>(il);
  for (int i = 0; i < pkt.num_insns; i++) {
    const Insn &insn = pkt.insn[i];
    if (PlainLoopEnd(insn, pc)) {
      continue; // Lifted with the packet's branches.
    }
    RETURN_IF_ERROR(
        FillBnInstructionLowLevelImpl(arch, pc, pkt, insn, i, *ctx));
  }

  // Write back all clobbered registers. The context lives on for the
  // branches, which may test their conditions directly.
  ctx->WriteClobberedRegs();

  // Branch semantics. See comment above.
  if (pkt.pkt_has_cof) {
    LowLevelILLabel done;
    for (int i = 0; i < pkt.num_insns; i++) {
      const Insn &insn = pkt.insn[i];
      if (insn.part1) {
        continue;
      }
      if (const LoopStarts *loop = PlainLoopEnd(insn, pc)) {
        LiftPlainLoopEnd(arch, il, insn, *loop);
        continue;
      }
      if (IsJump(insn) || IsCall(insn)) {
        LowLevelILLabel branch_case, next_insn;
        if (IsCondJump(insn)) {
          // Test the branch's own condition when the packet left its inputs
          // unchanged; otherwise the flag the instruction set. (The flag's
          // code is then dead, and analysis drops it.)
          std::optional<ExprId> cond = ctx->StableBranchCondition(i);
          il.AddInstruction(il.If(
              cond ? *cond
                   : il.CompareEqual(1, il.Register(1, BRANCH_TAKEN_ARRAY + i),
                                     il.Const(1, 1)),
              branch_case, next_insn));
          il.MarkLabel(branch_case);
        }
        if (IsIndirect(insn) && IsJump(insn)) {
          const LoopStarts *loop =
              IsLoopEnd(insn) ? CurrentLoopStarts(pc) : nullptr;
          if (IsReturn(insn)) {
            il.AddInstruction(il.Return(il.Register(4, HEX_REG_LR)));
          } else if (loop != nullptr) {
            LiftLoopJump(il, insn, *loop, BRANCHR_DEST_ARRAY + i);
          } else {
            il.AddInstruction(il.Jump(il.Register(4, BRANCHR_DEST_ARRAY + i)));
          }
        } else if (IsIndirect(insn) && IsCall(insn)) {
          il.AddInstruction(il.Call(il.Register(4, BRANCHR_DEST_ARRAY + i)));
          // Skip other branches in the packet, and go to the next neighboring
          // packet.
          il.AddInstruction(il.Goto(done));
        } else if (IsJump(insn)) {
          // Go to the target's label when the function has one. A packet
          // with two jumps has two branch targets, and Binary Ninja gives a
          // constant jump of the packet both of them.
          const uint64_t target = pc + insn.immed[0];
          if (BNLowLevelILLabel *label = il.GetLabelForAddress(arch, target)) {
            il.AddInstruction(il.Goto(*label));
          } else {
            il.AddInstruction(il.Jump(il.ConstPointer(4, target)));
          }
        } else {
          if (!IsCall(insn)) {
            return absl::InternalError(
                StrCat("Unexpected branch opcode ", insn.opcode));
          }
          il.AddInstruction(
              il.Call(il.ConstPointer(4, pc + insn.immed[0])));
          // Skip other branches in the packet, and go to the next neighboring
          // packet.
          il.AddInstruction(il.Goto(done));
        }
        il.MarkLabel(next_insn);
      }
    }
    il.MarkLabel(done);
  }

  return absl::OkStatus();
}
