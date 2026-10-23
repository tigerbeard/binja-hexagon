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

#include "plugin/insn_util.h"

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "glog/logging.h"
#include "plugin/status_macros.h"

// Defined in insn_text_funcs_generated.cc.
typedef void (*InsnTextFunc)(
    uint64_t pc, const Packet &pkt, const Insn &insn,
    std::vector<BinaryNinja::InstructionTextToken> &result);

extern const InsnTextFunc opcode_textptr[XX_LAST_OPCODE];

namespace {

using namespace BinaryNinja;
using absl::Hex;
using absl::StrCat;

int GetLastInsn(const Packet &pkt) {
  int last_insn = pkt.num_insns - 1;
  if (pkt.insn[last_insn].is_endloop) {
    last_insn--;
  }
  return last_insn;
}

void AppendInsnTextTokens(uint64_t pc, const Packet &pkt, const Insn &insn,
                          std::vector<InstructionTextToken> &result) {
  if (opcode_textptr[insn.opcode] == nullptr) {
    // Show the opcode name rather than losing the rest of the packet.
    result.emplace_back(InstructionToken, opcode_names[insn.opcode]);
    return;
  }
  opcode_textptr[insn.opcode](pc, pkt, insn, result);
}

} // namespace

bool IsSubInsn(const Insn &insn) { return GET_ATTRIB(insn.opcode, A_SUBINSN); }
bool IsJump(const Insn &insn) {
  return GET_ATTRIB(insn.opcode, A_JUMP) && insn.opcode != J4_hintjumpr;
}
bool IsCall(const Insn &insn) { return GET_ATTRIB(insn.opcode, A_CALL); }
bool IsIndirect(const Insn &insn) {
  return GET_ATTRIB(insn.opcode, A_INDIRECT) && insn.opcode != J4_hintjumpr;
}
bool IsCondJump(const Insn &insn) {
  return GET_ATTRIB(insn.opcode, A_BN_COND_J);
}
bool IsReturn(const Insn &insn) { return GET_ATTRIB(insn.opcode, A_BN_RETURN); }
bool IsSystem(const Insn &insn) { return GET_ATTRIB(insn.opcode, A_BN_SYSTEM); }

absl::Status FillBnInstructionInfo(uint64_t pc, const Packet &pkt,
                                   BinaryNinja::InstructionInfo &result) {
  if (pc & 3) {
    return absl::InvalidArgumentError(
        StrCat("Got unaligned packet address ", Hex(pc)));
  }
  result.length = pkt.encod_pkt_size_in_bytes;
  bool has_cj = false;
  bool has_ucj = false;
  for (int i = 0; i < pkt.num_insns; i++) {
    const Insn &insn = pkt.insn[i];
    has_cj |= IsJump(insn) && !IsIndirect(insn) && IsCondJump(insn);
    has_ucj |= IsJump(insn) && !IsIndirect(insn) && !IsCondJump(insn);
  }

  for (int i = 0; i < pkt.num_insns; i++) {
    const Insn &insn = pkt.insn[i];
    if (IsReturn(insn)) {
      if (IsCondJump(insn)) {
        // Skip, and do not annotate conditional returns.
      } else {
        result.AddBranch(FunctionReturn);
      }
    } else if (IsSystem(insn)) {
      if (IsCondJump(insn)) {
        // Skip, and do not annotate conditional, indirect jumps.
      } else {
        result.AddBranch(SystemCall);
      }
    } else if (IsJump(insn)) {
      if (IsIndirect(insn)) {
        if (IsCondJump(insn)) {
          // Skip, and do not annotate conditional, indirect jumps.
        } else {
          result.AddBranch(IndirectBranch);
        }
      } else if (IsCondJump(insn)) {
        result.AddBranch(TrueBranch, pc + insn.immed[0]);
        if (!has_ucj) {
          // Add implicit 'else' case.
          result.AddBranch(FalseBranch, pc + pkt.encod_pkt_size_in_bytes);
        }
      } else {
        auto type = UnconditionalBranch;
        if (has_cj) {
          // Add explicity 'else' case.
          type = FalseBranch;
        }
        result.AddBranch(type, pc + insn.immed[0]);
      }
    } else if (IsCall(insn)) {
      if (IsIndirect(insn)) {
        // Skip, and do not annotate indirect calls.
      } else {
        result.AddBranch(CallDestination, pc + insn.immed[0]);
      }
    }
  }
  return absl::OkStatus();
}

absl::Status
FillBnInstructionTextTokens(uint64_t pc, const Packet &pkt,
                            std::vector<BinaryNinja::InstructionTextToken> &result) {
  if (pc & 3) {
    return absl::InvalidArgumentError(
        StrCat("Got unaligned packet address ", Hex(pc)));
  }
  const int last_insn = GetLastInsn(pkt);
  uint64_t offset = 0;
  for (int i = 0; i <= last_insn; i++) {
    result.emplace_back(TextToken, i == 0 ? "{ " : "  ");
    AppendInsnTextTokens(pc, pkt, pkt.insn[i], result);
    if (IsSubInsn(pkt.insn[i]) && i < last_insn) {
      // The two sub-instructions of a duplex share one word and one line.
      result.emplace_back(TextToken, "; ");
      AppendInsnTextTokens(pc, pkt, pkt.insn[++i], result);
    }
    if (i == last_insn) {
      result.emplace_back(TextToken, " }");
      if (pkt.pkt_has_endloop) {
        switch (pkt.insn[last_insn + 1].opcode) {
        case J2_endloop0:
          result.emplace_back(TextToken, "  :endloop0");
          break;
        case J2_endloop1:
          result.emplace_back(TextToken, "  :endloop1");
          break;
        case J2_endloop01:
          result.emplace_back(TextToken, "  :endloop01");
          break;
        }
      }
    }
    // A NewLineToken's value is the offset of the line it ends, so each line
    // shows the address of its own word.
    result.emplace_back(NewLineToken, "", offset);
    offset += 4;
  }
  return absl::OkStatus();
}
