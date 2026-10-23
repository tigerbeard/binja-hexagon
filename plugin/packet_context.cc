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

#include "plugin/packet_context.h"

#include "absl/memory/memory.h"
#include "plugin/hex_regs.h"
#include "third_party/qemu-hexagon/attribs.h"
#include "third_party/qemu-hexagon/iclass.h"
#include "third_party/qemu-hexagon/insn.h"
#include "third_party/qemu-hexagon/opcodes.h"

#include <cassert>

namespace {

using namespace BinaryNinja;

// The key of |reg|'s temp in |subspace|, in PacketContext::regs_.
int TempKey(int subspace, int reg) { return subspace * NUM_HEX_REGS + reg; }

std::unique_ptr<TempReg> MakeTempReg(bool rw, int size, int reg, int subspace,
                                     LowLevelILFunction &il) {
  if (rw) {
    return absl::make_unique<DestReadWriteReg>(size, reg, subspace, il);
  } else {
    return absl::make_unique<DestWriteOnlyReg>(size, reg, subspace);
  }
}

} // namespace

int MapRegNum(char regtype, int regno) {
  if (regtype == 'R' || regtype == 'N') {
    return HEX_REG_R00 + regno;
  }
  if (regtype == 'C') {
    return HEX_REG_C00 + regno;
  }
  if (regtype == 'P') {
    return HEX_REG_P0 + regno;
  }
  // The generated lifters only map these register types.
  LogError("Unknown regtype %d", static_cast<int>(regtype));
  assert(false);
  return -1;
}

void TempReg::CopyToTemp(BinaryNinja::LowLevelILFunction &il) {
  ExprId expr;
  if (size_ == 1) {
    expr = il.SetRegister(1, Reg(), il.Register(1, reg_));
  } else if (size_ == 4) {
    expr = il.SetRegister(4, Reg(), il.Register(4, reg_));
  } else {
    assert(size_ == 8);
    expr = il.SetRegister(8, Reg(), il.RegisterSplit(4, reg_ + 1, reg_));
  }
  il.AddInstruction(expr);
}

void TempReg::CopyFromTemp(BinaryNinja::LowLevelILFunction &il) {
  ExprId expr;
  if (size_ == 1) {
    expr = il.SetRegister(1, reg_, il.Register(1, Reg()));
  } else if (size_ == 4) {
    expr = il.SetRegister(4, reg_, il.Register(4, Reg()));
  } else {
    assert(size_ == 8);
    expr = il.SetRegisterSplit(4, reg_ + 1, reg_, il.Register(8, Reg()));
  }
  il.AddInstruction(expr);
}

PacketContext::PacketContext(BinaryNinja::LowLevelILFunction &il) : il_(il) {}

PacketContext::~PacketContext() {}

int PacketContext::AddDestWriteOnlyRegPair(int reg) {
  return AddDestReg(false, 8, reg);
}

int PacketContext::AddDestReadWriteRegPair(int reg) {
  return AddDestReg(true, 8, reg);
}
int PacketContext::AddDestWriteOnlyReg(int reg) {
  return AddDestReg(false, 4, reg);
}
int PacketContext::AddDestReadWriteReg(int reg) {
  return AddDestReg(true, 4, reg);
}
int PacketContext::AddDestWriteOnlyPredReg(int reg) {
  assert(reg >= HEX_REG_P0 && reg <= HEX_REG_P3);
  return AddDestReg(false, 1, reg);
}
int PacketContext::AddDestReadWritePredReg(int reg) {
  assert(reg >= HEX_REG_P0 && reg <= HEX_REG_P3);
  return AddDestReg(true, 1, reg);
}

int PacketContext::AddDestReg(bool rw, int size, int reg) {
  // Pairs have their own subspace, so a packet that writes both a register
  // and a pair containing it keeps two temps.
  const int subspace = size == 8 ? kDestPairSubspace : kSingleRegSubspace;
  const int key = TempKey(subspace, reg);
  auto it = regs_.find(key);
  if (it == regs_.end()) {
    it = regs_.emplace(key, MakeTempReg(rw, size, reg, subspace, il_)).first;
  }
  return it->second->Reg();
}

void PacketContext::WritePredicate(int temp, ExprId value) {
  if (!written_predicates_.insert(temp).second) {
    value = il_.And(1, il_.Register(1, temp), value);
  }
  il_.AddInstruction(il_.SetRegister(1, temp, value));
}

void PacketContext::WriteClobberedRegs() {
  // Single registers are written back before pairs. A packet may write a
  // register and a pair containing it only under complementary predicates;
  // then the pair's write-back wins, whichever instruction executed.
  for (auto &r : regs_) {
    r.second->CopyFromTemp(il_);
  }
}

void PacketContext::SetBranchCondition(int insn_num,
                                       std::function<ExprId()> condition,
                                       std::vector<int> reads) {
  branch_conditions_[insn_num] = {std::move(condition), std::move(reads)};
}

std::optional<ExprId> PacketContext::StableBranchCondition(int insn_num) {
  auto it = branch_conditions_.find(insn_num);
  if (it == branch_conditions_.end()) {
    return std::nullopt;
  }
  for (int reg : it->second.reads) {
    if (Writes(reg)) {
      return std::nullopt;
    }
  }
  return it->second.build();
}

bool PacketContext::Writes(int reg) const {
  // allocframe, deallocframe and dealloc_return write SP, FP and LR directly.
  if (reg == HEX_REG_SP || reg == HEX_REG_FP || reg == HEX_REG_LR) {
    return true;
  }
  if (regs_.count(TempKey(kSingleRegSubspace, reg))) {
    return true;
  }
  if (reg >= HEX_REG_P0 && reg <= HEX_REG_P3) {
    // The predicates are parts of C4 (P3:0).
    return regs_.count(TempKey(kSingleRegSubspace, HEX_REG_P3_0)) > 0;
  }
  if (reg == HEX_REG_P3_0) {
    for (int p = HEX_REG_P0; p <= HEX_REG_P3; p++) {
      if (regs_.count(TempKey(kSingleRegSubspace, p))) {
        return true;
      }
    }
    return false;
  }
  // A destination pair that contains the register.
  return regs_.count(TempKey(kDestPairSubspace, reg & ~1)) > 0;
}

size_t TempRegSize(uint32_t index) {
  if (index < kFixedTempBase) {
    switch (index / NUM_HEX_REGS) {
    case kSourcePairSubspace:
    case kDestPairSubspace:
      return 8;
    default: {
      const uint32_t reg = index % NUM_HEX_REGS;
      return (reg >= HEX_REG_P0 && reg <= HEX_REG_P3) ? 1 : 4;
    }
    }
  }
  if (index == static_cast<uint32_t>(LLIL_GET_TEMP_REG_INDEX(EA_REG))) {
    return 4;
  }
  if (index < kBranchDestBase) {
    return 8; // TMP_REG, WIDTH_REG, OFFSET_REG and SHAMT_REG.
  }
  if (index < kBranchTakenBase) {
    return 4;
  }
  return 1;
}
