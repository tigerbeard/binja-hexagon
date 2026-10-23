/*
 * Copyright (C) 2020 Google LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#pragma once

#include <functional>
#include <map>
#include <optional>
#include <set>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/types/optional.h"
#include "binaryninjaapi.h"
#include "plugin/hex_regs.h"
#include "third_party/qemu-hexagon/insn.h"

// LLIL_TEMP register layout.
//
// Each packet register temp lives in one of three subspaces of NUM_HEX_REGS
// temps, indexed by HEX_REG number: single registers (including predicates),
// source register pairs, and destination register pairs. Pairs have their own
// subspaces so that a pair never shares a temp with one of its halves, or
// with a source pair read in the same packet. The generated lifters' fixed
// temps follow all three subspaces.
enum TempSubspace {
  kSingleRegSubspace = 0,
  kSourcePairSubspace = 1,
  kDestPairSubspace = 2,
  kNumTempSubspaces = 3,
};

constexpr int kFixedTempBase =
    static_cast<int>(kNumTempSubspaces) * static_cast<int>(NUM_HEX_REGS);

// Effective address, and the generated lifters' scratch values.
#define EA_REG LLIL_TEMP(kFixedTempBase + 0)
#define TMP_REG LLIL_TEMP(kFixedTempBase + 1)
#define WIDTH_REG LLIL_TEMP(kFixedTempBase + 2)
#define OFFSET_REG LLIL_TEMP(kFixedTempBase + 3)
#define SHAMT_REG LLIL_TEMP(kFixedTempBase + 4)
constexpr int kNumScratchTemps = 5;

// Holds indirect branch destinations, one per instruction in the packet.
constexpr int kBranchDestBase = kFixedTempBase + kNumScratchTemps;
#define BRANCHR_DEST_ARRAY LLIL_TEMP(kBranchDestBase)

// Holds conditional branch results, one per instruction in the packet.
constexpr int kBranchTakenBase = kBranchDestBase + INSTRUCTIONS_MAX;
#define BRANCH_TAKEN_ARRAY LLIL_TEMP(kBranchTakenBase)

constexpr int kNumTemps = kBranchTakenBase + INSTRUCTIONS_MAX;

static_assert(HEX_REG_USR_LPCFG < NUM_HEX_REGS,
              "every HEX_REG must fit in one temp subspace");

// Returns the size in bytes of the LLIL_TEMP register with |index|.
size_t TempRegSize(uint32_t index);

// Maps insn.regno and regtype ('R', 'P') from insn type
// to HEX_REG enum value:
//   MapRegNum('R', 1) ->  HEX_REG_R01
//   MapRegNum('R', 8) ->  HEX_REG_R08
//   MapRegNum('P', 0) ->  HEX_REG_P0
//   MapRegNum('P', 1) ->  HEX_REG_P1
int MapRegNum(char regtype, int regno);

// Temporary source/dest register.
// Maps HEX_REG register to LLIL_TEMP register space:
//   HEX_REG_R00 -> LLIL_TEMP(HEX_REG_R00).
class TempReg {
public:
  TempReg(int size, int reg, int ss) : size_(size), reg_(reg), subspace_(ss) {}
  virtual ~TempReg() = default;
  TempReg(const TempReg &) = delete;
  TempReg &operator=(const TempReg &) = delete;

  int Size() const { return size_; }

  // Returns the register index in the LLIL_TEMP register space.
  int Reg() const { return LLIL_TEMP(subspace_ * NUM_HEX_REGS + reg_); }

  // Adds an IL SetRegister expression that copies the original register
  // value to LLIL_TEMP register.
  void CopyToTemp(BinaryNinja::LowLevelILFunction &il);

  // Adds an IL SetRegister expression that copies the LLIL_TEMP register
  // value to the original register.
  void CopyFromTemp(BinaryNinja::LowLevelILFunction &il);

protected:
  const int size_;
  const int reg_;
  const int subspace_;
};

// Register value is copied on construction.
class SourceReg : public TempReg {
public:
  SourceReg(int size, int reg, int subspace,
            BinaryNinja::LowLevelILFunction &il)
      : TempReg(size, reg, subspace) {
    CopyToTemp(il);
  }
  ~SourceReg() override = default;
  SourceReg(const SourceReg &) = delete;
  SourceReg &operator=(const SourceReg &) = delete;
};

// Reads a register pair value on construction, into the source pair
// subspace, so it cannot collide with temps written in the packet.
class SourcePairReg : public TempReg {
public:
  SourcePairReg(int reg, BinaryNinja::LowLevelILFunction &il)
      : TempReg(/*size=*/8, reg, kSourcePairSubspace) {
    CopyToTemp(il);
  }
  ~SourcePairReg() override = default;
  SourcePairReg(const SourcePairReg &) = delete;
  SourcePairReg &operator=(const SourcePairReg &) = delete;
};

class DestWriteOnlyReg : public TempReg {
public:
  DestWriteOnlyReg(int size, int reg, int subspace)
      : TempReg(size, reg, subspace) {}
  ~DestWriteOnlyReg() override = default;
  DestWriteOnlyReg(const DestWriteOnlyReg &) = delete;
  DestWriteOnlyReg &operator=(const DestWriteOnlyReg &) = delete;
};

// Register value is copied on construction.
// LLIL_TEMP register value is copied back to normal register space
// when PacketContext.WriteClobberedRegs() is called.
class DestReadWriteReg : public SourceReg {
public:
  DestReadWriteReg(int size, int reg, int subspace,
                   BinaryNinja::LowLevelILFunction &il)
      : SourceReg(size, reg, subspace, il) {}
  ~DestReadWriteReg() override = default;
  DestReadWriteReg(const DestReadWriteReg &) = delete;
  DestReadWriteReg &operator=(const DestReadWriteReg &) = delete;
};

// Holds all temporary dest registers in the packet.
// Copies all dest registers back to original registers when
// WriteClobberedRegs() is called on packet destruction.
// Managing dest registers in LLIL_TEMP space helps implement the '.new'
// semantics.
class PacketContext {
public:
  PacketContext(BinaryNinja::LowLevelILFunction &il);
  ~PacketContext();
  PacketContext(const PacketContext &) = delete;
  PacketContext &operator=(const PacketContext &) = delete;

  BinaryNinja::LowLevelILFunction &IL() { return il_; }

  // Creates new DestReg and inserts it to |regs_| map if doesn't exist.
  // Returns the register index in the LLIL_TEMP register space.
  int AddDestWriteOnlyRegPair(int reg);
  int AddDestReadWriteRegPair(int reg);
  int AddDestWriteOnlyReg(int reg);
  int AddDestReadWriteReg(int reg);
  int AddDestWriteOnlyPredReg(int reg);
  int AddDestReadWritePredReg(int reg);

  // Writes |value| to the predicate temp |temp| (from AddDest*PredReg).
  // Several writes to one predicate in a packet are ANDed together, as the
  // hardware does.
  void WritePredicate(int temp, BinaryNinja::ExprId value);

  // Adds IL instructions that write back all clobbered registers.
  void WriteClobberedRegs();

  // Records how to rebuild instruction |insn_num|'s branch condition, and the
  // registers (HEX_REG numbers) the condition reads.
  void SetBranchCondition(int insn_num,
                          std::function<BinaryNinja::ExprId()> condition,
                          std::vector<int> reads);

  // Instruction |insn_num|'s branch condition, rebuilt for the end of the
  // packet, if the packet left the registers it reads unchanged. The branch
  // can then test it instead of a branch-taken flag.
  std::optional<BinaryNinja::ExprId> StableBranchCondition(int insn_num);

  // Whether the packet writes |reg| (a HEX_REG number).
  bool Writes(int reg) const;

private:
  int AddDestReg(bool rw, int size, int reg);

  BinaryNinja::LowLevelILFunction &il_;
  // Ordered by register, so write-back order is the same on every platform.
  std::map<int, std::unique_ptr<TempReg>> regs_;
  // Predicate temps written so far in the packet.
  std::set<int> written_predicates_;
  struct BranchCondition {
    std::function<BinaryNinja::ExprId()> build;
    std::vector<int> reads;
  };
  std::map<int, BranchCondition> branch_conditions_;
};
