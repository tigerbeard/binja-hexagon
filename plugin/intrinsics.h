/*
 * Copyright (C) 2026 The binja-hexagon contributors
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

#include <cstdint>

#include "third_party/qemu-hexagon/opcodes.h"

// Opcodes without lifted semantics are lifted as Binary Ninja intrinsics,
// whose id is the opcode. Their inputs are the instruction's source registers
// and immediates, and their outputs its destination registers, so that data
// flow through the instruction is right even though its operation is opaque.

// One operand of an intrinsic: its name in the instruction syntax (Rs, Rdd,
// #s8) and its size in bytes.
struct IntrinsicOperand {
  const char *name;
  uint8_t size;
};

constexpr int kMaxIntrinsicInputs = 12;
constexpr int kMaxIntrinsicOutputs = 6;

struct IntrinsicInfo {
  // The opcode is lifted as an intrinsic.
  bool valid;
  // The instruction loads or stores memory.
  bool memory;
  uint8_t num_inputs;
  uint8_t num_outputs;
  IntrinsicOperand inputs[kMaxIntrinsicInputs];
  IntrinsicOperand outputs[kMaxIntrinsicOutputs];
};

// Defined in il_funcs_generated.cc, indexed by opcode.
extern const IntrinsicInfo opcode_intrinsics[XX_LAST_OPCODE];
