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

#include <cstdint>
#include <string>

#include "absl/strings/string_view.h"

// Instruction text tokenizer helpers.

// Returns register name for disassembly listing.
//  ('R', "", 10)  -> "R10"
//  ('R', "", 29)  -> "SP"
//  ('R', "L", 4)  -> "R4.L"
std::string GetRegisterName(absl::string_view reg_type,
                            absl::string_view hi_low_modifier, int regno);

// Returns a register pair's name as the manuals write it, from its low
// register.
//  ('R', 16) -> "R17:16"
//  ('C', 0)  -> "C1:0"
std::string GetRegisterPairName(absl::string_view reg_type, int regno);

// Returns the name of a register in the plugin's register numbering
// (hex_regs.h).
std::string GetArchRegisterName(uint32_t reg);

// Formats an immediate in hex. Signed immediates keep their sign:
//  (-16, true)  -> "-0x10"
//  (-16, false) -> "0xfffffff0"
std::string ImmediateHex(int32_t value, bool is_signed);
