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

#include "absl/status/status.h"
#include "binaryninjaapi.h"
#include "plugin/decoder.h"

// Prepares packet for il lifting by removing no-op extender instructions,
// moving dotnew instructions to the end and splitting cmpjump instructions.
// Exported for testing.
Packet PreparePacketForLifting(const Packet &src);

// Lifts the whole packet at |pc|, which is one Binary Ninja instruction.
absl::Status FillBnInstructionLowLevelIL(BinaryNinja::Architecture *arch,
                                         uint64_t pc, const Packet &src,
                                         BinaryNinja::LowLevelILFunction &il);
