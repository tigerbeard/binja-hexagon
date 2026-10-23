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
#include <optional>
#include <unordered_map>

#include "binaryninjaapi.h"

// Hardware loops.
//
// loopN (and spNloop0) sets the address where loop N's body starts. The loop
// ends at the first later packet whose parse bits mark endloopN (or
// endloop01), and that packet jumps back to the start while the loop count
// lasts. Neither packet says where the other is, so the instruction callbacks
// cannot find the jump back on their own. The loops are found by scanning a
// view's code once, and handed to the callbacks while Binary Ninja analyses
// or lifts a function on the same thread. Outside that (linear sweep,
// standalone disassembly) loop ends report no jump back.

// Loop body starts for a packet that ends loop 0, loop 1 or both.
struct LoopStarts {
  std::optional<uint64_t> loop0;
  std::optional<uint64_t> loop1;
  // Loop 0 was set up by spNloop0, a software-pipelined loop, which also
  // counts down USR.LPCFG and sets P3. loopN zeroes LPCFG.
  bool pipelined = false;
};

// Loop starts by the address of the packet that ends the loop.
using LoopMap = std::unordered_map<uint64_t, LoopStarts>;

// Finds the hardware loops in |len| bytes of code at address |base|.
LoopMap FindHardwareLoops(const uint8_t *code, size_t len, uint64_t base);

// The hardware loops in |view|'s executable code, found on first use.
const LoopMap &LoopsForView(BinaryNinja::BinaryView *view);

// Publishes |loops| to the instruction callbacks on this thread while it
// lives.
class ScopedLoops {
public:
  explicit ScopedLoops(const LoopMap *loops);
  ~ScopedLoops();
  ScopedLoops(const ScopedLoops &) = delete;
  ScopedLoops &operator=(const ScopedLoops &) = delete;

private:
  const LoopMap *prev_;
};

// The loop starts for the packet at |pc| if it ends a loop and the loops of
// the function being analysed are known, or nullptr.
const LoopStarts *CurrentLoopStarts(uint64_t pc);
