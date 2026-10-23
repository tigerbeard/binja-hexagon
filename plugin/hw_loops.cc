// Copyright (C) 2026 The binja-hexagon contributors
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

#include "plugin/hw_loops.h"

#include <map>
#include <mutex>
#include <set>
#include <utility>
#include <vector>

#include "plugin/decoder.h"

using namespace BinaryNinja;

namespace {

// Longer "loops" are data that decodes as a loop setup.
constexpr uint64_t kMaxLoopBytes = 0x10000;

// The loop a setup instruction starts: 0, 1, or -1 for other instructions.
int LoopSetupNumber(uint16_t opcode) {
  switch (opcode) {
  case J2_loop0r:
  case J2_loop0i:
  case J2_ploop1sr:
  case J2_ploop1si:
  case J2_ploop2sr:
  case J2_ploop2si:
  case J2_ploop3sr:
  case J2_ploop3si:
    return 0;
  case J2_loop1r:
  case J2_loop1i:
    return 1;
  default:
    return -1;
  }
}

bool IsPipelinedLoopSetup(uint16_t opcode) {
  switch (opcode) {
  case J2_ploop1sr:
  case J2_ploop1si:
  case J2_ploop2sr:
  case J2_ploop2si:
  case J2_ploop3sr:
  case J2_ploop3si:
    return true;
  default:
    return false;
  }
}

thread_local const LoopMap *current_loops = nullptr;

} // namespace

LoopMap FindHardwareLoops(const uint8_t *code, size_t len, uint64_t base) {
  // Loop setups, and the packets that end each loop.
  struct Setup {
    int loop;
    uint64_t start;
    bool pipelined;
  };
  std::vector<Setup> setups;
  std::set<uint64_t> ends[2];
  size_t offset = 0;
  while (offset + 4 <= len) {
    auto pkt = Decoder::Get().DecodePacketAt(code + offset, len - offset);
    if (!pkt.ok()) {
      offset += 4;
      continue;
    }
    const uint64_t pc = base + offset;
    for (int i = 0; i < pkt->num_insns; i++) {
      const Insn &insn = pkt->insn[i];
      const int loop = LoopSetupNumber(insn.opcode);
      if (loop >= 0) {
        // The start is relative to the packet; immed[0] is #r7:2, in bytes.
        setups.push_back(
            {loop, pc + insn.immed[0], IsPipelinedLoopSetup(insn.opcode)});
      }
      if (insn.opcode == J2_endloop0 || insn.opcode == J2_endloop01) {
        ends[0].insert(pc);
      }
      if (insn.opcode == J2_endloop1 || insn.opcode == J2_endloop01) {
        ends[1].insert(pc);
      }
    }
    offset += pkt->encod_pkt_size_in_bytes;
  }

  LoopMap loops;
  for (const Setup &setup : setups) {
    auto end = ends[setup.loop].lower_bound(setup.start);
    if (end == ends[setup.loop].end() || *end - setup.start > kMaxLoopBytes) {
      continue;
    }
    LoopStarts &starts = loops[*end];
    std::optional<uint64_t> &slot =
        setup.loop == 0 ? starts.loop0 : starts.loop1;
    // Loops with one number do not nest, so of several setups ending at the
    // same packet the one whose start is nearest is the real loop.
    if (!slot || *slot < setup.start) {
      slot = setup.start;
      if (setup.loop == 0) {
        starts.pipelined = setup.pipelined;
      }
    } else if (*slot == setup.start && setup.pipelined) {
      // Entered by both loop0 and spNloop0: keep LPCFG semantics.
      starts.pipelined = true;
    }
  }
  return loops;
}

const LoopMap &LoopsForView(BinaryView *view) {
  static std::mutex mu;
  // Keyed by the view and its file session, so that a new view at a reused
  // address does not see another view's loops. Patching code does not update
  // the loops.
  static std::map<std::pair<BNBinaryView *, size_t>, LoopMap> loops_by_view;

  const auto key =
      std::make_pair(view->GetObject(), view->GetFile()->GetSessionId());
  std::lock_guard<std::mutex> lock(mu);
  auto it = loops_by_view.find(key);
  if (it != loops_by_view.end()) {
    return it->second;
  }

  LoopMap loops;
  auto scan = [&](uint64_t start, uint64_t length) {
    DataBuffer data = view->ReadBuffer(start, length);
    LoopMap found = FindHardwareLoops(
        static_cast<const uint8_t *>(data.GetData()), data.GetLength(), start);
    loops.insert(found.begin(), found.end());
  };
  const auto segments = view->GetSegments();
  for (const auto &segment : segments) {
    if (segment->GetFlags() & SegmentExecutable) {
      scan(segment->GetStart(), segment->GetLength());
    }
  }
  if (segments.empty()) {
    // A view without segments (a raw view): scan all of it.
    scan(view->GetStart(), view->GetLength());
  }
  return loops_by_view.emplace(key, std::move(loops)).first->second;
}

ScopedLoops::ScopedLoops(const LoopMap *loops) : prev_(current_loops) {
  current_loops = loops;
}

ScopedLoops::~ScopedLoops() { current_loops = prev_; }

const LoopStarts *CurrentLoopStarts(uint64_t pc) {
  if (current_loops == nullptr) {
    return nullptr;
  }
  auto it = current_loops->find(pc);
  return it == current_loops->end() ? nullptr : &it->second;
}
