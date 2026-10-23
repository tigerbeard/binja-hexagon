# Copyright (C) 2026 The binja-hexagon contributors
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""Assembles Hexagon snippets with LLVM and analyses them in Binary Ninja.

Snippets are assembled with llvm-mc into a relocatable object, and the raw
.text bytes are loaded into a Binary Ninja view at address 0. Nothing is
linked, so a snippet must not need relocations: use local labels (no .globl)
and no GP-relative or absolute symbol references. Instructions llvm-mc cannot
assemble go in as `.word` constants.
"""

import dataclasses
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..',
                    'test_binaries'))
from il_test_util import instruction_lines, normalize_il  # noqa: E402

LLVM_BIN = os.environ.get('HEXAGON_LLVM_BIN', '/opt/homebrew/opt/llvm/bin')
MCPU = 'hexagonv79'
MATTR = '+hvxv79,+hvx-length128b,+hvx-ieee-fp,+hvx-qfloat,+audio'


def llvm_tool(name):
  path = os.path.join(LLVM_BIN, name)
  return path if os.access(path, os.X_OK) else shutil.which(name)


def have_llvm():
  return all(llvm_tool(t) for t in ('llvm-mc', 'llvm-objcopy', 'llvm-readelf',
                                    'llvm-nm'))


@dataclasses.dataclass
class Snippet:
  code: bytes
  symbols: dict  # label -> offset in code


def assemble(source, mcpu=MCPU, mattr=MATTR):
  """Assembles `source` and returns its .text bytes and label offsets."""
  with tempfile.TemporaryDirectory() as tmp:
    asm, obj, text = (os.path.join(tmp, n) for n in ('a.s', 'a.o', 'a.bin'))
    with open(asm, 'w') as f:
      f.write('\t.text\n' + source + '\n')
    mc = subprocess.run([
        llvm_tool('llvm-mc'), '-triple=hexagon', '-mcpu=' + mcpu,
        '-mattr=' + mattr, '-filetype=obj', asm, '-o', obj
    ],
                        capture_output=True,
                        text=True)
    if mc.returncode != 0:
      raise ValueError('llvm-mc failed:\n' + mc.stderr)
    relocs = subprocess.run([llvm_tool('llvm-readelf'), '-r', obj],
                            check=True,
                            capture_output=True,
                            text=True).stdout
    if 'Relocation section' in relocs:
      raise ValueError('snippet needs relocations; use local labels only:\n' +
                       relocs)
    subprocess.run([
        llvm_tool('llvm-objcopy'), '-O', 'binary', '--only-section=.text', obj,
        text
    ],
                   check=True)
    with open(text, 'rb') as f:
      code = f.read()
    symbols = {}
    nm = subprocess.run([llvm_tool('llvm-nm'), obj],
                        check=True,
                        capture_output=True,
                        text=True).stdout
    for line in nm.splitlines():
      m = re.match(r'([0-9a-fA-F]+) [tT] (\S+)$', line)
      if m:
        symbols[m.group(2)] = int(m.group(1), 16)
    return Snippet(code, symbols)


def load(binja, snippet):
  """Loads a snippet at address 0 with a function at each label."""
  bv = binja.BinaryView.new(snippet.code)
  platform = binja.Architecture['hexagon'].standalone_platform
  bv.platform = platform
  for addr in sorted(set(snippet.symbols.values())):
    bv.add_function(addr, plat=platform)
  bv.update_analysis_and_wait()
  return bv


def function_at(bv, snippet, label):
  return bv.get_function_at(snippet.symbols[label])


def disasm(binja, func):
  """Disassembly, one line per instruction word, in address order."""
  lines = ['']
  for block in sorted(func.basic_blocks, key=lambda b: b.start):
    for tokens, _ in block:
      lines.extend(instruction_lines(binja, tokens))
  return '\n'.join(lines)


def llil(func):
  lines = ['']
  for block in func.llil:
    for insn in block:
      lines.append('{0}: {1}'.format(insn.instr_index, insn))
  return normalize_il('\n'.join(lines))


def hlil(func):
  return normalize_il('\n'.join([''] + [str(l) for l in func.hlil.root.lines]))
