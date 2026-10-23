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
"""Compares the plugin's decoder with llvm-objdump, word by word.

The two disassemblers spell instructions differently (register aliases, pair
syntax, hex or decimal immediates, `:raw` forms, duplex order), so they are
compared on a structural signature: whether the word decodes, the registers it
names and its immediates modulo 2^32.

  python llvm_diff.py 0x9201c800 0xa0a2c308 ...    compare these words
  python llvm_diff.py --patterns 'locked|_aq|_rl'  one word per matching
                                                   encoding in iset.py
"""

import argparse
import os
import random
import re
import subprocess
import sys
import tempfile

import hexasm

_REG_ALIASES = {'sp': 'r29', 'fp': 'r30', 'lr': 'r31'}
_PAIR = re.compile(r'\b([rcsgv])(\d+):(\d+)\b')
_REG = re.compile(r'\b(?:[rcpmsgvq]\d+|sp|fp|lr|pc|gp|usr|ugp)\b')
_INT = re.compile(r'(?<![\w.])-?(?:0x[0-9a-f]+|\d+)\b')


def signature(text):
  """Registers and immediates of an instruction text, order-independent."""
  if text is None:
    return None
  t = text.lower()
  # llvm-objdump annotates targets: `jump 0x9e0 <.text+0x9e0>`.
  t = re.sub(r'<[^>]*>', ' ', t)
  t = re.sub(r'\{|\}|:endloop\d+', ' ', t)
  t = _PAIR.sub(lambda m: '{0}{1} {0}{2}'.format(m.group(1), m.group(2),
                                                 m.group(3)), t)
  regs = sorted(_REG_ALIASES.get(r, r) for r in _REG.findall(t))
  stripped = _REG.sub(' ', t)
  ints = sorted(int(v, 0) % (1 << 32) for v in _INT.findall(stripped))
  return regs, ints


def llvm_disasm(words):
  """llvm-objdump's text for each word (None for an invalid encoding)."""
  source = ''.join('  .word 0x{:08x}\n'.format(w) for w in words)
  with tempfile.TemporaryDirectory() as tmp:
    asm, obj = os.path.join(tmp, 'a.s'), os.path.join(tmp, 'a.o')
    with open(asm, 'w') as f:
      f.write('\t.text\n' + source)
    subprocess.run([
        hexasm.llvm_tool('llvm-mc'), '-triple=hexagon', '-mcpu=' + hexasm.MCPU,
        '-mattr=' + hexasm.MATTR, '-filetype=obj', asm, '-o', obj
    ],
                   check=True,
                   capture_output=True)
    out = subprocess.run([
        hexasm.llvm_tool('llvm-objdump'), '-d', '--no-show-raw-insn',
        '--mcpu=' + hexasm.MCPU, '--mattr=' + hexasm.MATTR, obj
    ],
                         check=True,
                         capture_output=True,
                         text=True).stdout
  texts = {}
  for line in out.splitlines():
    m = re.match(r'\s*([0-9a-f]+):\s*(.*)$', line)
    if not m:
      continue
    offset, text = int(m.group(1), 16), m.group(2).strip()
    texts[offset // 4] = None if '<unknown>' in text else text
  return [texts.get(i) for i in range(len(words))]


def plugin_disasm(binja, words):
  """The plugin's text for each word (None if it does not decode)."""
  arch = binja.Architecture['hexagon']
  result = []
  for i, w in enumerate(words):
    # Each word sits at its offset in llvm_disasm's object, which matters for
    # PC-relative targets.
    tokens, length = arch.get_instruction_text(w.to_bytes(4, 'little'),
                                               4 * i) or ([], 0)
    result.append(''.join(str(t) for t in tokens) if length else None)
  return result


def compare(binja, words):
  """Returns [(word, plugin text, llvm text)] for words that differ."""
  diffs = []
  for w, mine, theirs in zip(words, plugin_disasm(binja, words),
                             llvm_disasm(words)):
    if theirs is None and mine is not None and '.new' in mine:
      # A new-value consumer alone in its packet has no producer, and LLVM
      # rejects it.
      continue
    if signature(mine) != signature(theirs):
      diffs.append((w, mine, theirs))
  return diffs


# Encoding letters of register fields (immediates use i and I).
REGISTER_FIELDS = 'stuvwxyzdef'

DEFAULT_ISET = os.environ.get(
    'HEXAGON_ISET',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'build',
                 'third_party', 'qemu-hexagon', 'iset.py'))


def pattern_words(regex, iset_path=DEFAULT_ISET, seed=0):
  """One word per 32-bit encoding whose tag matches |regex|.

  Encodings come from the build's iset.py, which has every encoding with its
  macros expanded. Operand fields get random bits (register fields even, as
  pairs require), don't-care bits are 0 and the parse bits end the packet.
  """
  namespace = {}
  with open(iset_path) as f:
    exec(f.read(), namespace)
  rng = random.Random(seed)
  words = []
  for tag, info in sorted(namespace['iset'].items()):
    bits = info['enc'].replace(' ', '')
    if not re.search(regex, tag) or len(bits) != 32 or 'PP' not in info['enc']:
      continue
    word = 0
    for i, b in enumerate(bits):
      bit = 31 - i
      if bit in (15, 14):
        v = 1
      elif b in '01':
        v = int(b)
      elif b == '-':
        v = 0
      elif b in REGISTER_FIELDS and (i == 31 or bits[i + 1] != b):
        v = 0
      else:
        v = rng.getrandbits(1)
      word |= v << bit
    words.append((tag, word))
  return words


def main():
  parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
  parser.add_argument('words', nargs='*', help='instruction words, in hex')
  parser.add_argument('--patterns', help='regex over instruction tags')
  parser.add_argument('--iset', default=DEFAULT_ISET,
                      help="the build's iset.py (default: %(default)s)")
  args = parser.parse_args()
  import binaryninja as binja  # noqa: E402

  if args.patterns:
    tagged = pattern_words(args.patterns, args.iset)
  else:
    tagged = [('', int(w, 16)) for w in args.words]
  tags = {w: t for t, w in tagged}
  diffs = compare(binja, [w for _, w in tagged])
  for w, mine, theirs in diffs:
    print('{:08x} {:24s} plugin: {}\n{:33s}llvm:   {}'.format(
        w, tags.get(w, ''), mine, '', theirs))
  print('{} of {} words differ'.format(len(diffs), len(tagged)))
  return 1 if diffs else 0


if __name__ == '__main__':
  sys.exit(main())
