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
"""Compares the plugin's lifted IL with QEMU, instruction by instruction.

  python qemu_diff.py                    every lifted scalar ALU instruction
  python qemu_diff.py --tags 'S2_asl_r'  the lifted tags that match

Each instruction gets random encodings (iset.py, as llvm_diff.py) and random
register values. QEMU runs the instruction as a packet of its own; the
plugin's LLIL for the same packet runs in llil_eval. Registers r0-r31, p0-p3
and m0-m1 must agree afterwards, and so must the bytes the lifted IL stores.

Loads and stores address a data window that holds the same random bytes in
QEMU and in llil_eval: the base register (and GP) point into it, an index
register is a small multiple of 8, and m0/m1 hold small increments. Absolute addresses
(which need constant extenders), locked, circular and bit-reversed accesses
are left out, as are branches, system, HVX, new-value and duplex
instructions.

Predicates: the plugin writes compare results as 1 where the hardware writes
0xff, so a predicate matches when both are 0 or the plugin's is 1 and QEMU's
0xff. Inputs are 0 or 0xff. USR (the saturation flag) is not compared.
"""

import argparse
import collections
import os
import random
import re
import sys

import hexasm
import llil_eval
import llvm_diff
import qemu_oracle

HERE = os.path.dirname(os.path.abspath(__file__))
# Next to the build's iset.py.
OP_ATTRIBS = os.path.join(os.path.dirname(llvm_diff.DEFAULT_ISET),
                          'op_attribs_generated.h')
JUMPR_LR = 0x529fc000

# Attributes of instructions this comparison cannot run or does not model.
EXCLUDED_ATTRIBS = {
    'A_JUMP', 'A_CALL', 'A_COF', 'A_PRIV', 'A_GUEST', 'A_EXTENSION', 'A_CVI',
    'A_DOTNEWVALUE', 'A_SUBINSN', 'A_HWLOOP0_SETUP', 'A_HWLOOP1_SETUP',
    'A_HWLOOP0_END', 'A_HWLOOP1_END', 'A_IMPLICIT_WRITES_SP', 'A_FPOP',
}

# brkpt stops QEMU.
EXCLUDED_TAGS = {'Y2_break'}

MEMORY_ATTRIBS = {'A_LOAD', 'A_STORE', 'A_MEMLIKE', 'A_MEMLIKE_PACKET_RULES'}

# The data window for loads and stores.
DATA_BASE = 0x100000
DATA_SIZE = 0x80000
# A memory operand: mem*(Rs32+...), mem*(Rx32++...) or mem*(gp+...), and
# the index register of mem*(Rs32+Ru32<<#u2).
_MEMORY_OPERAND = re.compile(r'mem\w*\((?:(R[a-z]{1,2})32|gp)(?:\+\+|\+|\))')
_INDEX = re.compile(r'\+\s*R([a-z])32\s*<<')

QEMU_TO_BN = dict({'r%d' % i: 'R%d' % i for i in range(29)},
                  r29='SP', r30='FP', r31='LR', p0='P0', p1='P1', p2='P2',
                  p3='P3', m0='M0', m1='M1', usr='USR', gp='GP')
COMPARED = ['r%d' % i for i in range(32)] + ['p0', 'p1', 'p2', 'p3', 'm0',
                                               'm1']


def lifted_tags():
  sys.path.insert(0, os.path.join(HERE, '..', 'plugin'))
  from gen_il_funcs_data import SUPPORTED_TAGS  # noqa: E402
  return SUPPORTED_TAGS


def op_attribs(path=OP_ATTRIBS):
  with open(path) as f:
    return {
        tag: set(a.strip() for a in attribs.split(',') if a.strip())
        for tag, attribs in re.findall(
            r'OP_ATTRIB\((\w+),\s*ATTRIBS\(([^)]*)\)\)', f.read())
    }


def testable(tag, attribs, iset):
  info = iset.get(tag)
  if info is None or tag.startswith(('V6_', 'SA1_', 'SL1_', 'SL2_', 'SS1_',
                                     'SS2_')):
    return False
  enc = info['enc'].replace(' ', '')
  syntax = info['syntax']
  if attribs.get(tag, set()) & MEMORY_ATTRIBS and (
      not _MEMORY_OPERAND.search(syntax) or tag.startswith('Y') or
      re.search(r'locked|:circ|:brev|phys', syntax) or
      # V79 :nt stores, which QEMU's newest CPU (V73) does not have.
      ':nt' in syntax):
    return False
  return (len(enc) == 32 and 'PP' in info['enc'] and
          not attribs.get(tag, set()) & EXCLUDED_ATTRIBS and
          # New values need their producer in the packet.
          'N' not in re.findall(r'\b([A-Z])[a-z]{1,2}\d', syntax) and
          '.new' not in syntax and
          # Control registers include counters that change as QEMU runs.
          not re.search(r'\bC[st]{1,2}32', syntax) and tag not in EXCLUDED_TAGS)


def random_word(info, rng):
  """A random encoding: operand bits random, pair registers even, don't-care
  bits 0, parse bits ending the packet."""
  bits = info['enc'].replace(' ', '')
  pairs = set(m.group(1)[0] for m in re.finditer(
      r'\b[RC]([a-z])\1\d', info['syntax']))
  word = 0
  for i, b in enumerate(bits):
    bit = 31 - i
    if bit in (15, 14):
      v = 1
    elif b in '01':
      v = int(b)
    elif b == '-':
      v = 0
    elif b in pairs and (i == 31 or bits[i + 1] != b):
      v = 0  # Lowest bit of a pair's register field.
    else:
      v = rng.getrandbits(1)
    word |= v << bit
  return word


# Values at the edges of saturation, rounding and sign, which random values
# seldom reach.
EDGES = [0, 1, 0xffffffff, 0x7fff, 0x8000, 0xffff, 0xffff8000, 0x7fffffff,
         0x80000000, 0x80008000, 0x7fff7fff, 0x00010001]


def random_value(rng):
  return rng.choice(EDGES) if rng.random() < 0.25 else rng.getrandbits(32)


def random_regs(rng):
  regs = {'r%d' % i: random_value(rng) for i in range(32)}
  regs.update({'p%d' % i: rng.choice((0, 0xff)) for i in range(4)})
  regs.update(m0=rng.getrandbits(32), m1=rng.getrandbits(32), gp=DATA_BASE)
  return regs


def field(info, word, letter):
  """The value of |word|'s encoding field |letter|."""
  value = 0
  for i, b in enumerate(info['enc'].replace(' ', '')):
    if b == letter:
      value = (value << 1) | ((word >> (31 - i)) & 1)
  return value


def memory_case(info, rng):
  """A word and registers for a load or store: the base register points into
  the middle of the data window, an index register is small and m0/m1 hold
  small increments. None if base and index are one register."""
  word = random_word(info, rng)
  regs = random_regs(rng)
  base = _MEMORY_OPERAND.search(info['syntax']).group(1)
  index = _INDEX.search(info['syntax'])
  numbers = {}
  if base:
    numbers['base'] = field(info, word, base[1])
  if index:
    numbers['index'] = field(info, word, index.group(1))
  if len(set(numbers.values())) < len(numbers):
    return None
  if base:
    regs['r%d' % numbers['base']] = (DATA_BASE + DATA_SIZE // 2 +
                                      8 * rng.randrange(0x400))
  if index:
    # A multiple of 8 keeps any scaled address aligned, as accesses must be.
    regs['r%d' % numbers['index']] = 8 * rng.randrange(8)
  regs['m0'] = (8 * rng.randrange(-8, 8)) & 0xffffffff
  regs['m1'] = (8 * rng.randrange(-8, 8)) & 0xffffffff
  return word, regs


class WindowMemory(dict):
  """The data window's bytes, and the stores into it."""

  def __init__(self, data):
    super().__init__()
    self.data = data

  def __missing__(self, address):
    offset = address - DATA_BASE
    if 0 <= offset < len(self.data):
      return self.data[offset]
    raise KeyError(address)


def bn_regs(regs):
  out = {QEMU_TO_BN[k]: v for k, v in regs.items()}
  for name in ('SA0', 'LC0', 'SA1', 'LC1', 'USR', 'C5', 'UGP', 'GP', 'CS0',
               'CS1', 'LPCFG'):
    out.setdefault(name, 0)
  return out


def agree(name, bn, qemu):
  if bn == qemu:
    return True
  return name.startswith('p') and bn == 1 and qemu == 0xff


def compare(binja, cases):
  """Runs |cases| [(tag, word, regs)]; returns {tag: [mismatch text]}."""
  data = random.Random(1).randbytes(DATA_SIZE)
  code = b''.join(w.to_bytes(4, 'little') + JUMPR_LR.to_bytes(4, 'little')
                  for _, w, _ in cases)
  bv = hexasm.load(binja, hexasm.Snippet(
      code, {str(i): 8 * i for i in range(len(cases))}))
  problems = collections.defaultdict(list)
  try:
    with qemu_oracle.Qemu() as qemu:
      qemu.write_memory(DATA_BASE, data)
      for i, (tag, word, regs) in enumerate(cases):
        func = bv.get_function_at(8 * i)
        memory, stores = WindowMemory(data), []
        try:
          bn = llil_eval.evaluate(func, bn_regs(regs), memory, stores)
        except llil_eval.Unsupported as e:
          problems[tag].append('{:08x}: {}'.format(word, e))
          continue
        # At the plugin's address, for PC-relative instructions.
        hw = qemu.run(word.to_bytes(4, 'little'), regs, packets=1,
                      address=8 * i)
        diffs = [
            '{}: plugin {:#x} qemu {:#x}'.format(
                name, bn.get(QEMU_TO_BN[name], -1), hw[name])
            for name in COMPARED
            if not agree(name, bn.get(QEMU_TO_BN[name], -1), hw[name])
        ]
        for address, size in stores:
          mine = bytes(memory[address + j] for j in range(size))
          theirs = qemu.read_memory(address, size)
          if mine != theirs:
            diffs.append('mem[{:#x}]: plugin {} qemu {}'.format(
                address, mine.hex(), theirs.hex()))
          # Restore the window for the next case.
          offset = address - DATA_BASE
          if 0 <= offset and offset + size <= DATA_SIZE:
            qemu.write_memory(address, data[offset:offset + size])
        if diffs:
          inputs = ' '.join('{}={:#x}'.format(k, v) for k, v in regs.items()
                            if k in ('r%d' % n for n in range(32)) or
                            k.startswith(('p', 'm')))
          problems[tag].append('{:08x}: {}\n      inputs: {}'.format(
              word, '; '.join(diffs), inputs))
  finally:
    bv.file.close()
  return problems


def cases_for(tags, iset, samples, seed=0, attribs=None):
  rng = random.Random(seed)
  attribs = op_attribs() if attribs is None else attribs
  cases = []
  for tag in tags:
    for _ in range(samples):
      if attribs.get(tag, set()) & MEMORY_ATTRIBS:
        case = None
        while case is None:
          case = memory_case(iset[tag], rng)
        cases.append((tag,) + case)
      else:
        cases.append((tag, random_word(iset[tag], rng), random_regs(rng)))
  return cases


def main():
  parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
  parser.add_argument('--tags', default='.', help='regex over tags')
  parser.add_argument('--samples', type=int, default=4)
  parser.add_argument('--iset', default=llvm_diff.DEFAULT_ISET)
  args = parser.parse_args()
  import binaryninja as binja  # noqa: E402

  namespace = {}
  with open(args.iset) as f:
    exec(f.read(), namespace)
  iset = namespace['iset']
  attribs = op_attribs()
  tags = [t for t in lifted_tags()
          if re.search(args.tags, t) and testable(t, attribs, iset)]
  problems = compare(binja, cases_for(tags, iset, args.samples))
  for tag in sorted(problems):
    print('{} ({}):'.format(tag, iset[tag]['syntax']))
    for p in problems[tag][:2]:
      print('  ' + p)
  print('{} of {} instructions differ'.format(len(problems), len(tags)))
  return 1 if problems else 0


if __name__ == '__main__':
  sys.exit(main())
