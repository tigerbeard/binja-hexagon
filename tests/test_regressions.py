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
"""Regression tests: llvm-mc snippets analysed headless in Binary Ninja.

Each fix adds a test here that fails before the fix. A test for a bug that is
not fixed yet carries @unittest.expectedFailure and names its issue; the fix
removes the marker.
"""

import os
import re
import sys
import unittest

import hexasm

try:
  import binaryninja as binja
  sys.path.insert(
      0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..',
                      'test_binaries'))
  from il_test_util import check_environment
except ImportError:
  binja = None

REQUIREMENTS = 'needs the Binary Ninja Python API and llvm-mc with Hexagon'


@unittest.skipUnless(binja is not None and hexasm.have_llvm(), REQUIREMENTS)
class SnippetTest(unittest.TestCase):
  maxDiff = None

  @classmethod
  def setUpClass(cls):
    check_environment(binja)

  def analyse(self, source):
    """Assembles and loads `source`; returns {label: Function}."""
    snippet = hexasm.assemble(source)
    self.bv = hexasm.load(binja, snippet)
    self.addCleanup(self.bv.file.close)
    return {
        label: hexasm.function_at(self.bv, snippet, label)
        for label in snippet.symbols
    }


class TestHarness(SnippetTest):

  def test_simple_function(self):
    f = self.analyse('''
f:
  { r0 = add(r1, r2) }
  { jumpr r31 }
''')['f']
    self.assertEqual(hexasm.disasm(binja, f), '''
{ R0 = add(R1,R2) }
{ jumpr LR }''')
    self.assertEqual(
        hexasm.llil(f), '''
0: temp#0.d = R1 + R2
1: R0 = temp#0.d
2: temp#1.d = LR
3: <return> jump(LR)''')
    self.assertEqual(hexasm.hlil(f), '''
return arg2 + arg3''')


class TestFrameRegisterWrites(SnippetTest):
  # allocframe, deallocframe and dealloc_return write SP, FP and LR directly
  # rather than through PacketContext. That is safe while they are slot-0
  # instructions lifted after the rest of their packet; these tests keep it so.

  def test_reads_in_allocframe_packet_see_old_sp(self):
    f = self.analyse('''
f:
  { r2 = add(r29, #0); allocframe(#16) }
  { jumpr r31 }
''')['f']
    il = hexasm.llil(f)
    self.assertIn('0: temp#0.d = SP {arg_0}', il)
    self.assertLess(il.index('R2 = temp#0.d'), il.index('<return>'))
    self.assertLess(il.index('temp#0.d = SP {arg_0}'), il.index('SP = '))

  def test_store_in_allocframe_packet_uses_old_sp(self):
    f = self.analyse('''
f:
  { allocframe(#8); memw(r29+#0) = r0 }
  { dealloc_return }
''')['f']
    il = hexasm.llil(f).split('\n')
    self.assertEqual(il[1:3],
                     ['0: temp#0.d = SP {arg_0}', '1: [temp#0.d {arg_0}].d = R0'])


class TestPacketDecoding(SnippetTest):

  def test_views_at_same_address_show_their_own_bytes(self):
    # #3: decoded packets were cached by address across all views.
    first = self.analyse('''
f:
  { r0 = add(r1, r2) }
  { jumpr r31 }
''')['f']
    self.assertIn('R0 = add(R1,R2)', hexasm.disasm(binja, first))
    second = self.analyse('''
f:
  { r0 = sub(r1, r2) }
  { jumpr r31 }
''')['f']
    self.assertIn('R0 = sub(R1,R2)', hexasm.disasm(binja, second))

  def test_long_run_of_non_final_words_is_rejected(self):
    # #15: words whose parse bits say "not last" (01) were decoded without a
    # limit, overrunning the 7-entry instruction array of a packet.
    arch = binja.Architecture['hexagon']
    not_last = (0xf3014200).to_bytes(4, 'little')  # R0 = add(R1,R2), parse 01
    last = (0xf301c200).to_bytes(4, 'little')
    data = not_last * 9 + last
    self.assertIsNone(arch.get_instruction_info(data, 0))
    tokens, length = arch.get_instruction_text(data, 0) or ([], 0)
    self.assertEqual((tokens, length), ([], 0))
    il = binja.LowLevelILFunction(arch)
    self.assertFalse(arch.get_instruction_low_level_il(data, 0, il))



class TestDisassemblyText(SnippetTest):

  def test_manual_syntax(self):
    # #13: signed immediates printed as unsigned hex, pairs as R1:R0, and
    # C14-C19, C30, C31 without their names.
    f = self.analyse('''
f:
  { r0 = add(r1, #-16) }
  { r3:2 = combine(r0, r1) }
  { r5:4 = add(r3:2, r9:8) }
  { r0 = c14 }
  { r1 = c17 }
  { r2 = c18 }
  { r3 = c31 }
  { r0 = ##0x80000000 }
  { jumpr r31 }
''')['f']
    self.assertEqual(
        hexasm.disasm(binja, f), '''
{ R0 = add(R1,#-0x10) }
{ R3:2 = combine(R0,R1) }
{ R5:4 = add(R3:2,R9:8) }
{ R0 = UPCYCLELO }
{ R1 = FRAMEKEY }
{ R2 = PKTCOUNTLO }
{ R3 = UTIMERHI }
{ immext(#0x80000000)
R0 = ##0x80000000 }
{ jumpr LR }''')


class TestRegisterPairs(SnippetTest):

  def test_stored_pair_is_not_the_address(self):
    # #2: the source pair R1:0 and the effective address shared a temp, so
    # memd stored its own address.
    f = self.analyse('''
f:
  { memd(r29+#8) = r1:0 }
  { jumpr r31 }
''')['f']
    il = hexasm.llil(f)
    self.assertIn('0: temp#0.q = R1:R0', il)
    self.assertIn('1: temp#1.d = SP + 8', il)
    self.assertIn('2: [temp#1.d {arg_8}].q = temp#0.q', il)

  def test_accumulator_pair_is_eight_bytes(self):
    # #14: read-write pairs (Rxx) were read and written as 4 bytes.
    f = self.analyse('''
f:
  { r1:0 += mpy(r2, r3) }
  { jumpr r31 }
''')['f']
    self.assertIn('1: temp#0.q = temp#0.q + sx.q(R2) * sx.q(R3)',
                  hexasm.llil(f))

  def test_insert_source_pair_keeps_its_value(self):
    # #2: the source pair R5:4 shared a temp with insert's width.
    f = self.analyse('''
f:
  { r1:0 = insert(r5:4, #8, #4) }
  { jumpr r31 }
''')['f']
    il = hexasm.llil(f)
    self.assertIn('temp#1.q = R5:R4', il)
    self.assertIn('temp#2.q = 8', il)
    self.assertIn('(temp#1.q & ((sx.q(1) << temp#2.q) - 1))', il)

  def test_register_and_pair_in_one_packet_keep_separate_temps(self):
    # #2: R0 and R1:0 written in one packet shared a temp, and R1 was lost.
    f = self.analyse('''
f:
  { if (p0) r0 = #1; if (!p0) r1:0 = combine(r2, r3) }
  { jumpr r31 }
''')['f']
    il = hexasm.llil(f)
    self.assertRegex(il, r'R0 = temp#(\d+)\.d')
    self.assertRegex(il, r'R1:R0 = temp#(\d+)\.q')
    single = re.search(r'R0 = temp#(\d+)\.d', il).group(1)
    pair = re.search(r'R1:R0 = temp#(\d+)\.q', il).group(1)
    self.assertNotEqual(single, pair)


if __name__ == '__main__':
  unittest.main()
