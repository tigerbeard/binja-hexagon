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
import llvm_diff
import qemu_oracle

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
    self.assertIn('(temp#1.q & ((1 << temp#2.q) - 1))', il)

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


class TestPredicatedWrites(SnippetTest):
  # #20: a cancelled predicated instruction must leave its destination
  # unchanged; the destination used to be written back from an uninitialised
  # temp.

  def test_conditional_move(self):
    f = self.analyse('''
f:
  { p0 = cmp.eq(r0, #0) }
  { if (p0) r0 = #5 }
  { jumpr r31 }
''')['f']
    self.assertEqual(hexasm.hlil(f), '''
if (arg1 == 0)
    return 5
return arg1''')

  def test_conditional_add(self):
    f = self.analyse('''
f:
  { p0 = cmp.gt(r1, #3) }
  { if (!p0) r0 = add(r0, #1) }
  { jumpr r31 }
''')['f']
    self.assertEqual(hexasm.hlil(f), '''
if (arg2 s<= 3)
    return arg1 + 1
return arg1''')

  def test_conditional_load(self):
    f = self.analyse('''
f:
  { p0 = cmp.eq(r1, #0) }
  { if (!p0) r0 = memw(r1+#4) }
  { jumpr r31 }
''')['f']
    self.assertEqual(hexasm.hlil(f), '''
if (arg2 != 0)
    return *(arg2 + 4)
return arg1''')

  def test_conditional_pair_write_starts_from_old_value(self):
    f = self.analyse('''
f:
  { p0 = cmp.eq(r4, #0) }
  { if (p0) r1:0 = combine(r2, r3) }
  { jumpr r31 }
''')['f']
    il = hexasm.llil(f)
    copy_in = re.search(r'(temp#\d+)\.q = R1:R0', il)
    self.assertIsNotNone(copy_in)
    self.assertLess(il.index(copy_in.group(0)), il.index('if (P0)'))
    self.assertIn('R1:R0 = {}.q'.format(copy_in.group(1)), il)


class TestUnnamedRegisters(SnippetTest):

  def test_unnamed_system_registers_do_not_abort(self):
    # #4: naming S12-S15, S19 or S86-S127 called LOG(FATAL) and aborted
    # Binary Ninja. llvm-mc does not assemble these, so they are .words:
    # Y2_tfrscrr (Rd = Ss) and Y4_tfrscpp (Rdd = Sss), parse bits 11.
    f = self.analyse('''
f:
  .word 0x6e8cc000
  .word 0x6e93c000
  .word 0x6effc000
  .word 0x6f56c000
  { jumpr r31 }
''')['f']
    self.assertEqual(
        hexasm.disasm(binja, f), '''
{ R0 = S12 }
{ R0 = S19 }
{ R0 = S127 }
{ R1:0 = S87:86 }
{ jumpr LR }''')


class TestIntrinsics(SnippetTest):
  # #1: opcodes without lifted semantics were lifted as LLIL_UNDEF, which ends
  # the function's IL. They are intrinsics now.

  def test_unlifted_op_does_not_end_the_il(self):
    f = self.analyse('''
f:
  { r0 = cl0(r1) }
  { r0 = add(r0, #3) }
  { jumpr r31 }
''')['f']
    self.assertEqual(hexasm.hlil(f), '''
return S2_cl0(arg2) + 3''')

  def test_pair_output_is_eight_bytes(self):
    f = self.analyse('''
f:
  { r1:0 = tlbr(r2) }
  { memd(r29+#8) = r1:0 }
  { jumpr r31 }
''')['f']
    il = hexasm.llil(f)
    self.assertIn('0: temp#0 = Y2_tlbr(R2)', il)
    self.assertIn('1: R1:R0 = temp#0.q', il)
    self.assertIn('int64_t arg_8 = Y2_tlbr(arg3)', hexasm.hlil(f))

  def test_load_after_unlifted_store_is_not_folded(self):
    # dczeroa is a memory intrinsic, so the earlier store's value does not
    # reach the load.
    f = self.analyse('''
f:
  { memw(r0+#0) = r1 }
  { dczeroa(r0) }
  { r2 = memw(r0+#0) }
  { r0 = r2 }
  { jumpr r31 }
''')['f']
    self.assertEqual(hexasm.hlil(f), '''
*arg1 = arg2
Y2_dczeroa(arg1)
return *arg1''')

  def test_post_increment_load_writes_both_registers(self):
    f = self.analyse('''
f:
  { m0 = r3 }
  { r2 = memw(r0++m0) }
  { r0 = add(r0, r2) }
  { jumpr r31 }
''')['f']
    # Lifted since #48: the load reads the old base, which then advances.
    il = hexasm.llil(f)
    self.assertIn('3: temp#2.d = temp#1.d\n4: temp#1.d = temp#1.d + M0\n'
                  '5: temp#3.d = [temp#2.d].d\n6: R0 = temp#1.d\n'
                  '7: R2 = temp#3.d', il)

  def test_two_output_intrinsic_writes_both(self):
    f = self.analyse('''
f:
  { r0, p0 = sfrecipa(r1, r2) }
  { jumpr r31 }
''')['f']
    il = hexasm.llil(f)
    self.assertRegex(il, r'temp#\d+, temp#\d+ = F2_sfrecipa\(R1, R2\)')
    self.assertIn('R0 = ', il)
    self.assertIn('P0 = ', il)


class TestAcquireRelease(SnippetTest):
  # #8: the V67 LL/SC encodings left the bits that V71 uses for load-acquire,
  # store-release and release as don't-care, so those decoded as LL/SC.

  SOURCE = '''
f:
  { r0 = memw_aq(r1) }
  { r1:0 = memd_aq(r2) }
  { r0 = memw_locked(r1) }
  { r1:0 = memd_locked(r2) }
  { memw_rl(r2):at = r3 }
  { memw_rl(r2):st = r3 }
  { memd_rl(r2):at = r5:4 }
  { memd_rl(r2):st = r5:4 }
  { release(r2):at }
  { release(r2):st }
  { memw_locked(r2, p1) = r3 }
  { memd_locked(r2, p1) = r5:4 }
  .word 0xa800c0e3
  { jumpr r31 }
'''

  def test_decodes_v71_instructions(self):
    # 0xa800c0e3 is `R3 = dmsyncht` (V71 PRM p.299); llvm-mc lacks it.
    f = self.analyse(self.SOURCE)['f']
    self.assertEqual(
        hexasm.disasm(binja, f), '''
{ R0 = memw_aq(R1) }
{ R1:0 = memd_aq(R2) }
{ R0 = memw_locked(R1) }
{ R1:0 = memd_locked(R2) }
{ memw_rl(R2):at = R3 }
{ memw_rl(R2):st = R3 }
{ memd_rl(R2):at = R5:4 }
{ memd_rl(R2):st = R5:4 }
{ release(R2):at }
{ release(R2):st }
{ memw_locked(R2,P1) = R3 }
{ memd_locked(R2,P1) = R5:4 }
{ R3 = dmsyncht }
{ jumpr LR }''')

  def test_acquire_and_release_lift_as_loads_and_stores(self):
    il = hexasm.llil(self.analyse(self.SOURCE)['f'])
    self.assertIn('1: temp#1.d = [temp#0.d].d', il)
    self.assertIn('13: [temp#0.d].d = R3', il)
    self.assertIn('22: R6_release_at_vi(R2)', il)

  def test_matches_llvm_for_all_ll_sc_and_acquire_release_encodings(self):
    words = [w for tag, w in llvm_diff.pattern_words(
        r'locked|_aq$|_rl_|^R6_release|L4_loadw_phys|Y5_l2locka')]
    self.assertGreaterEqual(len(words), 13)
    self.assertEqual(llvm_diff.compare(binja, words), [])


class TestUpstreamInstructions(SnippetTest):
  # #41: instructions from QEMU's current definitions, V68 to V81. llvm-mc
  # lacks the V79 :nt stores and cache operations, so those are words from
  # the V79 PRM's encodings: memw(Rx++#s4:2):nt=Rt and dczeroa(Rs):nt.

  SOURCE = '''
f:
  { callrh r2 }
  { unpause }
  { pause(#1000) }
  { v0.qf32 = vadd(v1.sf, v2.sf) }
  { v3.qf16 = vabs(v4.hf) }
  { q0 = vcmp.eq(v1.sf, v2.sf) }
  { dmstart(r0) }
  { r5 = dmpoll }
  .word 0xaa84d400
  .word 0xa0cce000
  { jumprh r31 }
'''

  def test_decodes_upstream_instructions(self):
    f = self.analyse(self.SOURCE)['f']
    self.assertEqual(
        hexasm.disasm(binja, f), '''
{ callrh R2 }
{ unpause }
{ pause(#0x3e8) }
{ V0.qf32 = vadd(V1.sf,V2.sf) }
{ V3.qf16 = vabs(V4.hf) }
{ Q0 = vcmp.eq(V1.sf,V2.sf) }
{ dmstart(R0) }
{ R5 = dmpoll }
{ memw(R4++#0x0):nt = R20 }
{ dczeroa(R12):nt }
{ jumprh LR }''')

  def test_hinted_branches_and_nt_stores_lift_like_their_older_forms(self):
    il = hexasm.llil(self.analyse(self.SOURCE)['f'])
    # The call target is set before the call (it was an unset temp).
    self.assertIn('0: temp#0.d = R2\n1: call(temp#0.d)', il)
    self.assertRegex(il, r'\[temp#\d+\.d\]\.d = R20')
    self.assertIn('R4 = temp#2.d', il)
    self.assertTrue(il.endswith('<return> jump(LR)'), il)

  def test_matches_llvm_for_new_encodings(self):
    words = [w for tag, w in llvm_diff.pattern_words(
        r'_(qf16|qf32|hf|sf|bf)(_|$)|qfext|^V6_valign4$|^V6_vmerge_qf$|'
        r'_tmp$|^J2_(callrh|jumprh|unpause|pause)$|^Y2_tlbpp$|'
        r'^Y6_dm(start|link|poll|wait|pause|resume)$|^V6_v6mpy|'
        r'^V6_vasrvw?u|^V6_vmpyuhvs$')]
    self.assertGreaterEqual(len(words), 119)
    self.assertEqual(llvm_diff.compare(binja, words), [])

  def test_decodes_deprecated_encodings(self):
    # QEMU's legacy encodings, which the V79 PRM lists as :deprecated and
    # LLVM decodes from V5 to V81.
    f = self.analyse('''
f:
  .word 0xd597cc03
  .word 0xd59ad785
  .word 0xd405d218
  { jumpr r31 }
''')['f']
    self.assertEqual(
        hexasm.disasm(binja, f), '''
{ R3 = add(R23,R12):sat:deprecated }
{ R5 = sub(R23,R26):sat:deprecated }
{ R25:24 = packhl(R5,R18):deprecated }
{ jumpr LR }''')
    words = [w for tag, w in llvm_diff.pattern_words(r'_deprecated$')]
    self.assertEqual(len(words), 3)
    self.assertEqual(llvm_diff.compare(binja, words), [])


class TestQualcommInstructions(SnippetTest):
  # Instructions from Qualcomm's QEMU (hex-next) that LLVM lacks, as words
  # built from their encodings: V83 restricted-target branches and trap2, V83
  # vallocframe and vsfadd, V85 atomics and dcfetch_multi, HMX, and HLX. The
  # HLX packet stores the value its load produces (Ku16.new names it).

  SOURCE = '''
f:
  .word 0x7f80c000
  .word 0x9002e321
  .word 0x90c2e6c4
  .word 0xeb02c440
  .word 0x9401c880
  .word 0x9200c1e4
  .word 0x9202e3ef
  .word 0x9204c3fe
  .word 0xa6e5da10
  .word 0xa6e6c718
  .word 0xa6e0c013
  .word 0xe506e082
  .word 0x98005003
  .word 0xa485c002
  .word 0x6080c803
  .word 0x5022c000
  .word 0x54c0c014
  .word 0x521fc000
'''

  def test_decodes_qualcomm_instructions(self):
    f = self.analyse(self.SOURCE)['f']
    self.assertEqual(
        hexasm.disasm(binja, f), '''
{ nop_rb }
{ R1 = atomw_add(R2,R3):aq }
{ R5:4 = atomd_swap(R2,R7:6):rl }
{ R1:0 = vsfadd(R3:2,R5:4) }
{ dcfetch_multi(R1,R2) }
{ activation.hf = mxmem(R0,R1) }
{ weight.hf = mxmem(R2,R3) }
{ bias = mxmem2(R4) }
{ cvt.hf = acc(R5) }
{ mxmem(R6,R7) = cvt }
{ mxclracc.hf }
{ L1.h = mux(L1.h,L2.h,L3.h) }
{ L3.tmp = mem(R0)
mem(R5) = L3.new }
{ vallocframe(#0x3) }
{ callr_rb R2 }
{ trap2(#0x5) }
{ jumpr_rb LR }''')

  def test_restricted_branches_lift_like_their_older_forms(self):
    il = hexasm.llil(self.analyse(self.SOURCE)['f'])
    self.assertRegex(il, r'temp#(\d+)\.d = R2\n\d+: call\(temp#\1\.d\)')
    self.assertRegex(il, r'\d+: syscall')
    self.assertTrue(il.endswith('<return> jump(LR)'), il)

  def test_new_instructions_lift_as_intrinsics(self):
    il = hexasm.llil(self.analyse(self.SOURCE)['f'])
    for call in ('M8_mxmem_blk_sm_act_hf(R0, R1)', 'M8_mxclracc_hf()',
                 'LX_mux_h()', 'LX_S16b_new(R5)', 'V2_vallocframe_imm(3)'):
      self.assertIn(call, il)

  def test_atomics_lift_as_a_load_and_a_store(self):
    # The :aq and :rl ordering is not lifted.
    f = self.analyse('''
f:
  .word 0x9002e321
  .word 0x90c2e6c4
  { jumpr r31 }
''')['f']
    self.assertIn('''
0: temp#0.d = R2
1: temp#1.d = [temp#0.d].d
2: [temp#0.d].d = temp#1.d + R3
3: R1 = temp#1.d
4: temp#2.q = R7:R6
5: temp#0.d = R2
6: temp#3.q = [temp#0.d].q
7: [temp#0.d].q = temp#2.q
8: R5:R4 = temp#3.q''', hexasm.llil(f))
    self.assertTrue(hexasm.hlil(f).startswith('\n*arg3 += arg4'))

  def test_hlx_new_value_store_needs_a_producer(self):
    arch = binja.Architecture['hexagon']
    self.assertEqual(arch.get_instruction_text(
        (0xa485c002).to_bytes(4, 'little'), 0), ([], 0))

  def test_every_new_encoding_decodes_as_itself(self):
    # A word for each encoding LLVM lacks, with random fields, decodes to text
    # of its own syntax's shape. HLX new-value stores need a producer.
    def shape(text):
      text = re.sub(r'\b([RPLK][a-z]*\d+(:\d+)?|SP|FP|LR)\b', 'reg', text)
      text = re.sub(r'#+-?(0x[0-9a-f]+|\d+|[rRsSuUm]\d+(:\d+)?)', '#imm', text)
      return re.sub(r'[\s{}]', '', text)

    words = [(tag, w) for tag, w in llvm_diff.pattern_words(
        r'^(M8|LX)_|_rb$|^(AM|F7|V2)_|^J2_trap2$|^Y4_dcfetch_multi$',
        llvm_only=False) if not re.search(r'K\w*\.new', iset_syntax(tag))]
    self.assertGreaterEqual(len(words), 340)
    texts = llvm_diff.plugin_disasm(binja, [w for _, w in words])
    wrong = [(tag, hex(w), text) for (tag, w), text in zip(words, texts)
             if text is None or shape(text) != shape(iset_syntax(tag))]
    self.assertEqual(wrong, [])


class TestOverlayInstructions(SnippetTest):
  # #44: the HVX FP8 and vcvt2 instructions and memcpy, which hex-next lacks,
  # from the overlay of Qualcomm's ds_master definitions.

  def test_decodes_overlay_instructions(self):
    f = self.analyse('''
f:
  { v18.f8 = vabs(v10.f8) }
  { v13:12.hf = vadd(v12.f8,v12.f8) }
  { v31:30.hf += vmpy(v14.f8,v12.f8) }
  { v30.b = vcvt2(v28.hf,v20.hf) }
  { v9:8.hf = vcvt2(v16.ub) }
  { v10.f8 = v24.qf16 }
  { memcpy(r18,r26,m0) }
  { jumpr r31 }
''')['f']
    self.assertEqual(
        hexasm.disasm(binja, f), '''
{ V18.f8 = vabs(V10.f8) }
{ V13:12.hf = vadd(V12.f8,V12.f8) }
{ V31:30.hf += vmpy(V14.f8,V12.f8) }
{ V30.b = vcvt2(V28.hf,V20.hf) }
{ V9:8.hf = vcvt2(V16.ub) }
{ V10.f8 = V24.qf16 }
{ memcpy(R18,R26,M0) }
{ jumpr LR }''')
    self.assertIn('6: L6_memcpy(R18, R26, M0)', hexasm.llil(f))

  def test_matches_llvm_for_overlay_encodings(self):
    words = [w for tag, w in llvm_diff.pattern_words(
        r'_f8($|_)|vcvt2|^L6_memcpy$')]
    self.assertEqual(len(words), 17)
    self.assertEqual(llvm_diff.compare(binja, words), [])


def iset_syntax(tag, _iset={}):
  if not _iset:
    with open(llvm_diff.DEFAULT_ISET) as f:
      exec(f.read(), _iset)
  return _iset['iset'][tag]['syntax']


class TestOperatorPrecedence(SnippetTest):
  # #46: the semantics parser grouped binary operators to the right, so
  # add(Rs,sub(#s6,Ru)), whose semantics are Rs - Ru + s6, lifted as
  # Rs - (Ru + s6).

  def test_add_of_sub(self):
    f = self.analyse('''
f:
  { r0 = add(r1, sub(#5, r2)) }
  { jumpr r31 }
''')['f']
    self.assertIn('temp#0.d = R1 - R2 + 5', hexasm.llil(f))
    self.assertIn('return arg2 - arg3 + 5', hexasm.hlil(f))


def _sx(value, bits):
  value &= (1 << bits) - 1
  return value - (1 << bits) if value >> (bits - 1) else value


def _bidir_shift(value, amount, bits, left, arith):
  """QEMU's fBIDIR_{A,L}SHIFT{L,R}: a negative amount shifts the other way.
  32-bit registers shift as 64-bit values."""
  value = _sx(value, bits) if arith else value & ((1 << bits) - 1)
  amount = _sx(amount, 7)
  if amount < 0:
    left, amount = not left, -amount
  result = value << amount if left else value >> amount
  return result & ((1 << 64) - 1)


def _eval_hlil(expr):
  """Evaluates a 64-bit HLIL constant expression: Binary Ninja does not fold
  values written to register pairs. Fails on anything unexpected."""
  tokens = re.findall(r'0x[0-9a-f]+|\d+|u>>|s>>|<<|[-+&|^()]|(?:sx|zx|neg)\.q',
                      expr)
  if ''.join(tokens) != expr.replace(' ', ''):
    raise ValueError('cannot evaluate ' + expr)
  mask = (1 << 64) - 1
  binary = {'|': (1, lambda a, b: a | b), '^': (2, lambda a, b: a ^ b),
            '&': (3, lambda a, b: a & b),
            '<<': (4, lambda a, b: a << b),
            'u>>': (4, lambda a, b: a >> b),
            's>>': (4, lambda a, b: _sx(a, 64) >> b),
            '+': (5, lambda a, b: a + b), '-': (5, lambda a, b: a - b)}
  pos = 0

  def unary():
    nonlocal pos
    token = tokens[pos]
    pos += 1
    if token == '-':
      return -unary() & mask
    if token in ('sx.q', 'zx.q', 'neg.q', '('):
      if token != '(':
        assert tokens[pos] == '('
        pos += 1
      value = parse(0)
      assert tokens[pos] == ')'
      pos += 1
      return -value & mask if token == 'neg.q' else value
    return int(token, 0) & mask

  def parse(level):
    nonlocal pos
    value = unary()
    while pos < len(tokens) and tokens[pos] in binary:
      prec, fn = binary[tokens[pos]]
      if prec <= level:
        break
      pos += 1
      value = fn(value, parse(prec)) & mask
    return value

  value = parse(0)
  if pos != len(tokens):
    raise ValueError('cannot evaluate ' + expr)
  return value


class TestRegisterShifts(SnippetTest):
  # Phase 4: shifts by a register amount, which shift the other way when the
  # amount is negative, were intrinsics. The results are checked through
  # Binary Ninja's constant folding against QEMU's macros.

  RS, RSS = 0x87654321, 0x8000000112345678
  RX, RXX = 0x11111111, 0x0123456711111111
  OPS = {'asl': (True, True), 'asr': (False, True), 'lsl': (True, False),
         'lsr': (False, False)}
  ACCS = {'': lambda x, v: v, '+': lambda x, v: x + v, '-': lambda x, v: x - v,
          '&': lambda x, v: x & v, '|': lambda x, v: x | v,
          '^': lambda x, v: x ^ v}

  def cases(self):
    """(label, instruction, register to return, expected value)."""
    cases = []
    for op, (left, arith) in self.OPS.items():
      for amount in (4, -4, 0, 33, -33):
        value = _bidir_shift(self.RS, amount, 32, left, arith)
        cases.append(('{}_r_{}'.format(op, amount & 0x7f),
                      'r6 = {}(r2, r3)'.format(op), amount, 'r6', value))
      for amount in (4, -4, 63, -64):
        if op == 'asl' and amount == -64:
          # test_arithmetic_shift_right_by_64.
          continue
        value = _bidir_shift(self.RSS, amount, 64, left, arith)
        for half, reg in ((0, 'r6'), (32, 'r7')):
          cases.append(('{}_p_{}_{}'.format(op, amount & 0x7f, reg),
                        'r7:6 = {}(r5:4, r3)'.format(op), amount, reg,
                        value >> half))
      for acc, fn in self.ACCS.items():
        if not acc:
          continue
        if acc != '^':
          value = fn(self.RX, _bidir_shift(self.RS, -4, 32, left, arith))
          cases.append(('{}_r_acc{}'.format(op, ord(acc)),
                        'r6 {}= {}(r2, r3)'.format(acc, op), -4, 'r6',
                        value))
        value = fn(self.RXX, _bidir_shift(self.RSS, -4, 64, left, arith))
        for half, reg in ((0, 'r6'), (32, 'r7')):
          cases.append(('{}_p_acc{}_{}'.format(op, ord(acc), reg),
                        'r7:6 {}= {}(r5:4, r3)'.format(acc, op), -4, reg,
                        value >> half))
    return cases

  @staticmethod
  def returned_value(hlil):
    """The constant a function returns, from its HLIL, or the HLIL."""
    m = re.search(r'return (-?(?:0x[0-9a-f]+|\d+))\s*$', hlil)
    if m:
      return int(m.group(1), 0) & 0xffffffff
    # A register pair's value stays an expression: `hi:lo = ...`.
    pair = re.search(r'^(\w+):(\w+) = (.+)$', hlil, re.M)
    ret = re.search(r'return (\w+)\s*$', hlil)
    if pair and ret and ret.group(1) in pair.group(1, 2):
      value = _eval_hlil(pair.group(3))
      if ret.group(1) == pair.group(1):
        value >>= 32
      return value & 0xffffffff
    return hlil

  def test_values(self):
    cases = self.cases()
    source = ''
    for label, insn, amount, reg, _ in cases:
      source += '''
{}:
  {{ r2 = ##0x{:x} }}
  {{ r3 = #{} }}
  {{ r4 = ##0x{:x} }}
  {{ r5 = ##0x{:x} }}
  {{ r6 = ##0x{:x} }}
  {{ r7 = ##0x{:x} }}
  {{ {} }}
  {{ r0 = {} }}
  {{ jumpr r31 }}
'''.format(label, self.RS, amount, self.RSS & 0xffffffff, self.RSS >> 32,
           self.RX if insn.startswith('r6') else self.RXX & 0xffffffff,
           self.RXX >> 32, insn, reg)
    funcs = self.analyse(source)
    failures = []
    for label, insn, amount, reg, expected in cases:
      got = self.returned_value(hexasm.hlil(funcs[label]))
      if got != expected & 0xffffffff:
        failures.append('{} with {}: {} != {:#x}'.format(
            insn, amount, got if isinstance(got, str) else hex(got),
            expected & 0xffffffff))
    self.assertEqual(failures, [])
    self.assertGreater(len(cases), 100)


  def test_other_values(self):
    rs = self.RS
    bit = lambda n: _bidir_shift(1, n, 32, True, False)
    cases = []  # (setup, instruction, result register, expected)
    for n in (5, 31, 32, -1):
      setup = '{{ r2 = ##0x{:x} }}\n  {{ r3 = #{} }}'.format(rs, n)
      cases += [
          (setup, 'r6 = setbit(r2, r3)', 'r6', rs | bit(n)),
          (setup, 'r6 = clrbit(r2, r3)', 'r6', rs & ~bit(n)),
          (setup, 'r6 = togglebit(r2, r3)', 'r6', rs ^ bit(n)),
          # Predicates are checked for truth: the lifter writes compare
          # results as 1, where the hardware writes 0xff.
          (setup + '\n  { p0 = tstbit(r2, r3) }', 'r6 = p0', 'r6',
           rs & bit(n) != 0),
          (setup + '\n  { p0 = !tstbit(r2, r3) }', 'r6 = p0', 'r6',
           rs & bit(n) == 0),
      ]
    for n in (4, -1):
      cases.append(('{{ r3 = #{} }}'.format(n), 'r6 = lsl(#-3, r3)', 'r6',
                    _bidir_shift(-3, n, 32, True, False)))
    for u in (0, 4, 31):
      cases.append(('{{ r2 = ##0x{:x} }}'.format(rs),
                    'r6 = asr(r2, #{}):rnd'.format(u), 'r6',
                    ((_sx(rs, 32) >> u) + 1) >> 1))
    for half, reg in ((0, 'r6'), (32, 'r7')):
      cases.append(('{{ r2 = ##0x{:x} }}'.format(rs), 'r7:6 = sxtw(r2)', reg,
                    _sx(rs, 32) >> half))
    for p in (0, 0x10):
      cases.append(('{{ r3 = #{} }}\n  {{ p1 = r3 }}\n  {{ p0 = any8(p1) }}'.format(p),
                    'r6 = p0', 'r6', p != 0))
    source = ''
    for i, (setup, insn, reg, _) in enumerate(cases):
      source += '\nf{}:\n  {}\n  {{ {} }}\n  {{ r0 = {} }}\n  {{ jumpr r31 }}\n'.format(
          i, setup, insn, reg)
    funcs = self.analyse(source)
    failures = []
    for i, (setup, insn, reg, expected) in enumerate(cases):
      got = self.returned_value(hexasm.hlil(funcs['f{}'.format(i)]))
      if isinstance(expected, bool):
        ok = isinstance(got, int) and bool(got) == expected
      else:
        ok = got == expected & 0xffffffff
      if not ok:
        failures.append('{} after {}: {} != {}'.format(
            insn, setup.replace('\n  ', ' '), got, expected))
    self.assertEqual(failures, [])

  def test_arithmetic_shift_right_by_64(self):
    # asl by -64 shifts right by 64, as (x s>> 63) s>> 1. Binary Ninja 6.1
    # folds two constant arithmetic shifts into one shift by their sum and
    # takes 64 as 0, so its HLIL shows x unchanged; two immediate asr
    # instructions show the same. The lifted IL is right.
    f = self.analyse('''
f:
  { r3 = #-64 }
  { r7:6 = asl(r5:4, r3) }
  { jumpr r31 }
''')['f']
    il = hexasm.llil(f)
    self.assertRegex(il, r'temp#\d+\.q s>> \(neg\.q\(temp#\d+\.q\) - 1\) s>> 1')


class TestCallingConvention(SnippetTest):
  # #5: arguments R0-R8, no caller-saved registers, only FP and LR
  # callee-saved, and the callee popping stack arguments.

  def test_register_lists(self):
    cc = binja.Architecture['hexagon'].calling_conventions['regparam']
    self.assertEqual(cc.int_arg_regs, ['R0', 'R1', 'R2', 'R3', 'R4', 'R5'])
    self.assertEqual(cc.callee_saved_regs,
                     ['R{}'.format(n) for n in range(16, 28)] + ['FP'])
    caller_saved = set(cc.caller_saved_regs)
    self.assertTrue({'R{}'.format(n) for n in range(16)} <= caller_saved)
    self.assertTrue({'R28', 'LR', 'P3:0'} <= caller_saved)
    self.assertFalse(cc.stack_adjusted_on_return)

  def test_unknown_callee_clobbers_caller_saved_registers(self):
    # R16 survives the call; R2 does not.
    f = self.analyse('''
f:
  { r16 = #5; r2 = #7 }
  { callr r3 }
  { r0 = add(r16, r2) }
  { jumpr r31 }
''')['f']
    hlil = hexasm.hlil(f)
    self.assertNotIn('return 0xc', hlil)
    self.assertIn('return 5 + R2', hlil)

  def test_r6_is_not_an_argument(self):
    f = self.analyse('''
f:
  { r0 = add(r0, r6) }
  { jumpr r31 }
''')['f']
    # BN still sees R6 read, but outside the convention's argument list.
    self.assertIn('(int32_t arg1, int32_t arg2 @ R6)', str(f.type))


class TestReturns(SnippetTest):
  # #6: `jumpr r31` reported IndirectBranch, and conditional `jumpr r31`
  # lifted as an indirect jump through a temp.

  def test_jumpr_lr_is_a_function_return(self):
    arch = binja.Architecture['hexagon']
    word = hexasm.assemble('f:\n  { jumpr r31 }').code
    info = arch.get_instruction_info(word, 0)
    self.assertEqual([b.type for b in info.branches],
                     [binja.BranchType.FunctionReturn])

  def test_conditional_returns(self):
    funcs = self.analyse('''
old_predicate:
  { p0 = cmp.eq(r0, #0); r0 = #7 }
  { if (p0) jumpr r31 }
  { r0 = #1 }
  { jumpr r31 }
new_predicate:
  { p0 = cmp.gt(r0, #5); if (p0.new) jumpr:nt r31 }
  { r0 = add(r0, #1) }
  { jumpr r31 }
''')
    for f in funcs.values():
      il = hexasm.llil(f)
      self.assertEqual(il.count('<return> jump(LR)'), 2, il)
      self.assertNotRegex(il, r'jump\(temp')
    hlil = hexasm.hlil(funcs['old_predicate'])
    self.assertIn('return 7', hlil)
    self.assertIn('return 1', hlil)

  def test_conditional_dealloc_returns(self):
    # #40: predicated dealloc_return lifted as a jump through an unset temp.
    funcs = self.analyse('''
old_predicate:
  { allocframe(#8) }
  { p0 = cmp.eq(r0, #0); r0 = #7 }
  { if (p0) dealloc_return }
  { r0 = #1 }
  { dealloc_return }
new_predicate:
  { allocframe(#8) }
  { p0 = cmp.gt(r0, #5); if (p0.new) dealloc_return:nt }
  { r0 = add(r0, #1) }
  { dealloc_return }
''')
    for f in funcs.values():
      il = hexasm.llil(f)
      self.assertEqual(il.count('<return> jump(LR)'), 2, il)
      self.assertNotRegex(il, r'jump\(temp')
    hlil = hexasm.hlil(funcs['old_predicate'])
    self.assertIn('return 7', hlil)
    self.assertIn('return 1', hlil)


class TestHardwareLoops(SnippetTest):
  # #7: the packet that ends a hardware loop reported no branch back to the
  # loop's start, so loops decompiled as straight-line code with a
  # `jump(&data_...)` at the end.

  def test_counted_loop(self):
    f = self.analyse('''
f:
  { loop0(.Lbody, #10); r1 = #0 }
.Lbody:
  { r1 = add(r1, r0) }:endloop0
  { r0 = r1; jumpr r31 }
''')['f']
    self.assertEqual(hexasm.hlil(f), '''
int32_t LC0 = 0xa
int32_t result = 0
while (true)
    result += arg1
    if (LC0 s<= 1)
        break
    LC0 -= 1
return result''')

  def test_register_count(self):
    f = self.analyse('''
f:
  { loop0(.Lbody, r1); r2 = #0 }
.Lbody:
  { r2 = add(r2, r0) }:endloop0
  { r0 = r2; jumpr r31 }
''')['f']
    self.assertIn('int32_t LC0 = arg2', hexasm.hlil(f))
    self.assertIn('LC0 -= 1', hexasm.hlil(f))

  NESTED = '''
int32_t LC1 = 4
int32_t result = 0
while (true)
    int32_t LC0_1 = 3
    while (true)
        result += 1
        if (LC0_1 s<= 1)
            break
        LC0_1 -= 1{}
    if (LC1 s<= 1)
        break
    LC1 -= 1
return result'''

  def test_nested_loops(self):
    f = self.analyse('''
f:
  { loop1(.Louter, #4); r2 = #0 }
.Louter:
  { loop0(.Linner, #3) }
.Linner:
  { r2 = add(r2, #1) }:endloop0
  { r2 = add(r2, #10) }:endloop1
  { r0 = r2; jumpr r31 }
''')['f']
    self.assertEqual(hexasm.hlil(f),
                     self.NESTED.format('\n    result += 0xa'))

  def test_loops_ending_in_one_packet(self):
    f = self.analyse('''
f:
  { loop1(.Louter, #4); r2 = #0 }
.Louter:
  { loop0(.Linner, #3) }
.Linner:
  { r2 = add(r2, #1) }:endloop01
  { r0 = r2; jumpr r31 }
''')['f']
    self.assertEqual(hexasm.hlil(f), self.NESTED.format(''))

  def test_pipelined_loop_is_a_loop(self):
    # spNloop0 also counts down LPCFG; its loop end keeps the generic
    # endloop semantics.
    f = self.analyse('''
f:
  { p3 = sp1loop0(.Lbody, r1); r2 = #0 }
.Lbody:
  { r2 = add(r2, r0) }:endloop0
  { r0 = r2; jumpr r31 }
''')['f']
    hlil = hexasm.hlil(f)
    self.assertRegex(hlil, r'\bwhile\b')
    self.assertNotIn('jump(', hlil)


class TestPredicateAutoAnd(SnippetTest):
  # #9: several writes to one predicate in a packet are ANDed; the lifter
  # kept only the last.

  def test_two_compares_are_anded(self):
    f = self.analyse('''
f:
  { p0 = cmp.eq(r0, #0); p0 = cmp.eq(r1, #0) }
  { r0 = mux(p0, #1, #0) }
  { jumpr r31 }
''')['f']
    self.assertEqual(hexasm.hlil(f), '''
if (arg1 == 0 & arg2 == 0)
    return 1
return 0''')

  def test_new_value_reader_sees_the_and(self):
    f = self.analyse('''
f:
  { p0 = cmp.eq(r0, #0); p0 = cmp.eq(r1, #0); if (p0.new) r2 = #5 }
  { r0 = r2 }
  { jumpr r31 }
''')['f']
    self.assertIn('bool temp#0 = arg2 == 0 & arg1 == 0', hexasm.hlil(f))


class TestBranchConditions(SnippetTest):
  # #10: every conditional branch set a branch-taken flag and tested it at
  # the end of the packet, which HLIL kept (`temp210 = 1; if (temp210 == 1)`).

  def test_branch_tests_its_condition(self):
    f = self.analyse('''
f:
  { p0 = cmp.eq(r0, #0) }
  { r1 = add(r1, r1); if (p0) jump:t .Lone }
  { r0 = #0; jumpr r31 }
.Lone:
  { r0 = #1; jumpr r31 }
''')['f']
    self.assertEqual(hexasm.hlil(f), '''
if (arg1 == 0)
    return 1
return 0''')

  def test_flag_kept_when_packet_writes_the_condition(self):
    # The jump tests P0's old value, and the same packet writes P0.
    f = self.analyse('''
f:
  { p0 = cmp.eq(r1, #5) }
  { p0 = cmp.eq(r0, #0); if (p0) jump:t .Lone }
  { r0 = #0; jumpr r31 }
.Lone:
  { r0 = #1; jumpr r31 }
''')['f']
    self.assertRegex(hexasm.llil(f), r'if \(temp#\d+\.b == 1\)')
    # The branch follows P0's old value, arg2 == 5, through the flag.
    hlil = hexasm.hlil(f)
    self.assertIn('if (arg2 == 5)', hlil)
    self.assertNotIn('arg1 == 0', hlil)


class TestFrames(SnippetTest):
  # #11: the LR:FP save of allocframe stayed in HLIL (Binary Ninja 3.x); and
  # the duplex deallocframe/dealloc_return wrote 8-byte values into LR and FP.

  def test_frame_save_is_hidden(self):
    funcs = self.analyse('''
leaf:
  { allocframe(#8) }
  { r0 = #256 }
  { dealloc_return }
dealloc_then_return:
  { allocframe(#16) }
  { r0 = #1 }
  { deallocframe }
  { jumpr r31 }
''')
    self.assertEqual(hexasm.hlil(funcs['leaf']), '\nreturn 0x100')
    self.assertEqual(hexasm.hlil(funcs['dealloc_then_return']), '\nreturn 1')

  def test_duplex_dealloc_writes_four_byte_registers(self):
    f = self.analyse('''
f:
  { allocframe(#8) }
  { r0 = #1 }
  { r17:16 = memd(r29+#0); dealloc_return }
''')['f']
    il = hexasm.llil(f)
    self.assertRegex(il, r'LR = \(.*\)\.d')
    self.assertNotRegex(il, r'(LR|FP) = sx\.q')


class TestPartialWrites(SnippetTest):
  # #31: combine and other instructions that build a write-only destination
  # in parts read its uninitialised temp, which HLIL kept as a variable.

  def test_combine_has_no_uninitialised_temp(self):
    f = self.analyse('''
f:
  { r17:16 = combine(r1, r0) }
  { r0 = add(r16, r17) }
  { jumpr r31 }
''')['f']
    hlil = hexasm.hlil(f)
    self.assertNotIn('temp#', hlil)
    self.assertNotIn('0xffffffff00000000', hlil)


@unittest.skipUnless(qemu_oracle.available(), 'needs qemu-system-hexagon')
class TestFloatingPoint(SnippetTest):
  # #48: scalar floating point lifts to float IL, which Binary Ninja types as
  # float and double. Conversions to an integer round to nearest, or toward
  # zero with :chop, before FloatToInt.

  SOURCE = '''
f:
  { r2 = sfmpy(r0, r1) }
  { r3:2 = convert_sf2df(r2) }
  { r5:4 = dfadd(r3:2, r3:2) }
  { p0 = dfcmp.gt(r5:4, r3:2) }
  { r0 = convert_df2sf(r5:4) }
  { r1 = convert_sf2uw(r0):chop }
  { r6 = convert_w2sf(r1) }
  { if (p0) r0 = add(r6, #0) }
  { jumpr r31 }
'''

  def test_lifts_to_float_il(self):
    il = hexasm.llil(self.analyse(self.SOURCE)['f'])
    for line in ('0: temp#0.d = R0 f* R1',
                 '2: temp#1.q = fconvert.d(R2)',
                 '6: temp#3.q = temp#2.q f+ temp#2.q',
                 '10: temp#5.b = temp#4.q f> temp#2.q',
                 '13: temp#6.d = fconvert.s(temp#4.q)',
                 '15: temp#7.d = (int.q(ftrunc.s(R0))).d',
                 '17: temp#8.d = float.s(R1)'):
      self.assertIn(line, il)

  def test_decompiles_with_float_types(self):
    self.assertEqual(
        hexasm.hlil(self.analyse(self.SOURCE)['f']), '''
int32_t R2
int32_t R3
R3:R2 = fconvert.d(arg1 * arg2)
double temp#0 = R3:R2
int32_t R4
int32_t R5
R5:R4 = temp#0 + temp#0
float result = fconvert.s(R5:R4)
if (R5:R4 > R3:R2)
    return float.s((int.q(ftrunc.s(result))).d)
return result''')


class TestDspInstructions(SnippetTest):
  # #48: vector word compares (fSETBITS), rounding, carries, clipping and
  # dfmake. The carry is the full adder's, from the operands' and the sum's
  # top bits, with the carry-in predicate's low bit.

  SOURCE = '''
f:
  { p0 = vcmpw.eq(r1:0, r3:2) }
  { r4 = round(r5, #4) }
  { r1:0 = add(r3:2, r5:4, p1):carry }
  { r6 = clip(r7, #7) }
  { r11:10 = dfmake(#1):pos }
  { jumpr r31 }
'''

  def test_lifts_dsp_instructions(self):
    il = hexasm.llil(self.analyse(self.SOURCE)['f'])
    for text in (
        'temp#0.b = (temp#0.b & 0xf0) | (neg.b(sx.q(temp#1.q.d) == '
        'sx.q(temp#2.q.d) ? 1 : 0) & 0xf)',
        'temp#3.d = ((sx.q(R5) + sx.q(1 << (4 - 1))) s>> 4).d',
        'temp#6.q = temp#2.q + temp#4.q + sx.q(zx.d(temp#5.b & 1))',
        'temp#5.b = ((temp#2.q & temp#4.q) | ((temp#2.q | temp#4.q) & '
        'not.q(temp#2.q + temp#4.q + sx.q(zx.d(temp#5.b & 1))))) u>> 0x3f != 0',
        'temp#8.q = temp#8.q + (1 << 0x2e)'):
      self.assertIn(text, il)
    self.assertNotIn('A4_addp_c', il)
    self.assertNotIn('A7_clip', il)


class TestQemuCases(SnippetTest):
  # The cases qemu_diff.py runs: only instructions QEMU's CPU has, and no
  # words that write one register twice (undefined; QEMU 11.1 keeps the
  # loaded value of r9 = memb(r9++#1), Qualcomm's QEMU the address).

  def setUp(self):
    import qemu_diff
    self.qemu_diff = qemu_diff
    namespace = {}
    with open(llvm_diff.DEFAULT_ISET) as f:
      exec(f.read(), namespace)
    self.iset = namespace['iset']

  def test_words_that_write_a_register_twice(self):
    writes_twice = self.qemu_diff.writes_a_register_twice
    load, pair_load = self.iset['L2_loadri_pi'], self.iset['L2_loadrd_pi']
    self.assertTrue(writes_twice(load, 0x9b89c029))  # r9 = memw(r9++#4)
    self.assertFalse(writes_twice(load, 0x9b89c02a))  # r10 = memw(r9++#4)
    self.assertTrue(writes_twice(pair_load, 0x9bc5c024))  # r5:4, r5++
    self.assertFalse(writes_twice(pair_load, 0x9bc6c024))  # r5:4, r6++
    self.assertFalse(writes_twice(self.iset['A2_add'], 0xf301c101))

  def test_instructions_newer_than_the_cpu_are_left_out(self):
    attribs = self.qemu_diff.op_attribs()
    testable = self.qemu_diff.testable
    self.assertFalse(testable('S2_storeri_pi_nt', attribs, self.iset, 73))
    self.assertTrue(testable('S2_storeri_pi_nt', attribs, self.iset, 79))
    self.assertFalse(testable('A2_nop_rb', attribs, self.iset, 81))
    self.assertTrue(testable('A2_nop_rb', attribs, self.iset, 85))


class TestAgainstQemu(SnippetTest):
  # Every lifted instruction that qemu_diff.py can run on QEMU's CPU (no
  # branches, system or HVX instructions) agrees with QEMU on random
  # encodings and registers. This found lifts that a 32-bit literal or mask broke:
  # mpy(Rs,Rt):rnd, extract(u) on pairs and vspliceb.

  def test_lifted_instructions_match_qemu(self):
    import qemu_diff
    namespace = {}
    with open(llvm_diff.DEFAULT_ISET) as f:
      exec(f.read(), namespace)
    iset = namespace['iset']
    attribs = qemu_diff.op_attribs()
    tags = [t for t in qemu_diff.lifted_tags()
            if qemu_diff.testable(t, attribs, iset)]
    self.assertGreater(len(tags), 900)
    problems = qemu_diff.compare(binja, qemu_diff.cases_for(tags, iset, 4))
    self.assertEqual(
        {tag: texts[0] for tag, texts in problems.items()}, {})


if __name__ == '__main__':
  unittest.main()
