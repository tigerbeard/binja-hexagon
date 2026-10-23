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

Run without arguments, every test runs in a fresh process: the plugin caches
decoded packets by address across views (#3), so snippets loaded at the same
address in one process would see each other's instructions.
"""

import os
import subprocess
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
    self.assertEqual(hexasm.disasm(f), '''
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


def run_isolated():
  """Runs every test in its own process and returns the exit status."""
  suite = unittest.defaultTestLoader.loadTestsFromModule(
      sys.modules[__name__])

  def ids(s):
    for t in s:
      yield from ids(t) if isinstance(t, unittest.TestSuite) else [t.id()]

  failed = []
  for test_id in ids(suite):
    name = test_id.split('.', 1)[1]
    result = subprocess.run([sys.executable, os.path.abspath(__file__), name],
                            capture_output=True,
                            text=True)
    if result.returncode != 0:
      status = 'FAILED'
    elif 'skipped=' in result.stderr:
      status = 'skipped'
    else:
      status = 'ok'
    print('{} ... {}'.format(name, status))
    if result.returncode != 0:
      failed.append(name)
      print(result.stderr)
  print('{} failed'.format(len(failed)) if failed else 'all passed')
  return 1 if failed else 0


if __name__ == '__main__':
  if len(sys.argv) > 1:
    unittest.main()
  else:
    sys.exit(run_isolated())
