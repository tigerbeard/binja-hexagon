#!/usr/bin/env python3
#
# Copyright (C) 2020 Google LLC
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

import unittest
import os
import sys

try:
  import binaryninja as binja
except ImportError:
  print('Failed to import binaryninja Python API.')
  print('Add ${BN_INSTALL_DIR}/python to PYTHONPATH.')
  sys.exit(1)

from il_test_util import check_environment, normalize_il


# E2E test for Hexagon hlil plugin.
# This test uses Binary Ninja headless API, analyses test_binaries/bn_hlil_test_app.s
# and checks the HLIL output.
class TestPluginIl(unittest.TestCase):
  TARGET_FILE = None

  @classmethod
  def setUpClass(cls):
    assert (cls.TARGET_FILE is not None)
    check_environment(binja)
    binja.log.log_to_stdout(True)
    cls.bv = binja.load(cls.TARGET_FILE)

  def get_function(self, name):
    return TestPluginIl.bv.get_functions_by_name(name)[0]

  def assertEqual(self, first, second, msg=None):
    # Listings compare after temp renaming and blank-line removal; see
    # il_test_util.normalize_il.
    if isinstance(first, str) and isinstance(second, str):
      first, second = normalize_il(first), normalize_il(second)
    super().assertEqual(first, second, msg)

  def list_hlil(self, func):
    ret = ['']
    for line in func.hlil.root.lines:
      ret.append('{0}'.format(line))
    return '\n'.join(ret)

  def test_add_int(self):
    func = self.get_function('test_add_int')
    self.assertEqual(
        self.list_hlil(func), '''
g_res = b + a''')

  def test_cmp_signed_int(self):
    func = self.get_function('test_cmp_signed_int')
    self.assertEqual(
        self.list_hlil(func), '''
bool temp90 = b s> a
int b_1 = b
if (temp90)
    b_1 = 0x8765
if (not.b(temp90))
    b_1 = 0x1234
g_res = b_1''')

  def test_cmp_unsigned_int(self):
    func = self.get_function('test_cmp_unsigned_int')
    self.assertEqual(
        self.list_hlil(func), '''
bool temp90 = b u> a
unsigned int b_1 = b
if (temp90)
    b_1 = 0x8765
if (not.b(temp90))
    b_1 = 0x1234
g_res = b_1''')

  def test_mul_int(self):
    func = self.get_function('test_mul_int')
    self.assertEqual(
        self.list_hlil(func), '''
g_res = b * a''')

  def test_func_call(self):
    func = self.get_function('test_func_call')
    self.assertEqual(
        self.list_hlil(func), '''
g_res = a(b)''')

  def test_struct(self):
    func = self.get_function('test_struct')
    self.assertEqual(
        self.list_hlil(func), '''
g_res = *(a + 8) + b''')

  def test_fact(self):
    func = self.get_function('test_fact')
    self.assertEqual(
        self.list_hlil(func), '''
char temp210 = 0
if (a != 0)
    temp210 = 1
int32_t result
if (temp210 == 1)
    result = test_fact(a - 1) * a
else
    result = 1
return result''')

  def test_and_int(self):
    func = self.get_function('test_and_int')
    self.assertEqual(
        self.list_hlil(func), '''
g_res = b & a''')

  def test_or_int(self):
    func = self.get_function('test_or_int')
    self.assertEqual(
        self.list_hlil(func), '''
g_res = b | a''')

  def test_xor_int(self):
    func = self.get_function('test_xor_int')
    self.assertEqual(
        self.list_hlil(func), '''
g_res = b ^ a''')

  def test_not_int(self):
    func = self.get_function('test_not_int')
    self.assertEqual(
        self.list_hlil(func), '''
g_res = 0xffffffff - a''')

  def test_collatz(self):
    func = self.get_function('test_collatz')
    self.assertEqual(
        self.list_hlil(func), '''
int a_1 = a
while (true)
    char temp210_1 = 0
    if (a_1 == 1)
        temp210_1 = 1
    if (temp210_1 == 1)
        break
    char temp210_2 = 0
    if ((a_1 & 1) != 0)
        temp210_2 = 1
    if (temp210_2 == 1)
        a_1 = 1 + a_1 * 3
    else
        a_1 s>>= 1''')

  def test_max_signed_int(self):
    func = self.get_function('test_max_signed_int')
    self.assertEqual(
        self.list_hlil(func), '''
g_res = (a s>= b ? 1 : 0) * a + (a s< b ? 1 : 0) * b''')

  def test_max_unsigned_int(self):
    func = self.get_function('test_max_unsigned_int')
    self.assertEqual(
        self.list_hlil(func), '''
g_res = (a u>= b ? 1 : 0) * a + (a u< b ? 1 : 0) * b''')

  def test_min_signed_int(self):
    func = self.get_function('test_min_signed_int')
    self.assertEqual(
        self.list_hlil(func), '''
g_res = (a s<= b ? 1 : 0) * a + (a s> b ? 1 : 0) * b''')

  def test_min_unsigned_int(self):
    func = self.get_function('test_min_unsigned_int')
    self.assertEqual(
        self.list_hlil(func), '''
g_res = (a u<= b ? 1 : 0) * a + (a u> b ? 1 : 0) * b''')


if __name__ == '__main__':
  TestPluginIl.TARGET_FILE = os.environ.get('TEST_TARGET_FILE')
  unittest.main()
