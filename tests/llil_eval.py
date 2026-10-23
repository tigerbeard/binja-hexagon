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
"""Evaluates a function's LLIL on concrete register values.

  regs = evaluate(func, {'R1': 10, 'R2': 32})

Values are unsigned integers of their expression's size. Shifts are
mathematical: shifting by the width or more gives 0 (or the sign, for an
arithmetic right shift). Evaluation stops at the first jump, return or call.
Intrinsics, unimplemented IL, reads of registers or temps that were never
written and loads from unmapped memory raise Unsupported, so lifting bugs of
that kind surface as errors.

Float operations are IEEE single or double precision by their size, rounding
to nearest even. A conversion of NaN, or of a float outside the integer's
(signed) range, to an integer raises Undefined: the IL does not say what it
gives, as C does not.
"""

import math
import struct

import binaryninja as binja

Op = binja.LowLevelILOperation


class Unsupported(Exception):
  pass


class Undefined(Exception):
  pass


def _mask(value, size):
  return value & ((1 << (8 * size)) - 1)


def _signed(value, size):
  value = _mask(value, size)
  return value - (1 << (8 * size)) if value >> (8 * size - 1) else value


def _rotate(value, left, size):
  bits = 8 * size
  return (value << left) | (value >> (bits - left)) if left else value


_BINARY = {
    Op.LLIL_ADD: lambda a, b, s: a + b,
    Op.LLIL_SUB: lambda a, b, s: a - b,
    Op.LLIL_MUL: lambda a, b, s: a * b,
    Op.LLIL_AND: lambda a, b, s: a & b,
    Op.LLIL_OR: lambda a, b, s: a | b,
    Op.LLIL_XOR: lambda a, b, s: a ^ b,
    Op.LLIL_LSL: lambda a, b, s: a << min(b, 8 * s),
    Op.LLIL_LSR: lambda a, b, s: a >> min(b, 8 * s),
    Op.LLIL_ASR: lambda a, b, s: _signed(a, s) >> min(b, 8 * s),
    Op.LLIL_ROL: lambda a, b, s: _rotate(a, b % (8 * s), s),
    Op.LLIL_ROR: lambda a, b, s: _rotate(a, -b % (8 * s), s),
}

def _to_float(bits, size):
  return struct.unpack('<f' if size == 4 else '<d',
                       _mask(bits, size).to_bytes(size, 'little'))[0]


def _from_float(value, size):
  """The bits of |value| rounded to a float of |size| bytes."""
  if size == 8:
    return int.from_bytes(struct.pack('<d', value), 'little')
  try:
    return int.from_bytes(struct.pack('<f', value), 'little')
  except OverflowError:  # Rounds to infinity.
    return 0x7f800000 | (0x80000000 if value < 0 else 0)


def _round_int(n, bits):
  """|n| rounded to |bits| significant bits, ties to even."""
  shift = abs(n).bit_length() - bits
  if shift <= 0:
    return n
  q, r = divmod(abs(n), 1 << shift)
  half = 1 << (shift - 1)
  if r > half or (r == half and q & 1):
    q += 1
  return (q << shift) * (-1 if n < 0 else 1)


def _divide(a, b):
  if b != 0:
    return a / b
  if a == 0 or math.isnan(a):
    return math.nan
  return math.copysign(math.inf, a) * math.copysign(1, b)


def _integral(value, rounding):
  if math.isinf(value) or math.isnan(value):
    return value
  return math.copysign(float(rounding(value)), value)


# On Python floats (doubles); a single-precision result is then rounded once,
# which is exact for these operations.
_FLOAT_BINARY = {
    Op.LLIL_FADD: lambda a, b: a + b,
    Op.LLIL_FSUB: lambda a, b: a - b,
    Op.LLIL_FMUL: lambda a, b: a * b,
    Op.LLIL_FDIV: _divide,
}

_FLOAT_COMPARE = {
    Op.LLIL_FCMP_E: lambda a, b: a == b,
    Op.LLIL_FCMP_NE: lambda a, b: a != b,
    Op.LLIL_FCMP_LT: lambda a, b: a < b,
    Op.LLIL_FCMP_LE: lambda a, b: a <= b,
    Op.LLIL_FCMP_GT: lambda a, b: a > b,
    Op.LLIL_FCMP_GE: lambda a, b: a >= b,
    Op.LLIL_FCMP_O: lambda a, b: not (math.isnan(a) or math.isnan(b)),
    Op.LLIL_FCMP_UO: lambda a, b: math.isnan(a) or math.isnan(b),
}

_COMPARE = {
    Op.LLIL_CMP_E: lambda a, b, s: a == b,
    Op.LLIL_CMP_NE: lambda a, b, s: a != b,
    Op.LLIL_CMP_ULT: lambda a, b, s: a < b,
    Op.LLIL_CMP_ULE: lambda a, b, s: a <= b,
    Op.LLIL_CMP_UGT: lambda a, b, s: a > b,
    Op.LLIL_CMP_UGE: lambda a, b, s: a >= b,
    Op.LLIL_CMP_SLT: lambda a, b, s: _signed(a, s) < _signed(b, s),
    Op.LLIL_CMP_SLE: lambda a, b, s: _signed(a, s) <= _signed(b, s),
    Op.LLIL_CMP_SGT: lambda a, b, s: _signed(a, s) > _signed(b, s),
    Op.LLIL_CMP_SGE: lambda a, b, s: _signed(a, s) >= _signed(b, s),
}


class _Machine:
  """Registers are kept by their full-width register, so that a write to
  P3:0 is seen in P0-P3 and the other way round; temps by name."""

  def __init__(self, arch, regs, memory):
    self.arch = arch
    self.full = {}
    self.memory = memory
    self.stores = []
    for name, value in regs.items():
      self.write(name, value, self._info(name)[2])

  def _info(self, name):
    """(full-width register, byte offset, size)."""
    info = self.arch.regs.get(name)
    if info is None:
      return name, 0, 8  # A temp.
    return info.full_width_reg, info.offset, info.size

  def read(self, reg, size):
    full, offset, _ = self._info(str(reg))
    if full not in self.full:
      raise Unsupported('read of unwritten ' + str(reg))
    return _mask(self.full[full] >> (8 * offset), size)

  def write(self, reg, value, size):
    full, offset, reg_size = self._info(str(reg))
    if full == str(reg) and full not in self.arch.regs:
      self.full[full] = _mask(value, size)  # A temp takes its write's size.
      return
    field = ((1 << (8 * reg_size)) - 1) << (8 * offset)
    old = self.full.get(full, 0) & ~field
    self.full[full] = old | ((_mask(value, reg_size) << (8 * offset)) & field)

  def regs(self):
    out = {}
    for name in self.arch.regs:
      full, _, size = self._info(name)
      if full in self.full:
        out[name] = self.read(name, size)
    return out

  def value(self, expr):
    op, size = expr.operation, expr.size
    if op in (Op.LLIL_CONST, Op.LLIL_CONST_PTR):
      return _mask(expr.constant, size)
    if op == Op.LLIL_REG:
      return self.read(expr.src, size)
    if op == Op.LLIL_REG_SPLIT:
      # The size is each half's.
      return (self.read(expr.hi, size) << (8 * size)) | self.read(
          expr.lo, size)
    if op in _BINARY:
      # The operands are read at the operation's size.
      left = _mask(self.value(expr.left), size)
      right = self.value(expr.right)
      return _mask(_BINARY[op](left, right, size), size)
    if op in _COMPARE:
      operand_size = expr.left.size
      return int(_COMPARE[op](_mask(self.value(expr.left), operand_size),
                              _mask(self.value(expr.right), operand_size),
                              operand_size))
    if op in _FLOAT_BINARY:
      left = _to_float(self.value(expr.left), size)
      right = _to_float(self.value(expr.right), size)
      return _from_float(_FLOAT_BINARY[op](left, right), size)
    if op in _FLOAT_COMPARE:
      operand_size = expr.left.size
      return int(_FLOAT_COMPARE[op](
          _to_float(self.value(expr.left), operand_size),
          _to_float(self.value(expr.right), operand_size)))
    if op in (Op.LLIL_FNEG, Op.LLIL_FABS):
      bits, sign = self.value(expr.src), 1 << (8 * size - 1)
      return bits ^ sign if op == Op.LLIL_FNEG else bits & ~sign
    if op == Op.LLIL_FLOAT_CONV:
      return _from_float(_to_float(self.value(expr.src), expr.src.size), size)
    if op == Op.LLIL_ROUND_TO_INT:
      return _from_float(
          _integral(_to_float(self.value(expr.src), size), round), size)
    if op == Op.LLIL_FTRUNC:
      return _from_float(
          _integral(_to_float(self.value(expr.src), size), math.trunc), size)
    if op == Op.LLIL_INT_TO_FLOAT:
      n = _signed(self.value(expr.src), expr.src.size)
      if size == 4:
        n = _round_int(n, 24)  # Exactly representable from here on.
      return _from_float(float(n), size)
    if op == Op.LLIL_FLOAT_TO_INT:
      value = _to_float(self.value(expr.src), expr.src.size)
      bits = 8 * size
      if math.isnan(value) or math.isinf(value) or not (
          -(1 << (bits - 1)) <= math.trunc(value) < (1 << (bits - 1))):
        raise Undefined('{} to a {}-byte integer'.format(value, size))
      return _mask(math.trunc(value), size)
    if op == Op.LLIL_NEG:
      return _mask(-self.value(expr.src), size)
    if op == Op.LLIL_NOT:
      return _mask(~self.value(expr.src), size)
    if op == Op.LLIL_SX:
      return _mask(_signed(self.value(expr.src), expr.src.size), size)
    if op == Op.LLIL_ZX:
      return _mask(self.value(expr.src), size)
    if op == Op.LLIL_LOW_PART:
      return _mask(self.value(expr.src), size)
    if op == Op.LLIL_BOOL_TO_INT:
      return int(self.value(expr.src) != 0)
    if op == Op.LLIL_LOAD:
      address = self.value(expr.src)
      try:
        data = bytes(self.memory[address + i] for i in range(size))
      except KeyError:
        raise Unsupported('load from unmapped {:#x}'.format(address))
      return int.from_bytes(data, 'little')
    raise Unsupported('expression {} ({})'.format(op.name, expr))

  def run(self, il):
    index, steps = 0, 0
    while True:
      steps += 1
      if steps > 10000:
        raise Unsupported('no end')
      insn = il[index]
      op = insn.operation
      index += 1
      if op == Op.LLIL_SET_REG:
        self.write(insn.dest, self.value(insn.src), insn.size)
      elif op == Op.LLIL_SET_REG_SPLIT:
        # The size is each half's.
        value = self.value(insn.src)
        self.write(insn.hi, value >> (8 * insn.size), insn.size)
        self.write(insn.lo, value, insn.size)
      elif op == Op.LLIL_STORE:
        value = self.value(insn.src)
        address = self.value(insn.dest)
        for i in range(insn.size):
          self.memory[address + i] = (value >> (8 * i)) & 0xff
        self.stores.append((address, insn.size))
      elif op == Op.LLIL_IF:
        index = insn.true if self.value(insn.condition) else insn.false
      elif op == Op.LLIL_GOTO:
        index = insn.dest
      elif op == Op.LLIL_NOP:
        pass
      elif op in (Op.LLIL_JUMP, Op.LLIL_JUMP_TO, Op.LLIL_RET, Op.LLIL_CALL,
                  Op.LLIL_TAILCALL, Op.LLIL_NORET, Op.LLIL_SYSCALL):
        return
      else:
        raise Unsupported('instruction {} ({})'.format(op.name, insn))


def evaluate(func, regs, memory=None, stores=None):
  """Runs |func|'s LLIL from its start on |regs| ({name: value}), and returns
  the registers after it. |memory| maps addresses to bytes (a load from an
  address it lacks raises Unsupported) and takes the stores; |stores|, a
  list, gets the (address, size) of each."""
  machine = _Machine(func.arch, regs, {} if memory is None else memory)
  machine.run(func.llil)
  if stores is not None:
    stores.extend(machine.stores)
  return machine.regs()
