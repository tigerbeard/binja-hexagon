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
"""

import binaryninja as binja

Op = binja.LowLevelILOperation


class Unsupported(Exception):
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
