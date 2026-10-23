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

import copy
import sys
import re
import string
import itertools
from io import StringIO
from typing import Union

from lark import Lark, Transformer, Tree, v_args, Token
from pcpp import Preprocessor

from hex_common import *
from type_util import *
from gen_il_funcs_data import *

# Following grammar is based on the C grammar copied from
# https://www2.cs.arizona.edu/~debray/Teaching/CSc453/DOCS/cminusminusspec.html
semantics_grammar = r"""

fbody: stmt* -> fbody

?stmt: "if" "(" expr ")" stmt [ "else" stmt ] -> if_stmt
     | logor_e "?" "(" assg ")" ":" "(" assg ")" -> ternary_stmt
     | "while" "(" expr ")" stmt
     | "for" "(" [ assg ] ";" [ expr ] ";" [ assg ] ")" stmt
     | "return" [ expr ] ";"
     | assg ";" -> assg_stmt
     | id ASSGOP expr ";" -> assg_binop_stmt
     | id "(" [expr ("," expr)* ] ")" ";" -> call_stmt
     | "{" stmt* "}" -> multi_stmt
     | ";" -> empty_stmt
     | "CANCEL;" -> cancel_stmt

?assg: id "=" expr

// Expressions, from the loosest binding to the tightest, as in C. Binary
// operators group left to right.
?expr: ternary_e

?ternary_e: logor_e
          | logor_e "?" expr ":" ternary_e -> ternary_expr

?logor_e: logand_e
        | logor_e LOGOR logand_e -> expr_logop

?logand_e: bitor_e
         | logand_e LOGAND bitor_e -> expr_logop

?bitor_e: bitxor_e
        | bitor_e BITOR bitxor_e -> expr_binop

?bitxor_e: bitand_e
         | bitxor_e BITXOR bitand_e -> expr_binop

?bitand_e: eq_e
         | bitand_e BITAND eq_e -> expr_binop

?eq_e: rel_e
     | eq_e EQOP rel_e -> expr_relop

?rel_e: shift_e
      | rel_e RELOP shift_e -> expr_relop

?shift_e: add_e
        | shift_e SHIFTOP add_e -> expr_binop

?add_e: mul_e
      | add_e ADDOP mul_e -> expr_binop

?mul_e: unary_e
      | mul_e MULOP unary_e -> expr_binop

?unary_e: primary_e
        | "(" CTYPE ")" unary_e -> cast_expr
        | "-" unary_e -> neg_expr
        | "!" unary_e -> not_expr
        | "~" unary_e -> bit_not_expr

?primary_e: id
          | id "(" [expr ("," expr)* ] ")" -> call_expr
          | id "[" expr "]" -> unexpected
          | "(" expr ")"
          | INTCON
          | STRINGCON

ASSGOP.4: "+="
     |    "-="
     |    "&="
     |    "^="
     |    "|="

LOGOR.3: "||"
LOGAND.3: "&&"
SHIFTOP.3: "<<" | ">>"
EQOP.3: "==" | "!="
RELOP.2: "<=" | ">=" | "<" | ">"
BITOR.1: "|"
BITXOR.1: "^"
BITAND.1: "&"
ADDOP.1: "+" | "-"
MULOP.1: "*" | "/"

?id: REG_OLD | REG_NEW | REG_LR | IMM | MACRO | EA | SIGN | BRANCH_TYPE | TMP
    | LOCAL
REG_OLD: REG "V"
REG_NEW: REG "N"
REG: REG_TYPE REG_ID
REG_TYPE: "C" | "N" | "P" | "R" | "M" | "Q" | "V" | "O"
REG_ID: DST_REG | DST_REG_PAIR | SRC_REG | SRC_REG_PAIR | RX_REG | RX_REG_PAIR
DST_REG: "d" | "e"
DST_REG_PAIR: "dd"
SRC_REG: "s" | "t" | "u" | "v" | "w"
SRC_REG_PAIR: "ss" | "tt" | "uu" | "vv"
RX_REG: "x" | "y"
RX_REG_PAIR: "xx" | "yy"
REG_LR: "REG_LR"
IMM: IMMLETT "iV"
IMMLETT: "r" | "R" | "s" | "S" | "u" | "U" | "m"
// QEMU's macros, and the C functions its floating-point semantics call.
MACRO: /f\w+|conv_\w+|isunordered/
EA: "EA"
SIGN: "s" | "u"
BRANCH_TYPE: /COF_TYPE_\w+/
TMP: "tmp" | "width" | "offset" | "shamt"
LOCAL: /local_\w+/
CTYPE: /unsigned\s+long\s+long|unsigned\s+int|long\s+long|unsigned|int(?!\w)|size[1248][su]_t|u?int(8|16|32|64)_t/

INTCON: HEX_NUMBER | DEC_NUMBER
HEX_NUMBER: /0x[\da-f]*/i
DEC_NUMBER: /0|[1-9][\d_]*/i
STRINGCON: ESCAPED_STRING

%import common.ESCAPED_STRING
%import common.INT
%import common.WS
%ignore WS
"""

# The semantics' temporaries (tmp, width, offset, shamt), as 8-byte temps.
TEMP_REGS = ('TMP_REG', 'WIDTH_REG', 'OFFSET_REG', 'SHAMT_REG')

BINOP_TERMINALS = ('BITOR', 'BITXOR', 'BITAND', 'SHIFTOP', 'ADDOP', 'MULOP')

semantics_parser = Lark(
    semantics_grammar,
    start='fbody',
    parser='lalr',
    debug=True,
    propagate_positions=False,
    maybe_placeholders=False)

#
# Following classes map to Binary Ninja ExprId.
#


class IlExprId:
  # Whether the value is a float or double (fFLOAT, fDOUBLE), which makes C
  # operators lift to float IL.
  is_float = False

  def __init__(self, signed=True):
    self.signed = signed


class IlSetRegister(IlExprId):

  @type_check
  def __init__(self, size: int, reg: str, val: IlExprId):
    super().__init__(signed=val.signed)
    self.size, self.reg, self.val = size, reg, val

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.reg == other.reg and
            self.val == other.val)

  def __repr__(self):
    return '''il.SetRegister({0}, {1}, {2})'''.format(self.size, self.reg,
                                                      self.val)


class IlRegister(IlExprId):

  @type_check
  def __init__(self, size: int, reg: str):
    super().__init__()
    self.size, self.reg = size, reg

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.reg == other.reg)

  def __repr__(self):
    return '''il.Register({0}, {1})'''.format(self.size, self.reg)


class IlSetRegisterSplit(IlExprId):

  @type_check
  def __init__(self, size: int, hi: str, lo: str, val: IlExprId):
    super().__init__(signed=val.signed)
    self.size, self.hi, self.lo, self.val = size, hi, lo, val

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.hi == other.hi and
            self.lo == other.lo and self.val == other.val)

  def __repr__(self):
    return '''il.SetRegisterSplit({0}, {1}, {2}, {3})'''.format(
        self.size, self.hi, self.lo, self.val)


class IlRegisterSplit(IlExprId):

  @type_check
  def __init__(self, size: int, hi: str, lo: str):
    super().__init__()
    self.size, self.hi, self.lo = size, hi, lo

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.hi == other.hi and
            self.lo == other.lo)

  def __repr__(self):
    return '''il.RegisterSplit({0}, {1}, {2})'''.format(self.size, self.hi,
                                                        self.lo)


class IlConst(IlExprId):

  @type_check
  def __init__(self, size: int, val: Union[int, str]):
    super().__init__()
    self.size, self.val = size, val
    self.val = str(self.val) if isinstance(self.val, int) else self.val

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.val == other.val)

  def __repr__(self):
    return '''il.Const({0}, {1})'''.format(self.size, self.val)


class IlConstPointer(IlExprId):

  @type_check
  def __init__(self, size: int, val: str):
    super().__init__(signed=False)
    self.size, self.val = size, val

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.val == other.val)

  def __repr__(self):
    return '''il.ConstPointer({0}, {1})'''.format(self.size, self.val)


class IlLowPart(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId):
    super().__init__(signed=a.signed)
    self.size, self.a = size, a

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a)

  def __repr__(self):
    return '''il.LowPart({0}, {1})'''.format(self.size, self.a)


class IlZeroExtend(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId):
    super().__init__(signed=False)
    self.size, self.a = size, a

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a)

  def __repr__(self):
    return '''il.ZeroExtend({0}, {1})'''.format(self.size, self.a)


class IlSignExtend(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId):
    super().__init__(signed=True)
    self.size, self.a = size, a

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a)

  def __repr__(self):
    return '''il.SignExtend({0}, {1})'''.format(self.size, self.a)


class IlAdd(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=a.signed)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.Add({0}, {1}, {2})'''.format(self.size, self.a, self.b)


class IlSub(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=a.signed)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.Sub({0}, {1}, {2})'''.format(self.size, self.a, self.b)


class IlOr(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=False)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.Or({0}, {1}, {2})'''.format(self.size, self.a, self.b)


class IlAnd(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=False)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.And({0}, {1}, {2})'''.format(self.size, self.a, self.b)


class IlXor(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=False)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.Xor({0}, {1}, {2})'''.format(self.size, self.a, self.b)


class IlNot(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId):
    super().__init__(signed=False)
    self.size, self.a = size, a

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a)

  def __repr__(self):
    return '''il.Not({0}, {1})'''.format(self.size, self.a)


class IlNeg(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId):
    super().__init__(signed=False)
    self.size, self.a = size, a

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a)

  def __repr__(self):
    return '''il.Neg({0}, {1})'''.format(self.size, self.a)


class IlStore(IlExprId):

  @type_check
  def __init__(self, size: int, addr: IlExprId, val: IlExprId):
    super().__init__(signed=val.signed)
    self.size, self.addr, self.val = size, addr, val

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.addr == other.addr and
            self.val == other.val)

  def __repr__(self):
    return '''il.Store({0}, {1}, {2})'''.format(self.size, self.addr, self.val)


class IlLoad(IlExprId):

  @type_check
  def __init__(self, size: int, addr: IlExprId):
    super().__init__()
    self.size, self.addr = size, addr

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.addr == other.addr)

  def __repr__(self):
    return '''il.Load({0}, {1})'''.format(self.size, self.addr)


class IlBranch(IlExprId):
  pass


class IlJump(IlBranch):

  @type_check
  def __init__(self, dest: IlExprId):
    super().__init__()
    self.dest = dest

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.dest == other.dest)

  def __repr__(self):
    return '''il.Jump({0})'''.format(self.dest)


class IlCall(IlBranch):

  @type_check
  def __init__(self, dest: IlExprId):
    super().__init__()
    self.dest = dest

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.dest == other.dest)

  def __repr__(self):
    return '''il.Call({0})'''.format(self.dest)


class IlReturn(IlBranch):

  @type_check
  def __init__(self, dest: IlExprId):
    super().__init__()
    self.dest = dest

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.dest == other.dest)

  def __repr__(self):
    return '''il.Return({0})'''.format(self.dest)


class IlShiftLeft(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=a.signed)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.ShiftLeft({0}, {1}, {2})'''.format(self.size, self.a, self.b)


class IlLogicalShiftRight(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=a.signed)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.LogicalShiftRight({0}, {1}, {2})'''.format(
        self.size, self.a, self.b)


class IlArithShiftRight(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=a.signed)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.ArithShiftRight({0}, {1}, {2})'''.format(
        self.size, self.a, self.b)


class IlRotateLeft(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=a.signed)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.RotateLeft({0}, {1}, {2})'''.format(self.size, self.a, self.b)


class IlMult(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=a.signed)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.Mult({0}, {1}, {2})'''.format(self.size, self.a, self.b)


class IlTrap(IlExprId):

  @type_check
  def __init__(self, num: IlConst):
    super().__init__()
    self.num = num

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.num == other.num)

  def __repr__(self):
    return '''il.Trap({0})'''.format(self.num.val)


class IlSystemCall(IlExprId):

  @type_check
  def __init__(self):
    super().__init__()
    pass

  def __eq__(self, other):
    return isinstance(other, self.__class__)

  def __repr__(self):
    return '''il.SystemCall()'''


class IlBreakpoint(IlExprId):

  @type_check
  def __init__(self):
    super().__init__()
    pass

  def __eq__(self, other):
    return isinstance(other, self.__class__)

  def __repr__(self):
    return '''il.Breakpoint()'''


class IlBoolToInt(IlExprId):

  @type_check
  def __init__(self, size: int, a: IlExprId):
    super().__init__()
    self.size, self.a = size, a

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a)

  def __repr__(self):
    return '''il.BoolToInt({0}, {1})'''.format(self.size, self.a)


class IlCompareExpr(IlExprId):
  pass


class IlCompareEqual(IlCompareExpr):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=False)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.CompareEqual({0}, {1}, {2})'''.format(self.size, self.a,
                                                       self.b)


class IlCompareNotEqual(IlCompareExpr):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=False)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.CompareNotEqual({0}, {1}, {2})'''.format(
        self.size, self.a, self.b)


class IlCompareSignedGreaterThan(IlCompareExpr):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=False)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.CompareSignedGreaterThan({0}, {1}, {2})'''.format(
        self.size, self.a, self.b)


class IlCompareUnsignedGreaterThan(IlCompareExpr):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=False)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.CompareUnsignedGreaterThan({0}, {1}, {2})'''.format(
        self.size, self.a, self.b)


class IlCompareSignedGreaterEqual(IlCompareExpr):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=False)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.CompareSignedGreaterEqual({0}, {1}, {2})'''.format(
        self.size, self.a, self.b)


class IlCompareSignedLessThan(IlCompareExpr):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=False)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.CompareSignedLessThan({0}, {1}, {2})'''.format(
        self.size, self.a, self.b)


class IlCompareUnsignedGreaterEqual(IlCompareExpr):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=False)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.CompareUnsignedGreaterEqual({0}, {1}, {2})'''.format(
        self.size, self.a, self.b)


class IlCompareUnsignedLessThan(IlCompareExpr):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=False)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.CompareUnsignedLessThan({0}, {1}, {2})'''.format(
        self.size, self.a, self.b)


class IlCompareSignedLessEqual(IlCompareExpr):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=False)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.CompareSignedLessEqual({0}, {1}, {2})'''.format(
        self.size, self.a, self.b)


class IlCompareUnsignedLessEqual(IlCompareExpr):

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=False)
    self.size, self.a, self.b = size, a, b

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return '''il.CompareUnsignedLessEqual({0}, {1}, {2})'''.format(
        self.size, self.a, self.b)


class IlFloatBinop(IlExprId):
  """A float operation of two operands, il.<CALL>(size, a, b)."""
  CALL = None
  RESULT_IS_FLOAT = True

  @type_check
  def __init__(self, size: int, a: IlExprId, b: IlExprId):
    super().__init__(signed=True)
    self.size, self.a, self.b = size, a, b
    self.is_float = self.RESULT_IS_FLOAT

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a and self.b == other.b)

  def __repr__(self):
    return 'il.{0}({1}, {2}, {3})'.format(self.CALL, self.size, self.a, self.b)


class IlFloatAdd(IlFloatBinop):
  CALL = 'FloatAdd'


class IlFloatSub(IlFloatBinop):
  CALL = 'FloatSub'


class IlFloatMult(IlFloatBinop):
  CALL = 'FloatMult'


class IlFloatDiv(IlFloatBinop):
  CALL = 'FloatDiv'


class IlFloatCompare(IlFloatBinop, IlCompareExpr):
  # |size| is the operands' size; the result is a boolean.
  RESULT_IS_FLOAT = False


class IlFloatCompareEqual(IlFloatCompare):
  CALL = 'FloatCompareEqual'


class IlFloatCompareNotEqual(IlFloatCompare):
  CALL = 'FloatCompareNotEqual'


class IlFloatCompareLessThan(IlFloatCompare):
  CALL = 'FloatCompareLessThan'


class IlFloatCompareLessEqual(IlFloatCompare):
  CALL = 'FloatCompareLessEqual'


class IlFloatCompareGreaterThan(IlFloatCompare):
  CALL = 'FloatCompareGreaterThan'


class IlFloatCompareGreaterEqual(IlFloatCompare):
  CALL = 'FloatCompareGreaterEqual'


class IlFloatCompareUnordered(IlFloatCompare):
  CALL = 'FloatCompareUnordered'


class IlFloatUnop(IlExprId):
  """A float operation or conversion of one operand, il.<CALL>(size, a), with
  a result of |size| bytes."""
  CALL = None
  RESULT_IS_FLOAT = True

  @type_check
  def __init__(self, size: int, a: IlExprId):
    super().__init__(signed=True)
    self.size, self.a = size, a
    self.is_float = self.RESULT_IS_FLOAT

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.a == other.a)

  def __repr__(self):
    return 'il.{0}({1}, {2})'.format(self.CALL, self.size, self.a)


class IlFloatNeg(IlFloatUnop):
  CALL = 'FloatNeg'


class IlFloatConvert(IlFloatUnop):
  CALL = 'FloatConvert'


class IlIntToFloat(IlFloatUnop):
  CALL = 'IntToFloat'


class IlFloatToInt(IlFloatUnop):
  CALL = 'FloatToInt'
  RESULT_IS_FLOAT = False


class IlRoundToInt(IlFloatUnop):
  # Rounds to an integral float in the current (nearest-even) mode.
  CALL = 'RoundToInt'


class IlFloatTrunc(IlFloatUnop):
  # Rounds toward zero to an integral float.
  CALL = 'FloatTrunc'


class IlTernary(IlExprId):
  """`cond ? t : f`. Binary Ninja has no select, so the assignment that holds
  it becomes an if/else (SemanticsTreeTransformer.assg)."""

  @type_check
  def __init__(self, cond: IlExprId, t: IlExprId, f: IlExprId):
    super().__init__(signed=t.signed)
    self.cond, self.t, self.f = cond, t, f
    self.size = max(t.size, f.size)

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.cond == other.cond and self.t == other.t and self.f == other.f)

  def __repr__(self):
    raise ValueError('A ternary outside an assignment is not lifted')


def find_ternary(expr):
  """The first IlTernary in |expr| whose condition has none, or None."""
  if isinstance(expr, IlTernary):
    inner = find_ternary(expr.cond)
    return expr if inner is None else inner
  if isinstance(expr, (list, tuple)):
    children = expr
  elif isinstance(expr, IlExprId):
    children = vars(expr).values()
  else:
    return None
  for child in children:
    found = find_ternary(child)
    if found is not None:
      return found
  return None


def replace_expr(expr, old, new):
  """A copy of |expr| with the node |old| replaced by |new|."""
  if expr is old:
    return new
  if isinstance(expr, list):
    return [replace_expr(e, old, new) for e in expr]
  if isinstance(expr, IlExprId):
    expr = copy.copy(expr)
    for name, value in list(vars(expr).items()):
      setattr(expr, name, replace_expr(value, old, new))
  return expr


class IlIf(IlExprId):

  @type_check
  def __init__(self, cond: IlExprId, t: str, f: str):
    super().__init__()
    self.cond, self.t, self.f = cond, t, f

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.cond == other.cond and self.t == other.t and self.f == other.f)

  def __repr__(self):
    return '''il.If({0}, {1}, {2})'''.format(self.cond, self.t, self.f)


class IlGoto(IlExprId):

  @type_check
  def __init__(self, l: str):
    super().__init__()
    self.l = l

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.l == other.l)

  def __repr__(self):
    return '''il.Goto({0})'''.format(self.l)


class IlPush(IlExprId):

  @type_check
  def __init__(self, size: int, val: IlExprId):
    super().__init__()
    self.size, self.val = size, val

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size and self.val == other.val)

  def __repr__(self):
    return '''il.Push({0}, {1})'''.format(self.size, self.val)


class IlPop(IlExprId):

  @type_check
  def __init__(self, size: int):
    super().__init__()
    self.size = size

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size)

  def __repr__(self):
    return '''il.Pop({0})'''.format(self.size)


class IlReadGP(IlExprId):

  @type_check
  def __init__(self, size: int):
    super().__init__()
    self.size = size

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return (self.size == other.size)

  # #define fREAD_GP() \
  #     (insn->extension_valid ? 0 : READ_REG(HEX_REG_GP))
  #
  # Global pointer relative addresses can be expressed two ways in assembly language:
  #  * By explicitly adding an unsigned offset value to register GP.
  #  * By specifying only an immediate value as the instruction operand.
  def __repr__(self):
    return (
        '''(insn.extension_valid ? il.Const({0}, 0) : il.Register({0}, HEX_REG_GP))'''
        .format(self.size))


class IlLabel(str):
  pass


class RawC(str):
  pass


#
# Tag overrides.
#
behoverrides = {
    'A2_swiz': 'Rd32=swiz(Rs32)',
}
semoverrides = {
    'A2_swiz': '{ RdV = fBYTESWAP(RsV); }',
}


#
# Transforms semantics tree to serialized lifter code.
#
class SemanticsTreeTransformer(Transformer):

  def __init__(self, tag):
    super().__init__()
    self.tag = tag

  def lift_operand(self, op):
    if isinstance(op, IlExprId):
      return copy.copy(op)
    if op.type == 'REG_OLD':
      if op.startswith('P'):
        # Predicates hold unsigned 8-bit values.
        op = IlRegister(1, op)
        op.signed = False
      elif is_pair_operand(op):
        # Pair
        op = IlRegister(8, op)
      else:
        op = IlRegister(4, op)
    elif op.type == 'REG_NEW':
      if op.startswith('P'):
        op = IlRegister(1, op)
        op.signed = False
      elif is_pair_operand(op):
        # Pair
        op = IlRegister(8, op)
      else:
        op = IlRegister(4, op)
    elif op.type == 'EA':
      op = IlRegister(4, 'EA_REG')
    elif op.type == 'REG_LR':
      op = IlRegister(4, 'HEX_REG_LR')
    elif op.type in ['IMM', 'INTCON']:
      op = IlConst(4, op)
    elif op.type == 'LOCAL':
      reg, size, signed = LOCALS[self.tag][op.value]
      op = IlRegister(size, reg)
      op.signed = signed
    elif op.type == 'TMP':
      if op.value == 'tmp':
        op = IlRegister(8, 'TMP_REG')
      elif op.value == 'width':
        op = IlRegister(8, 'WIDTH_REG')
      elif op.value == 'offset':
        op = IlRegister(8, 'OFFSET_REG')
      elif op.value == 'shamt':
        op = IlRegister(8, 'SHAMT_REG')
      else:
        assert (0)
    else:
      assert (0)
    return op

  def macro_stmt_fIMMEXT(self, args):
    # macros.h:
    #   #define fIMMEXT(IMM) (IMM = IMM)
    # no-op operation.
    assert (len(args) == 1)
    assert (args[0].type == 'IMM')
    return []

  def macro_stmt_fPCALIGN(self, args):
    # macros.h:
    #  #define fPCALIGN(IMM) IMM = (IMM & ~PCALIGN_MASK)
    assert (len(args) == 1)
    assert (args[0].type == 'IMM')
    return [RawC('''{0} = {0} & ~PCALIGN_MASK;'''.format(args[0]))]

  def macro_stmt_fBRANCH(self, args):
    # macros.h:
    # #define fBRANCH(LOC, TYPE)          fWRITE_NPC(LOC)
    assert (len(args) == 2)
    assert (args[1].type == 'BRANCH_TYPE')
    typ = args[1]
    loc = self.lift_operand(args[0])
    ret = []
    if 'A_BN_COND_J' in attribdict[self.tag]:
      ret += [IlSetRegister(1, 'BRANCH_TAKEN_ARRAY + insn_num', IlConst(1, 1))]
    if (typ in ['COF_TYPE_JUMP', 'COF_TYPE_JUMPNEW']):
      ret += [IlJump(loc)]
    elif (typ == 'COF_TYPE_JUMPR'):
      ret += [IlSetRegister(4, 'BRANCHR_DEST_ARRAY + insn_num', loc)]
      ret += [IlJump(loc)]
    elif (typ == 'COF_TYPE_CALL'):
      ret += [IlCall(loc)]
    elif (typ == 'COF_TYPE_CALLR'):
      ret += [IlSetRegister(4, 'BRANCHR_DEST_ARRAY + insn_num', loc)]
      ret += [IlCall(loc)]
    elif (typ == 'COF_TYPE_RETURN'):
      ret += [IlReturn(loc)]
    elif (typ in ['COF_TYPE_LOOPEND0', 'COF_TYPE_LOOPEND1']):
      # Loop ends are treated as a conditional branches.
      assert ('A_BN_COND_J' in attribdict[self.tag])
      ret += [IlSetRegister(4, 'BRANCHR_DEST_ARRAY + insn_num', loc)]
      ret += [IlJump(loc)]
    else:
      assert (0)
    return ret

  def macro_stmt_fJUMPR(self, args):
    # macros.h:
    # #define fJUMPR(REGNO, TARGET, TYPE) fBRANCH(TARGET, COF_TYPE_JUMPR)
    assert (len(args) == 3)
    regno, loc, typ = args
    if regno == 'REG_LR':
      typ = Token('BRANCH_TYPE', 'COF_TYPE_RETURN')
    return self.macro_stmt_fBRANCH([loc, typ])

  # Floating point. A float or double is a register's bits (fFLOAT, fDOUBLE),
  # on which C's operators lift to float IL (expr_binop, expr_relop).

  def float_bits(self, args, size, is_float):
    # fFLOAT(A), fUNFLOAT(A), fDOUBLE(A) and fUNDOUBLE(A) reinterpret A's
    # bits. fUNFLOAT and fUNDOUBLE also turn any NaN into all ones, which the
    # IL leaves out.
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    if isinstance(val, (IlZeroExtend, IlSignExtend)) and val.a.size == size:
      val = val.a  # A word of a pair (fGETUWORD) as it is.
    val = convert(val, size, False)
    val.is_float = is_float
    return val

  def macro_expr_fFLOAT(self, args):
    return self.float_bits(args, 4, True)

  def macro_expr_fUNFLOAT(self, args):
    return self.float_bits(args, 4, False)

  def macro_expr_fDOUBLE(self, args):
    return self.float_bits(args, 8, True)

  def macro_expr_fUNDOUBLE(self, args):
    return self.float_bits(args, 8, False)

  def macro_expr_fSFMPY(self, args):
    # #define fSFMPY(A,B) internal_mpyf(A,B), a rounded A * B.
    assert (len(args) == 2)
    return self.expr_binop(args[0], Token('MULOP', '*'), args[1])

  def macro_expr_isunordered(self, args):
    assert (len(args) == 2)
    a, b = list(map(self.lift_operand, args))
    assert (a.is_float and b.is_float and a.size == b.size)
    return IlFloatCompareUnordered(a.size, a, b)

  def macro_stmt_fFPSETROUND_CHOP(self, args):
    # Rounds toward zero for the rest of the instruction, which conversion()
    # reads from the semantics.
    return []

  CONVERSION_TYPES = {'4s': (4, True), '4u': (4, False), '8s': (8, True),
                      '8u': (8, False), 'sf': (4, None), 'df': (8, None)}

  def conversion(self, name, args):
    # conv_<from>_to_<to>(A) between integers (4s, 4u, 8s, 8u) and floats
    # (sf, df), rounding to nearest, or toward zero after fFPSETROUND_CHOP.
    # A conversion from or to a 64-bit unsigned integer has no IL: integer
    # and float conversions are signed.
    assert (len(args) == 1)
    m = re.fullmatch(r'conv_(\w\w)_to_(\w\w)', name)
    (from_size, from_signed), (to_size, to_signed) = (
        self.CONVERSION_TYPES[m.group(1)], self.CONVERSION_TYPES[m.group(2)])
    val = self.lift_operand(args[0])
    if from_signed is None and to_signed is None:
      assert (val.is_float and val.size == from_size)
      return IlFloatConvert(to_size, val)
    if from_signed is None:
      # Float to integer. A C program converts only values the integer type
      # holds, for which FloatToInt to the signed 8-byte type is exact.
      assert (val.is_float and val.size == from_size)
      if (to_size, to_signed) == (8, False):
        raise ValueError('No IL for a conversion to a 64-bit unsigned integer')
      if 'fFPSETROUND_CHOP' in semdict[self.tag]:
        integral = IlFloatTrunc(from_size, val)
      else:
        integral = IlRoundToInt(from_size, val)
      if to_signed:
        result = IlFloatToInt(to_size, integral)
      else:
        result = IlLowPart(to_size, IlFloatToInt(8, integral))
      result.signed = to_signed
      return result
    # Integer to float.
    if (from_size, from_signed) == (8, False):
      raise ValueError('No IL for a conversion from a 64-bit unsigned integer')
    val = convert(val, from_size, from_signed)
    if not from_signed:
      val = IlZeroExtend(8, val)  # Holds every value of the type, signed.
    return IlIntToFloat(to_size, val)

  def macro_stmt_fTRAP(self, args):
    # macros.h:
    # #define fTRAP(TRAPTYPE, IMM) helper_raise_exception(env, HEX_EXCP_TRAP0)
    assert (len(args) == 2)
    typ, imm = list(map(self.lift_operand, args))
    return [IlSystemCall()]

  def macro_stmt_fBREAK(self, args):
    assert (len(args) == 0)
    return [IlBreakpoint()]

  def macro_stmt_fSTORE(self, args):
    # macros.h:
    # #define fSTORE(NUM, SIZE, EA, SRC) MEM_STORE##SIZE(EA, SRC, slot)
    assert (len(args) == 4)
    _, size, ea, src = args
    assert (size.type == 'INTCON')
    assert (ea.type == 'EA')
    size = int(size)
    ea, src = list(map(self.lift_operand, [ea, src]))
    return [IlStore(size, ea, src)]

  def macro_stmt_fSTORE_LOCKED(self, args):
    # macros.h:
    # #define fSTORE(NUM, SIZE, EA, SRC, PRED) \
    #    { PRED = (mem_store_conditional(thread,EA,SRC,SIZE,insn) ? 0xff : 0); }
    assert (len(args) == 5)
    pred = self.lift_operand(args[4])
    ret = []
    ret += self.macro_stmt_fSTORE(args[:4])
    ret += [IlSetRegister(pred.size, pred.reg, IlConst(1, 1))]
    return ret

  def macro_stmt_fLOAD(self, args):
    # macros.h:
    # #define fLOAD(NUM, SIZE, SIGN, EA, DST) \
    #     DST = (size##SIZE##SIGN##_t)MEM_LOAD##SIZE##SIGN(EA)
    # #endif
    assert (len(args) == 5)
    _, size, sign, ea, dst = args
    assert (size.type == 'INTCON')
    assert (sign.type == 'SIGN')
    assert (ea.type == 'EA')
    size = int(size)
    ea, dst = list(map(self.lift_operand, [ea, dst]))
    val = IlLoad(size, ea)
    if size < dst.size:
      if sign == 's':
        val = IlSignExtend(dst.size, val)
      else:
        val = IlZeroExtend(dst.size, val)
    return [IlSetRegister(dst.size, dst.reg, val)]

  def macro_stmt_fWRITE_FP(self, args):
    # macros.h:
    # #define fWRITE_FP(A) WRITE_RREG(HEX_REG_FP, A)
    assert (len(args) == 1)
    a = self.lift_operand(args[0])
    return [IlSetRegister(4, 'HEX_REG_FP', fit_to_size(4, a))]

  def macro_stmt_fWRITE_LR(self, args):
    # macros.h:
    # #define fWRITE_LR(A) WRITE_RREG(HEX_REG_LR, A)
    assert (len(args) == 1)
    a = self.lift_operand(args[0])
    return [IlSetRegister(4, 'HEX_REG_LR', fit_to_size(4, a))]

  def macro_stmt_fWRITE_SP(self, args):
    # macros.h:
    # #define fWRITE_SP(A) WRITE_RREG(HEX_REG_SP, A)
    assert (len(args) == 1)
    a = self.lift_operand(args[0])
    return [IlSetRegister(4, 'HEX_REG_SP', fit_to_size(4, a))]

  def macro_stmt_fWRITE_P0(self, args):
    # macros.h:
    # #define fWRITE_P0(VAL) WRITE_PREG(0, VAL)
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    return [IlSetRegister(1, 'Pd0', val)]

  def macro_stmt_fWRITE_P1(self, args):
    # macros.h:
    # #define fWRITE_P1(VAL) WRITE_PREG(1, VAL)
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    return [IlSetRegister(1, 'Pd1', val)]

  def macro_stmt_fWRITE_P2(self, args):
    # macros.h:
    # #define fWRITE_P2(VAL) WRITE_PREG(2, VAL)
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    return [IlSetRegister(1, 'Pd2', val)]

  def macro_stmt_fWRITE_P3(self, args):
    # macros.h:
    # #define fWRITE_P3(VAL) WRITE_PREG(3, VAL)
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    return [IlSetRegister(1, 'Pd3', val)]

  def macro_stmt_fWRITE_LOOP_REGS(self, args):
    # macros.h
    # #define fWRITE_LOOP_REGS0(START, COUNT) \
    #     do { \
    #         WRITE_RREG(HEX_REG_LC0, COUNT);  \
    #         WRITE_RREG(HEX_REG_SA0, START); \
    #     } while (0)
    # or
    # #define fWRITE_LOOP_REGS1(START, COUNT) \
    #     do { \
    #         WRITE_RREG(HEX_REG_LC1, COUNT);  \
    #         WRITE_RREG(HEX_REG_SA1, START); \
    #     } while (0)
    assert (len(args) == 3)
    n = fold_constant(args[0])
    assert (n is not None)
    start, count = list(map(self.lift_operand, args[1:]))
    ret = []
    if n == 0:
      ret += [IlSetRegister(4, 'HEX_REG_LC0', count)]
      ret += [IlSetRegister(4, 'HEX_REG_SA0', start)]
    elif n == 1:
      ret += [IlSetRegister(4, 'HEX_REG_LC1', count)]
      ret += [IlSetRegister(4, 'HEX_REG_SA1', start)]
    else:
      assert (0)
    return ret

  def macro_stmt_fSET_LPCFG(self, args):
    # macros.h
    # #define fSET_LPCFG(VAL) SET_USR_FIELD(USR_LPCFG, (VAL))
    # #define SET_USR_FIELD(FIELD, VAL) \
    #     fINSERT_BITS(env->gpr[HEX_REG_USR], reg_field_info[FIELD].width, \
    #                  reg_field_info[FIELD].offset, (VAL))
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    return [IlSetRegister(1, 'HEX_REG_USR_LPCFG', val)]

  def macro_stmt_fWRITE_LC(self, args):
    # macros.h
    # #define fWRITE_LC0(VAL) WRITE_RREG(HEX_REG_LC0, VAL)
    # #define fWRITE_LC1(VAL) WRITE_RREG(HEX_REG_LC1, VAL)
    assert (len(args) == 2)
    n = fold_constant(args[0])
    assert (n is not None)
    val = self.lift_operand(args[1])
    if n == 0:
      return [IlSetRegister(4, 'HEX_REG_LC0', val)]
    if n == 1:
      return [IlSetRegister(4, 'HEX_REG_LC1', val)]
    assert (0)

  def macro_expr_fGETBYTE(self, args):
    # macros.h:
    # #define fGETBYTE(N, SRC) ((int8_t)((SRC >> ((N) * 8)) & 0xff))
    assert (len(args) == 2)
    n = fold_constant(args[0])
    assert (n is not None)
    src = self.lift_operand(args[1])
    src.signed = True
    if n == 0:
      return IlLowPart(1, src)
    return IlLowPart(1, IlArithShiftRight(src.size, src, IlConst(1, n * 8)))

  def macro_expr_fGETUBYTE(self, args):
    # macros.h:
    # #define fGETBYTE(N, SRC) ((uint8_t)((SRC >> ((N) * 8)) & 0xff))
    assert (len(args) == 2)
    n = fold_constant(args[0])
    assert (n is not None)
    src = self.lift_operand(args[1])
    src.signed = False
    if n == 0:
      return IlLowPart(1, src)
    return IlLowPart(1, IlLogicalShiftRight(src.size, src, IlConst(1, n * 8)))

  def macro_expr_fGETHALF(self, args):
    # macros.h:
    # #define fGETHALF(N, SRC) ((int16_t)((SRC >> ((N) * 16)) & 0xffff))
    assert (len(args) == 2)
    n = fold_constant(args[0])
    assert (n is not None)
    src = self.lift_operand(args[1])
    src.signed = True
    if n == 0:
      half = IlLowPart(2, src)
    else:
      half = IlLowPart(2, IlArithShiftRight(src.size, src, IlConst(1, n * 16)))
    # An int16_t, which operators promote to int.
    half.signed = True
    return half

  def macro_expr_fGETUHALF(self, args):
    # macros.h:
    # #define fGETUHALF(N, SRC) ((uint16_t)((SRC >> ((N) * 16)) & 0xffff))
    assert (len(args) == 2)
    n = fold_constant(args[0])
    assert (n is not None)
    src = self.lift_operand(args[1])
    src.signed = False
    if n == 0:
      half = IlLowPart(2, src)
    else:
      half = IlLowPart(2, IlLogicalShiftRight(src.size, src, IlConst(1,
                                                                     n * 16)))
    # A uint16_t, which operators promote to (signed) int.
    half.signed = False
    return half

  def macro_expr_fGETWORD(self, args):
    # macros.h:
    # #define fGETWORD(N, SRC) \
    #     ((int64_t)((int32_t)((SRC >> ((N) * 32)) & 0x0ffffffffLL)))
    assert (len(args) == 2)
    n = fold_constant(args[0])
    assert (n is not None)
    src = self.lift_operand(args[1])
    assert (src.size == 8)
    src.signed = True
    if n == 0:
      word = IlLowPart(4, src)
    else:
      word = IlLowPart(4, IlArithShiftRight(src.size, src, IlConst(1, n * 32)))
    return IlSignExtend(src.size, word)

  def macro_expr_fGETUWORD(self, args):
    # macros.h:
    # #define fGETWORD(N, SRC) \
    #     ((uint64_t)((uint32_t)((SRC >> ((N) * 32)) & 0x0ffffffffLL)))
    assert (len(args) == 2)
    n = fold_constant(args[0])
    assert (n is not None)
    src = self.lift_operand(args[1])
    assert (src.size == 8)
    src.signed = False
    if n == 0:
      word = IlLowPart(4, src)
    else:
      word = IlLowPart(4, IlLogicalShiftRight(src.size, src, IlConst(1,
                                                                     n * 32)))
    return IlZeroExtend(src.size, word)

  def macro_expr_fROTL4_4u(self, args):
    assert (len(args) == 2)
    src, shamt = list(map(self.lift_operand, args))
    assert (src.size == 4)
    return IlRotateLeft(src.size, src, shamt)

  def macro_expr_fROTL8_8u(self, args):
    assert (len(args) == 2)
    src, shamt = list(map(self.lift_operand, args))
    assert (src.size == 8)
    return IlRotateLeft(src.size, src, shamt)

  def lane_shift(self, n, bits):
    # The shift of lane |n| of |bits| bits: N * BITS.
    if fold_constant(n) is not None:
      return IlConst(1, fold_constant(n) * bits)
    n = self.lift_operand(n)
    return IlMult(n.size, n, IlConst(n.size, bits))

  def set_lane(self, args, bits):
    # macros.h, for fSETBIT, fSETBYTE, fSETHALF and fSETWORD:
    # DST = (DST & ~(MASK << ((N) * BITS))) |
    #       (((VAL) & MASK) << ((N) * BITS))
    assert (len(args) == 3)
    dst, val = list(map(self.lift_operand, args[1:]))
    assert (isinstance(dst, IlRegister) and dst.size * 8 > bits)
    mask = (1 << bits) - 1
    if val.size * 8 == bits:
      # A value exactly the lane's width needs no mask (combine).
      if literal_fits(val, val.size, False):
        lane = widen(val, dst.size)  # A literal that fits takes the size.
      elif val.size < dst.size:
        lane = IlZeroExtend(dst.size, val)
      else:
        lane = val
    else:
      if val.size > dst.size:
        val = IlLowPart(dst.size, val)
      else:
        val = widen(val, dst.size)  # As its type says, before the mask.
      lane = IlAnd(dst.size, val, IlConst(dst.size, mask))
    old = IlAnd(
        dst.size, dst,
        IlNot(
            dst.size,
            IlShiftLeft(dst.size, IlConst(dst.size, mask),
                        self.lane_shift(args[0], bits))))
    new = IlShiftLeft(dst.size, lane, self.lane_shift(args[0], bits))
    return [IlSetRegister(dst.size, dst.reg, IlOr(dst.size, old, new))]

  def macro_stmt_fSETBIT(self, args):
    return self.set_lane(args, 1)

  def macro_stmt_fSETBITS(self, args):
    # macros.h:
    # #define fSETBITS(HI, LO, DST, VAL) for (j = LO; j <= HI; j++)
    #                                      fSETBIT(j, DST, VAL)
    # as DST = (DST & ~MASK) | (-(VAL & 1) & MASK), MASK bits LO to HI.
    assert (len(args) == 4)
    hi, lo = fold_constant(args[0]), fold_constant(args[1])
    assert (hi is not None and lo is not None)
    dst, val = list(map(self.lift_operand, args[2:]))
    assert (isinstance(dst, IlRegister))
    size = dst.size
    if isinstance(val, IlCompareExpr):
      bit = IlBoolToInt(size, val)
    else:
      bit = IlAnd(size, convert(val, size, False), IlConst(size, 1))
    mask = ((1 << (hi - lo + 1)) - 1) << lo
    old = IlAnd(size, dst, IlConst(size, ~mask & ((1 << (8 * size)) - 1)))
    new = IlAnd(size, IlNeg(size, bit), IlConst(size, mask))
    return [IlSetRegister(size, dst.reg, IlOr(size, old, new))]

  def macro_stmt_fSETBYTE(self, args):
    return self.set_lane(args, 8)

  def macro_stmt_fSETHALF(self, args):
    return self.set_lane(args, 16)

  def macro_stmt_fSETWORD(self, args):
    return self.set_lane(args, 32)

  def circular_add(self, rx, offset, mu):
    # helper.h: Rx = fcircadd(Rx, OFFSET, Mu, CS), with CS the CS register
    # paired with Mu:
    #   K = Mu[27:24]; length = Mu[16:0]; new = Rx + OFFSET;
    #   if (K == 0 && length >= 4) { start = CS; end = CS + length; }
    #   else { start = Rx & ~((1 << (K + 2)) - 1); end = start | length; }
    #   if (new >= end) new -= length; else if (new < start) new += length;
    assert (isinstance(rx, IlRegister))
    k, length, new, start, end = [
        IlRegister(4, 'CIRC_REG + {}'.format(i)) for i in range(5)
    ]
    for reg in (k, length, new, start, end):
      reg.signed = False
    cs = IlRegister(4, 'HEX_REG_CS0 + ({} - HEX_REG_M0)'.format(mu.reg))
    offset = convert(offset, 4, True)
    ret = [
        IlSetRegister(4, k.reg,
                      IlAnd(4, IlLogicalShiftRight(4, mu, IlConst(1, 24)),
                            IlConst(4, 0xf))),
        IlSetRegister(4, length.reg, IlAnd(4, copy.copy(mu),
                                           IlConst(4, 0x1ffff))),
        IlSetRegister(4, new.reg, IlAdd(4, rx, offset)),
    ]
    normal = IlAnd(1, IlCompareEqual(4, k, IlConst(4, 0)),
                   IlCompareUnsignedGreaterEqual(4, length, IlConst(4, 4)))
    ret += self.if_stmt([
        normal,
        [
            IlSetRegister(4, start.reg, cs),
            IlSetRegister(4, end.reg, IlAdd(4, cs, length)),
        ],
        [
            IlSetRegister(
                4, start.reg,
                IlAnd(
                    4, rx,
                    IlNot(
                        4,
                        IlSub(
                            4,
                            IlShiftLeft(4, IlConst(4, 1),
                                        IlAdd(4, k, IlConst(4, 2))),
                            IlConst(4, 1))))),
            IlSetRegister(4, end.reg, IlOr(4, start, length)),
        ],
    ])
    ret += self.if_stmt([
        IlCompareUnsignedGreaterEqual(4, new, end),
        [IlSetRegister(4, new.reg, IlSub(4, new, length))],
        self.if_stmt([
            IlCompareUnsignedLessThan(4, new, start),
            [IlSetRegister(4, new.reg, IlAdd(4, new, length))],
        ]),
    ])
    ret += [IlSetRegister(4, rx.reg, new)]
    return ret

  def macro_stmt_fPM_CIRI(self, args):
    # gen_tcg.h: fcircadd(REG, IMM, Mu, CS).
    assert (len(args) == 3)
    rx, offset, mu = list(map(self.lift_operand, args))
    return self.circular_add(rx, offset, mu)

  def macro_stmt_fPM_CIRR(self, args):
    # gen_tcg.h: fcircadd(REG, VAL, Mu, CS), VAL from fREAD_IREG.
    return self.macro_stmt_fPM_CIRI(args)

  def macro_expr_fREAD_IREG(self, args):
    # macros.h (gen_read_ireg): the signed 11-bit I field of a modifier
    # register, Mu[31:28] above Mu[23:17].
    assert (len(args) == 1)
    mu = self.lift_operand(args[0])
    high = IlShiftLeft(4, IlArithShiftRight(4, mu, IlConst(1, 28)),
                       IlConst(1, 7))
    low = IlAnd(4, IlLogicalShiftRight(4, copy.copy(mu), IlConst(1, 17)),
                IlConst(4, 0x7f))
    value = IlOr(4, high, low)
    value.signed = True
    return value

  def macro_stmt_fEA_BREVR(self, args):
    # helper.h: EA = fbrev(REG), REG with its low 16 bits reversed:
    # deposit32(REG, 0, 16, revbit16(REG)). Swapping bits, pairs, nibbles and
    # bytes reverses them.
    assert (len(args) == 1)
    reg = self.lift_operand(args[0])
    ea = IlRegister(4, 'EA_REG')
    ret = [IlSetRegister(4, 'EA_REG', IlAnd(4, reg, IlConst(4, 0xffff)))]
    for shift, mask in ((1, 0x5555), (2, 0x3333), (4, 0x0f0f), (8, 0x00ff)):
      ret.append(
          IlSetRegister(
              4, 'EA_REG',
              IlOr(
                  4,
                  IlAnd(4, IlLogicalShiftRight(4, ea, IlConst(1, shift)),
                        IlConst(4, mask)),
                  IlShiftLeft(4, IlAnd(4, ea, IlConst(4, mask)),
                              IlConst(1, shift)))))
    ret.append(
        IlSetRegister(
            4, 'EA_REG',
            IlOr(4, IlAnd(4, copy.copy(reg), IlConst(4, 0xffff0000)), ea)))
    return ret

  def macro_expr_fGETBIT(self, args):
    # macros.h:
    # #define fGETBIT(N, SRC) (((SRC) >> N) & 1)
    assert (len(args) == 2)
    src = self.lift_operand(args[1])
    value = IlAnd(
        src.size,
        IlLogicalShiftRight(src.size, src, self.lane_shift(args[0], 1)),
        IlConst(src.size, 1))
    value.signed = False
    return value
  def macro_expr_fFRAME_SCRAMBLE(self, args):
    # This macro is always invoked with the same arguments:
    #   fFRAME_SCRAMBLE((fCAST8_8u(fREAD_LR()) << 32) | fCAST4_4u(fREAD_FP()))
    # Return a simpler expression using RegisterSplit.
    return IlRegisterSplit(4, 'HEX_REG_LR', 'HEX_REG_FP')

  def macro_expr_fREAD_PC(self, args):
    # macros.h:
    # #define fREAD_PC() (READ_REG(HEX_REG_PC))
    assert (len(args) == 0)
    return IlConstPointer(4, 'pc')

  def macro_expr_fREAD_LR(self, args):
    # macros.h:
    # #define fREAD_LR() (READ_REG(HEX_REG_LR))
    return IlRegister(4, 'HEX_REG_LR')

  def macro_expr_fREAD_FP(self, args):
    # macros.h:
    # #define fREAD_FP() (READ_REG(HEX_REG_FP))
    return IlRegister(4, 'HEX_REG_FP')

  def macro_expr_fREAD_SP(self, args):
    # macros.h:
    # #define fREAD_SP() (READ_REG(HEX_REG_SP))
    return IlRegister(4, 'HEX_REG_SP')

  def macro_expr_fREAD_GP(self, args):
    # macros.h:
    # #define fREAD_GP() \
    #     (insn->extension_valid ? 0 : READ_REG(HEX_REG_GP))
    #
    # Global pointer relative addresses can be expressed two ways in assembly language:
    #  * By explicitly adding an unsigned offset value to register GP.
    #  * By specifying only an immediate value as the instruction operand.
    return IlReadGP(4)

  def macro_expr_fREAD_P0(self, args):
    assert (len(args) == 0)
    return IlRegister(1, 'Pd0')

  def macro_expr_fREAD_LPCFG(self, args):
    assert (len(args) == 0)
    return IlRegister(1, 'HEX_REG_USR_LPCFG')

  def macro_expr_fREAD_LC(self, args):
    # macros.h
    # #define fREAD_LC0 (READ_REG(tmp, HEX_REG_LC0))
    # #define fREAD_LC1 (READ_REG(tmp, HEX_REG_LC1))
    assert (len(args) == 1)
    n = fold_constant(args[0])
    assert (n is not None)
    if n == 0:
      return IlRegister(4, 'HEX_REG_LC0')
    if n == 1:
      return IlRegister(4, 'HEX_REG_LC1')
    assert (0)

  def macro_expr_fREAD_SA(self, args):
    # macros.h
    # #define fREAD_SA0 (READ_REG(tmp, HEX_REG_SA0))
    # #define fREAD_SA1 (READ_REG(tmp, HEX_REG_SA1))
    assert (len(args) == 1)
    n = fold_constant(args[0])
    assert (n is not None)
    if n == 0:
      return IlRegister(4, 'HEX_REG_SA0')
    if n == 1:
      return IlRegister(4, 'HEX_REG_SA1')
    assert (0)

  def macro_expr_fCAST4s(self, args):
    # macros.h:
    # #define fCAST4s(A) ((int32_t)(A))
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    if val.size > 4:
      # cast down by truncating value.
      val.signed = True
      return IlLowPart(4, val)

    if val.size == 4:
      val.signed = True
      return val

    return IlSignExtend(4, val)

  def macro_expr_fCAST4u(self, args):
    # macros.h:
    # #define fCAST4u(A) ((uint32_t)(A))
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    if val.size > 4:
      # cast down by truncating value.
      val.signed = False
      return IlLowPart(4, val)

    if val.size == 4:
      val.signed = False
      return val

    return IlZeroExtend(4, val)

  def macro_expr_fCAST8s(self, args):
    # macros.h:
    # #define fCAST8s(A) ((int64_t)(A))
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    assert (val.size <= 8)
    if val.size == 8 or literal_fits(val, 8, True):
      # A literal is a constant of the cast's size (0x8000000000000000ULL).
      val = copy.copy(val)
      val.size, val.signed = 8, True
      return val
    return IlSignExtend(8, val)

  def macro_expr_fCAST2_8s(self, args):
    # #define fCAST2_8s(A) ((int64_t)((int16_t)(A)))
    assert (len(args) == 1)
    return convert(convert(self.lift_operand(args[0]), 2, True), 8, True)

  def macro_expr_fCAST2_8u(self, args):
    # #define fCAST2_8u(A) ((uint64_t)((uint16_t)(A)))
    assert (len(args) == 1)
    return convert(convert(self.lift_operand(args[0]), 2, False), 8, False)

  def macro_expr_fCAST8u(self, args):
    # macros.h:
    # #define fCAST8u(A) ((uint64_t)(A))
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    assert (val.size <= 8)
    if val.size == 8 or literal_fits(val, 8, False):
      # A literal is a constant of the cast's size (0x8000000000000000ULL).
      val = copy.copy(val)
      val.size, val.signed = 8, False
      return val
    return IlZeroExtend(8, val)

  def extend_low_bits(self, args, signed):
    # fZXTN and fSXTN: the low N bits of VAL, zero- or sign-extended to M
    # bits, as QEMU's extract64 and sextract64.
    assert (len(args) == 3 and args[1].type == 'INTCON')
    # QEMU's result is 64-bit whatever M is (fSXTN(32,33,..) in vavgw); M up
    # to 32 keeps 32-bit uses at 32 bits.
    n, m_bytes = args[0], 4 if int(args[1]) <= 32 else 8
    val = self.lift_operand(args[2])
    if getattr(n, 'type', None) == 'INTCON' and int(n) in (8, 16, 32, 64):
      # A whole byte, half or word: an extension, which reads better.
      n_bytes = int(n) // 8
      if val.size > n_bytes:
        val = IlLowPart(n_bytes, val)
      val = widen(val, n_bytes)
      if n_bytes < m_bytes:
        if signed:
          return IlSignExtend(m_bytes, val)
        return IlZeroExtend(m_bytes, val)
      val = copy.copy(val)
      val.signed = signed
      return val
    # Any other width: masks M bits wide, so 64-bit values take N up to 63.
    n = self.lift_operand(n)
    one = IlConst(m_bytes, 1)
    val, mask = promote(
        val, IlSub(m_bytes, IlShiftLeft(m_bytes, one, n), copy.copy(one)))
    value = IlAnd(val.size, val, mask)
    value.signed = False
    if not signed:
      return value
    sign = IlShiftLeft(m_bytes, copy.copy(one),
                       IlSub(n.size, n, IlConst(n.size, 1)))
    value, sign = promote(value, sign)
    value = IlSub(value.size, IlXor(value.size, value, sign), copy.copy(sign))
    # Signed at M bits.
    if value.size > m_bytes:
      value = IlLowPart(m_bytes, value)
    value = widen(value, m_bytes)
    value.signed = True
    return value

  def macro_expr_fZXTN(self, args):
    # macros.h:
    # #define fZXTN(N, M, VAL) (((N) != 0) ? extract64((VAL), 0, (N)) : 0LL)
    return self.extend_low_bits(args, signed=False)

  def macro_expr_fSXTN(self, args):
    # macros.h:
    # #define fSXTN(N, M, VAL) (((N) != 0) ? sextract64((VAL), 0, (N)) : 0LL)
    return self.extend_low_bits(args, signed=True)

  def macro_expr_fCONST64(self, args):
    # A 64-bit literal (fCONSTLL).
    assert (len(args) == 1 and args[0].type == 'INTCON')
    return IlConst(8, args[0].value)

  def macro_expr_f8BITSOF(self, args):
    # macros.h
    # #define f8BITSOF(VAL) ((VAL) ? 0xff : 0x00)
    #
    # This macro is only used to write either 0/ff to an 8b predicate register:
    #   PdV = f8BITSOF((RsV & (1<<uiV)) != 0);
    # or,
    #   fWRITE_P0(f8BITSOF((fCAST4u(RsV)>RtV)))
    #
    # Predicate registers are only used as boolean registers, so instead of
    # storing the semantically correct 0/ff, store the result of a compare
    # operation - a boolean value.
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    assert (is_boolean(val))
    return val

  def macro_expr_fLSBOLD(self, args):
    # macros.h
    # #define fLSBOLD(VAL)  ((VAL) & 1)
    # This is only used on predicate registers, and these have boolean
    # values (see comment in f8BITSOF).
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    assert (isinstance(val, IlRegister) and val.reg.startswith('P'))
    # Used as a number (add(Rss,Rtt,Px):carry), it is the low bit.
    val.low_bit = True
    return val

  def macro_expr_fNEWREG_ST(self, args):
    assert (len(args) == 1)
    assert (args[0].type == 'REG_NEW')
    return self.lift_operand(args[0])

  def macro_expr_fNEWREG(self, args):
    assert (len(args) == 1)
    assert (args[0].type == 'REG_NEW')
    return self.lift_operand(args[0])

  def macro_expr_fLSBNEW(self, args):
    # macros.h:
    # #define fLSBNEW(PVAL)   (PVAL)
    assert (len(args) == 1)
    pval = self.lift_operand(args[0])
    if isinstance(pval, IlConst):
      if pval.val == '0':
        return IlAnd(1, IlRegister(1, 'Pd0'), IlConst(1, 1))
      if pval.val == '1':
        return IlAnd(1, IlRegister(1, 'Pd1'), IlConst(1, 1))
    return IlAnd(pval.size, pval, IlConst(1, 1))

  def macro_expr_fIMMEXT(self, args):
    # macros.h:
    #   #define fIMMEXT(IMM) (IMM = IMM)
    # no-op operation.
    assert (len(args) == 1)
    assert (args[0].type == 'IMM')
    return self.lift_operand(args[0])

  def macro_expr_fMAX(self, args):
    # macros.h:
    # #define fMAX(A, B) (((A) > (B)) ? (A) : (B))
    # IL does not support a ternary operator. Instead compute the following:
    # int max = (a >= b) * a + (a < b) * b;
    assert (len(args) == 2)
    a, b = list(map(self.lift_operand, args))
    if a.size != b.size or a.signed != b.signed:
      # The usual arithmetic conversions, as C's operators.
      signed = a.signed and b.signed
      a, b = promote(a, b)
      a.signed = b.signed = signed
    size = a.size
    if a.signed:
      return IlAdd(
          size,
          IlMult(size, IlBoolToInt(size,
                                   IlCompareSignedGreaterEqual(size, a, b)), a),
          IlMult(size, IlBoolToInt(size, IlCompareSignedLessThan(size, a, b)),
                 b))
    else:
      return IlAdd(
          size,
          IlMult(size,
                 IlBoolToInt(size, IlCompareUnsignedGreaterEqual(size, a, b)),
                 a),
          IlMult(size, IlBoolToInt(size, IlCompareUnsignedLessThan(size, a, b)),
                 b))

  def macro_expr_fMIN(self, args):
    # macros.h:
    # #define fMIN(A, B) (((A) < (B)) ? (A) : (B))
    # IL does not support a ternary operator. Instead compute the following:
    # int min = (a <= b) * a + (a > b) * b;
    assert (len(args) == 2)
    a, b = list(map(self.lift_operand, args))
    if a.size != b.size or a.signed != b.signed:
      # The usual arithmetic conversions, as C's operators.
      signed = a.signed and b.signed
      a, b = promote(a, b)
      a.signed = b.signed = signed
    size = a.size
    if a.signed:
      return IlAdd(
          size,
          IlMult(size, IlBoolToInt(size, IlCompareSignedLessEqual(size, a, b)),
                 a),
          IlMult(size, IlBoolToInt(size, IlCompareSignedGreaterThan(size, a,
                                                                    b)), b))
    else:
      return IlAdd(
          size,
          IlMult(size, IlBoolToInt(size, IlCompareUnsignedLessEqual(size, a,
                                                                    b)), a),
          IlMult(size,
                 IlBoolToInt(size, IlCompareUnsignedGreaterThan(size, a, b)),
                 b))

  def macro_expr_fABS(self, args):
    # macros.h:
    # #define fABS(A) (((A) < 0) ? (-(A)) : (A))
    # IL does not support a ternary operator. Instead compute the following:
    # int abs = (1 - 2*(a < 0)) * a;
    assert (len(args) == 1)
    a = int_promote(self.lift_operand(args[0]))
    if not a.signed:
      return a

    size = a.size
    return IlMult(
        size,
        IlSub(
            size, IlConst(size, 1),
            IlMult(
                size, IlConst(size, 2),
                IlBoolToInt(size,
                            IlCompareSignedLessThan(size, a, IlConst(size,
                                                                     0))))), a)

  def macro_expr_fBYTESWAP(self, args):
    assert (len(args) == 1)
    # Swizzle the bytes of a word.
    # uint32_t Byte0 = value & 0x000000FF;
    # uint32_t Byte1 = value & 0x0000FF00;
    # uint32_t Byte2 = value & 0x00FF0000;
    # uint32_t Byte3 = value & 0xFF000000;
    # return (Byte0 << 24) | (Byte1 << 8) | (Byte2 >> 8) | (Byte3 >> 24);
    x = self.lift_operand(args[0])
    assert (x.size == 4)
    b0 = IlAnd(x.size, x, IlConst(4, 0x000000ff))
    b1 = IlAnd(x.size, x, IlConst(4, 0x0000ff00))
    b2 = IlAnd(x.size, x, IlConst(4, 0x00ff0000))
    b3 = IlAnd(x.size, x, IlConst(4, 0xff000000))
    return IlOr(
        x.size, IlShiftLeft(x.size, b0, IlConst(1, 24)),
        IlOr(
            x.size, IlShiftLeft(x.size, b1, IlConst(1, 8)),
            IlOr(x.size, IlLogicalShiftRight(x.size, b2, IlConst(1, 8)),
                 IlLogicalShiftRight(x.size, b3, IlConst(1, 24)))))

  # | id "(" [expr ("," expr)* ] ")" ";" -> call_stmt
  @v_args(inline=False)
  def call_stmt(self, args):
    ident = args[0]
    for i, arg in enumerate(args[1:], 1):
      ternary = find_ternary(arg)
      if ternary is not None:
        # f(E[c ? t : f]) => if (c) f(E[t]); else f(E[f]);
        return self.if_stmt([
            ternary.cond,
            self.call_stmt(args[:i] + [replace_expr(arg, ternary, ternary.t)] +
                           args[i + 1:]),
            self.call_stmt(args[:i] + [replace_expr(arg, ternary, ternary.f)] +
                           args[i + 1:])
        ])
    if ident.type == 'MACRO':
      return getattr(self, 'macro_stmt_' + ident.value)(args[1:])
    assert (0)

  # | id "(" [expr ("," expr )* ] ")" -> call_expr
  @v_args(inline=False)
  def call_expr(self, args):
    ident = args[0]
    if ident.type == 'MACRO' and ident.value.startswith('conv_'):
      return self.conversion(ident.value, args[1:])
    if ident.type == 'MACRO':
      return getattr(self, 'macro_expr_' + ident.value)(args[1:])
    assert (0)

  @v_args(inline=False)
  def fbody(self, args):
    # args is a list of lists of il instructions.
    # Unpack, and return a single list of il instructions.
    #  In : a = [[1, 2], ['a', 'b', 'c'], [3]]
    #  In : list(itertools.chain(*a))
    #  Out: [1, 2, 'a', 'b', 'c', 3]
    return list(itertools.chain(*args))

  # | "{" stmt* "}" -> multi_stmt
  @v_args(inline=False)
  def multi_stmt(self, args):
    # args is a list of lists of il instructions.
    # Unpack, and return a single list of il instructions.
    #  In : a = [[1, 2], ['a', 'b', 'c'], [3]]
    #  In : list(itertools.chain(*a))
    #  Out: [1, 2, 'a', 'b', 'c', 3]
    return list(itertools.chain(*args))

  # | "CANCEL;" -> cancel_stmt
  @v_args(inline=False)
  def cancel_stmt(self, args):
    return []

  # | ";" -> empty_stmt
  @v_args(inline=False)
  def empty_stmt(self, args):
    return []

  # ?stmt: "if" "(" expr ")" stmt [ "else" stmt ] -> if_stmt
  @v_args(inline=False)
  def if_stmt(self, args):
    assert (len(args) in [2, 3])
    cond, tstmt = args[:2]
    fstmt = args[2] if len(args) == 3 else []
    ret = []
    if fstmt:
      ret += [RawC('''{ LowLevelILLabel true_case, false_case, done;''')]
      ret += [IlIf(cond, 'true_case', 'false_case')]
      ret += [IlLabel('true_case')]
      ret += tstmt
      ret += [IlGoto('done')]
      ret += [IlLabel('false_case')]
      ret += fstmt
      ret += [IlLabel('done')]
      ret += [RawC('''}''')]
    else:
      ret += [RawC('''{ LowLevelILLabel true_case, done;''')]
      ret += [IlIf(cond, 'true_case', 'done')]
      ret += [IlLabel('true_case')]
      ret += tstmt
      ret += [IlLabel('done')]
      ret += [RawC('''}''')]
    return ret

  #   | logor_e "?" "(" assg ")" ":" "(" assg ")" -> ternary_stmt
  @v_args(inline=False)
  def ternary_stmt(self, args):
    assert (len(args) == 3)
    return self.if_stmt(args)

  #   | assg ";" -> assg_stmt
  @v_args(inline=True)
  def assg_stmt(self, stmt):
    return stmt

  # | id ASSGOP expr ";" -> assg_binop_stmt
  @v_args(inline=True)
  def assg_binop_stmt(self, lvalue, op, rvalue):
    # a op= b => a = a op b, with the operator's conversions.
    terminal = {'+': 'ADDOP', '-': 'ADDOP', '&': 'BITAND', '^': 'BITXOR',
                '|': 'BITOR'}[op.value[0]]
    return self.assg(
        lvalue,
        self.expr_binop(lvalue, Token(terminal, op.value[0]), rvalue))

  # ?assg: id "=" expr
  @v_args(inline=True)
  def assg(self, lvalue, rvalue):
    rvalue = self.lift_operand(rvalue)
    ternary = find_ternary(rvalue)
    if ternary is not None:
      # a = E[c ? t : f] => if (c) a = E[t]; else a = E[f];
      return self.if_stmt([
          ternary.cond,
          self.assg(lvalue, replace_expr(rvalue, ternary, ternary.t)),
          self.assg(lvalue, replace_expr(rvalue, ternary, ternary.f))
      ])
    lvalue = self.lift_operand(lvalue)
    assert (isinstance(lvalue, IlRegister))
    if lvalue.reg.startswith('LOCAL'):
      # A local variable takes its declared type, as in C.
      return [
          IlSetRegister(lvalue.size, lvalue.reg,
                        convert(rvalue, lvalue.size, lvalue.signed))
      ]
    if lvalue.reg in TEMP_REGS and rvalue.size < lvalue.size:
      # The semantics' temporaries are 8-byte temps (their declared types are
      # hidden), so a narrower value is extended as its type says. Immediates
      # are C++ ints of the right sign, which a wider constant extends.
      if isinstance(rvalue, IlConst):
        rvalue = widen(rvalue, lvalue.size)
      elif rvalue.signed:
        rvalue = IlSignExtend(lvalue.size, rvalue)
      else:
        rvalue = IlZeroExtend(lvalue.size, rvalue)
    if lvalue.size >= 4:
      # A wider value (a 32-bit shift done in 64 bits) is truncated.
      # Predicates take comparisons, whose size is that of their operands.
      rvalue = fit_to_size(lvalue.size, rvalue)
    return [IlSetRegister(lvalue.size, lvalue.reg, rvalue)]

  # ?unary_e: "-" unary_e -> neg_expr
  @v_args(inline=False)
  def neg_expr(self, args):
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    if val.is_float:
      return IlFloatNeg(val.size, val)
    val = int_promote(val)
    result = IlNeg(val.size, val)
    result.signed = val.signed  # The promoted operand's type, as in C.
    return result

  # | "!" unary_e -> not_expr
  def not_expr(self, args):
    assert (len(args) == 1)
    val = self.lift_operand(args[0])
    return IlNot(val.size, val)

  # | "~" unary_e -> bit_not_expr
  def bit_not_expr(self, args):
    assert (len(args) == 1)
    # The low bits of ~x do not depend on promotion, so x keeps its type
    # (and predicate logic its size); later operators promote as needed.
    val = self.lift_operand(args[0])
    result = IlNot(val.size, val)
    result.signed = val.signed
    return result

  # The arithmetic, shift and bitwise levels -> expr_binop
  @v_args(inline=True)
  def expr_binop(self, op1, binop, op2):
    assert (binop.type in BINOP_TERMINALS)
    op1, op2 = list(map(self.lift_operand, [op1, op2]))
    if op1.is_float or op2.is_float:
      return float_binop(op1, binop.value, op2)
    op1, op2 = low_bit(op1), low_bit(op2)
    if binop.value in ('<<', '>>'):
      # A shift has its (promoted) left operand's type.
      op1 = int_promote(op1)
    elif binop.value in '&|^' and op1.size == op2.size:
      # Bitwise operators give the same low bits without promotion, which
      # keeps predicate logic at a predicate's size.
      pass
    else:
      op1, op2 = promote(op1, op2)
    result = self.binop(op1, binop.value, op2)
    if binop.value not in ('<<', '>>'):
      # Unsigned if either operand is, as C's usual arithmetic conversions.
      result.signed = op1.signed and op2.signed
    return result

  def binop(self, op1, binop, op2):
    # The IL for |binop| ('+', '<<', ...) on converted operands.
    if (binop == '+'):
      return IlAdd(op1.size, op1, op2)

    if (binop == '-'):
      return IlSub(op1.size, op1, op2)

    if (binop == '*'):
      return IlMult(op1.size, op1, op2)

    if (binop == '|'):
      return IlOr(op1.size, op1, op2)

    if (binop == '&'):
      return IlAnd(op1.size, op1, op2)

    if (binop == '^'):
      return IlXor(op1.size, op1, op2)

    if (binop == '<<'):
      return IlShiftLeft(op1.size, op1, op2)

    if (binop == '>>'):
      if op1.signed:
        return IlArithShiftRight(op1.size, op1, op2)
      else:
        return IlLogicalShiftRight(op1.size, op1, op2)

    assert (0)

  # | eq_e EQOP rel_e -> expr_relop
  # | rel_e RELOP shift_e -> expr_relop
  @v_args(inline=True)
  def expr_relop(self, op1, relop, op2):
    assert (relop.type in ('EQOP', 'RELOP'))
    op1, op2 = list(map(self.lift_operand, [op1, op2]))
    if op1.is_float or op2.is_float:
      return float_binop(op1, relop.value, op2)
    if op1.size != op2.size or op1.signed != op2.signed:
      # Operands of one type compare the same without promotion.
      op1, op2 = promote(op1, op2, compare=True)
    # Unsigned if either operand is, as C's usual arithmetic conversions.
    signed = op1.signed and op2.signed

    if (relop.value == '=='):
      return IlCompareEqual(op1.size, op1, op2)

    if (relop.value == '!='):
      return IlCompareNotEqual(op1.size, op1, op2)

    if (relop.value == '<='):
      if signed:
        return IlCompareSignedLessEqual(op1.size, op1, op2)
      else:
        return IlCompareUnsignedLessEqual(op1.size, op1, op2)

    if (relop.value == '<'):
      if signed:
        return IlCompareSignedLessThan(op1.size, op1, op2)
      else:
        return IlCompareUnsignedLessThan(op1.size, op1, op2)

    if (relop.value == '>='):
      if signed:
        return IlCompareSignedGreaterEqual(op1.size, op1, op2)
      else:
        return IlCompareUnsignedGreaterEqual(op1.size, op1, op2)

    if (relop.value == '>'):
      if signed:
        return IlCompareSignedGreaterThan(op1.size, op1, op2)
      else:
        return IlCompareUnsignedGreaterThan(op1.size, op1, op2)

    assert (0)

  # | logor_e LOGOR logand_e -> expr_logop
  # | logand_e LOGAND bitor_e -> expr_logop
  @v_args(inline=True)
  def expr_logop(self, op1, logop, op2):
    # a && b is a ? b : 0, and a || b is a ? 1 : b, on booleans, so b is not
    # evaluated when a decides.
    a, b = [boolean(self.lift_operand(op)) for op in (op1, op2)]
    if logop.value == '&&':
      return IlTernary(a, b, IlConst(1, 0))
    return IlTernary(a, IlConst(1, 1), b)

  # | "(" CTYPE ")" unary_e -> cast_expr
  @v_args(inline=True)
  def cast_expr(self, ctype, val):
    size, signed = c_type(ctype.value)
    return convert(self.lift_operand(val), size, signed)

  # | logor_e "?" expr ":" ternary_e -> ternary_expr
  @v_args(inline=True)
  def ternary_expr(self, cond, t, f):
    return IlTernary(*map(self.lift_operand, [cond, t, f]))

  # | id "[" expr "]" -> unexpected
  @v_args(inline=False)
  def unexpected(self, args):
    raise ValueError('Unexpected grammar rule in insn semantics')


FLOAT_BINOPS = {
    '+': IlFloatAdd, '-': IlFloatSub, '*': IlFloatMult, '/': IlFloatDiv,
    '==': IlFloatCompareEqual, '!=': IlFloatCompareNotEqual,
    '<': IlFloatCompareLessThan, '<=': IlFloatCompareLessEqual,
    '>': IlFloatCompareGreaterThan, '>=': IlFloatCompareGreaterEqual,
}


def float_binop(op1, op, op2):
  """The float IL for C's |op| on two floats or two doubles."""
  if not (op1.is_float and op2.is_float and op1.size == op2.size and
          op in FLOAT_BINOPS):
    raise ValueError('Unsupported float operation: {}'.format(op))
  return FLOAT_BINOPS[op](op1.size, op1, op2)


def low_bit(expr):
  """A predicate's fLSBOLD as a number: P & 1."""
  if getattr(expr, 'low_bit', False):
    return IlAnd(expr.size, expr, IlConst(expr.size, 1))
  return expr


def is_boolean(expr):
  """Whether |expr| is 0 or 1: a comparison, a bit (x & 1), one of those
  literals, or a logical operator's ternary of them."""
  if isinstance(expr, IlTernary):
    return is_boolean(expr.t) and is_boolean(expr.f)
  return (isinstance(expr, IlCompareExpr) or
          (isinstance(expr, IlAnd) and expr.b == IlConst(4, 1)) or
          (isinstance(expr, IlConst) and expr.val in (0, 1, '0', '1')))


def boolean(expr):
  """|expr| as a boolean, as C's logical operators take their operands."""
  if is_boolean(expr):
    return expr
  return IlCompareNotEqual(expr.size, expr, IlConst(expr.size, 0))


def widen(expr, size):
  """|expr| extended to |size| bytes as its type says."""
  if expr.size >= size:
    return expr
  if isinstance(expr, IlConst):
    # Immediates are C++ ints, and literals print as their value.
    widened = copy.copy(expr)
    widened.size = size
    return widened
  if expr.signed:
    return IlSignExtend(size, expr)
  return IlZeroExtend(size, expr)


def literal_fits(expr, size, signed):
  """Whether |expr| is a literal whose value fits |size| bytes."""
  if not isinstance(expr, IlConst):
    return False
  try:
    value = int(expr.val, 0)
  except ValueError:
    return False  # An immediate operand.
  bits = 8 * size
  if signed:
    return -(1 << (bits - 1)) <= value < (1 << (bits - 1))
  return 0 <= value < (1 << bits)


def int_promote(expr):
  """C's integer promotion: a value narrower than int widens to int, which is
  signed (it holds every value of the narrower type)."""
  if expr.size < 4:
    expr = copy.copy(widen(expr, 4))
    expr.signed = True
  return expr


def promote(op1, op2, compare=False):
  """C's integer promotions and usual arithmetic conversions, for size: both
  operands are extended to the wider one's size, at least an int's. A
  comparison with a literal that fits the other operand's type compares at
  that type instead (P == 0xff)."""
  if compare:
    for narrow, literal in ((op1, op2), (op2, op1)):
      if literal.size > narrow.size and literal_fits(literal, narrow.size,
                                                     narrow.signed):
        literal = copy.copy(literal)
        literal.size = narrow.size
        return (narrow, literal) if narrow is op1 else (literal, narrow)
  op1, op2 = int_promote(op1), int_promote(op2)
  size = max(op1.size, op2.size)
  return widen(op1, size), widen(op2, size)


def fold_constant(expr):
  """The value of a literal, or of arithmetic on literals (a lane index such
  as 2*i+1 once loops are unrolled), or None."""
  if getattr(expr, 'type', None) == 'INTCON':
    return int(expr.value, 0)
  if isinstance(expr, IlConst):
    try:
      return int(expr.val, 0)
    except ValueError:
      return None  # An immediate operand.
  ops = {
      IlAdd: lambda a, b: a + b,
      IlSub: lambda a, b: a - b,
      IlMult: lambda a, b: a * b,
      IlShiftLeft: lambda a, b: a << b,
  }
  if type(expr) in ops:
    a, b = fold_constant(expr.a), fold_constant(expr.b)
    if a is not None and b is not None:
      return ops[type(expr)](a, b)
  return None


def convert(expr, size, signed):
  """|expr| converted to a C integer type of |size| bytes, as a cast or an
  assignment does: truncated, or extended as its own type says."""
  if expr.size > size:
    expr = IlLowPart(size, expr)
  else:
    expr = copy.copy(widen(expr, size))
  expr.signed = signed
  return expr


def fit_to_size(size, expr):
  # A register write takes a value of the register's size. Word extracts
  # (fGETWORD) lift as sign-extended 8-byte values.
  if getattr(expr, 'size', size) > size:
    return IlLowPart(size, expr)
  return expr


def is_predicate_dest(reg):
  # Predicate destinations: Pd4/Pe4 operands, and P0-P3 written implicitly
  # (fWRITE_P0..fWRITE_P3). Read-write Px4 instructions combine the old value
  # in their own semantics.
  return re.fullmatch(r'P[de]V|Pd[0-3]', reg) is not None


def is_pair_operand(op):
  # Register operands are a type letter, a register id and V (old value) or
  # N (new value): RdV, RssV, RxxV. A doubled id letter is a register pair.
  return re.fullmatch(r'[A-Z]([a-z])\1[VN]', str(op)) is not None


def genptr_decl(tag, regtype, regid, regno):
  mapped_regno = 'MapRegNum(\'{0}\', insn.regno[{1}])'.format(regtype, regno)
  # A predicated instruction that is cancelled leaves its destination
  # unchanged. Its destination temps start with the register's old value, so
  # writing them back at the end of the packet restores it.
  predicated = 'A_CONDEXEC' in attribdict[tag]
  if regid in {'dd', 'ee'}:
    dest = 'AddDestReadWriteRegPair' if predicated else 'AddDestWriteOnlyRegPair'
  elif regtype == 'P':
    dest = 'AddDestReadWritePredReg' if predicated else 'AddDestWriteOnlyPredReg'
  else:
    dest = 'AddDestReadWriteReg' if predicated else 'AddDestWriteOnlyReg'
  if (regtype == 'R'):
    # GPT register
    if (regid in {'ss', 'tt'}):
      # Source register pair (read-only).
      return [
          RawC('''SourcePairReg tmp_{0}{1}V({2}, il);
                  const int {0}{1}V = tmp_{0}{1}V.Reg();'''.format(
              regtype, regid, mapped_regno))
      ]

    if (regid in {'dd', 'ee'}):
      # Destination register pair (write-only unless predicated).
      return [
          RawC('''const int {0}{1}V = ctx.{3}({2});'''
               .format(regtype, regid, mapped_regno, dest))
      ]

    if (regid in {'xx', 'yy'}):
      # Destination register pair (read-write).
      return [
          RawC('''const int {0}{1}V = ctx.AddDestReadWriteRegPair({2});'''
               .format(regtype, regid, mapped_regno, dest))
      ]

    if (regid in {'s', 't', 'u', 'v'}):
      # Source register (read-only).
      return [
          RawC('''const int {0}{1}V = {2};'''.format(regtype, regid,
                                                     mapped_regno))
      ]

    if (regid in {'d', 'e'}):
      # Destination register (write-only unless predicated).
      return [
          RawC('''const int {0}{1}V = ctx.{3}({2});'''.format(
              regtype, regid, mapped_regno, dest))
      ]

    if (regid in {'x', 'y'}):
      # Destination register (read-write).
      return [
          RawC('''const int {0}{1}V = ctx.AddDestReadWriteReg({2});'''.format(
              regtype, regid, mapped_regno))
      ]

  if (regtype == 'M' and regid == 'u'):
    # Modifier register M0 or M1 (read-only).
    return [
        RawC('''const int {0}{1}V = {2};'''.format(regtype, regid,
                                                   mapped_regno))
    ]

  if (regtype == 'P'):
    if (regid in {'s', 't', 'u', 'v'}):
      # Source register (read-only).
      return [
          RawC('''const int {0}{1}V = {2};'''.format(regtype, regid,
                                                     mapped_regno))
      ]

    if (regid in {'d', 'e'}):
      # Destination register (write-only unless predicated).
      return [
          RawC('''const int {0}{1}V = ctx.{3}({2});'''
               .format(regtype, regid, mapped_regno, dest))
      ]

    if (regid in {'x'}):
      # Destination register (read-write).
      return [
          RawC('''const int {0}{1}V = ctx.AddDestReadWritePredReg({2});'''
               .format(regtype, regid, mapped_regno, dest))
      ]

  if (regtype == 'C'):
    # Control register
    if (regid in {'ss'}):
      # Source register pair (read-only).
      return [
          RawC('''SourcePairReg tmp_{0}{1}V({2}, il);
                  const int {0}{1}V = tmp_{0}{1}V.Reg();'''.format(
              regtype, regid, mapped_regno))
      ]

    if (regid in {'dd'}):
      # Destination register pair (write-only unless predicated).
      return [
          RawC('''const int {0}{1}V = ctx.{3}({2});'''
               .format(regtype, regid, mapped_regno, dest))
      ]

    if (regid in {'s'}):
      # Source register (read-only).
      return [
          RawC('''const int {0}{1}V = {2};'''.format(regtype, regid,
                                                     mapped_regno))
      ]

    if (regid in {'d'}):
      # Destination register (write-only unless predicated).
      return [
          RawC('''const int {0}{1}V = ctx.{3}({2});'''.format(
              regtype, regid, mapped_regno, dest))
      ]

  assert (0)


def genptr_decl_new(regtype, regid, regno):
  mapped_regno = 'MapRegNum(\'{0}\', insn.regno[{1}])'.format(regtype, regno)
  if (regtype == 'N'):
    # GPT register
    assert (regid in {'s', 't'})
    return [
        RawC('''const int {0}{1}N = ctx.AddDestWriteOnlyReg({2});'''.format(
            regtype, regid, mapped_regno))
    ]

  if (regtype == 'P'):
    assert (regid in {'t', 'u', 'v'})
    return [
        RawC('''const int {0}{1}N = ctx.AddDestWriteOnlyPredReg({2});'''.format(
            regtype, regid, mapped_regno))
    ]

  assert (0)


def genptr_decl_opn(tag, regtype, regid, toss, numregs, i):
  if (is_pair(regid)):
    return genptr_decl(tag, regtype, regid, i) + zero_partial_dest(
        tag, regtype, regid)

  assert (is_single(regid))
  if is_old_val(regtype, regid, tag):
    return genptr_decl(tag, regtype, regid, i) + zero_partial_dest(
        tag, regtype, regid)

  assert (is_new_val(regtype, regid, tag))
  return genptr_decl_new(regtype, regid, i)


def zero_partial_dest(tag, regtype, regid):
  """Zeroes a write-only destination that the instruction builds in parts.

  fSETWORD, fSETHALF, fSETBYTE, fSETBIT and fSETBITS lift as read-modify-writes of the
  destination's temp. A write-only temp starts uninitialised, and Binary Ninja
  cannot fold `(uninitialised & mask) | part` away even when every part is
  written (combine, bitsplit, swiz, vector compares into a predicate).
  """
  if (not is_writeonly(regid) or 'A_CONDEXEC' in attribdict[tag] or
      regtype not in 'RCP'):
    return []
  var = '{}{}V'.format(regtype, regid)
  if not (re.search(
      r'fSET(WORD|HALF|BYTE|BIT)\(\s*[^,]+\s*,\s*{}\b'.format(var),
      semdict[tag]) or re.search(
          r'fSETBITS\(\s*[^,]+,\s*[^,]+,\s*{}\b'.format(var), semdict[tag])):
    return []
  size = 1 if regtype == 'P' else 8 if is_pair(regid) else 4
  return [
      RawC('''il.AddInstruction(il.SetRegister({0}, {1}, il.Const({0}, 0)));'''
           .format(size, var))
  ]


def genptr_decl_imm(immlett):
  i = 1 if immlett.isupper() else 0
  return [RawC('''int {0} = insn.immed[{1}];'''.format(imm_name(immlett), i))]


def set_overrides():
  for tag in behoverrides:
    behdict[tag] = behoverrides[tag]
  for tag in semoverrides:
    semdict[tag] = semoverrides[tag]


# C types of the semantics' variables: (size, signed).
C_TYPES = {
    'int': (4, True),
    'unsigned': (4, False),
    'unsigned int': (4, False),
    'long long': (8, True),
    'unsigned long long': (8, False),
}
for _bytes in (1, 2, 4, 8):
  C_TYPES['size{}s_t'.format(_bytes)] = (_bytes, True)
  C_TYPES['size{}u_t'.format(_bytes)] = (_bytes, False)
  C_TYPES['int{}_t'.format(8 * _bytes)] = (_bytes, True)
  C_TYPES['uint{}_t'.format(8 * _bytes)] = (_bytes, False)


def c_type(name):
  return C_TYPES.get(re.sub(r'\s+', ' ', name.strip()))


# The scratch temps the lifters have always had, at 8 bytes.
FIXED_TEMP_NAMES = ('tmp', 'width', 'offset', 'shamt')

# Each tag's local variables: {tag: {name: (temp, size, signed)}}.
LOCALS = {}


def local_declarations(sem):
  """{name: (size, signed)} for the variables that fHIDE declares, either
  `fHIDE(int i; size8u_t x;)` or `fHIDE(size4s_t) shamt`. fHIDE also hides
  code, which is not a declaration and is left alone."""
  decls = {}
  # The following word is only looked at: it may be the next fHIDE.
  for m in re.finditer(r'fHIDE\(\s*([^()]*?)\s*\)\s*(?=(\w*))', sem):
    body, following = m.group(1), m.group(2)
    if c_type(body) and following:
      decls[following] = c_type(body)
      continue
    for decl in filter(None, (d.strip() for d in body.split(';'))):
      dm = re.fullmatch(r'(.+?)\s+(\w+)(\s*=.*)?', decl)
      if dm and c_type(dm.group(1)):
        decls[dm.group(2)] = c_type(dm.group(1))
  return decls


def initialise_declarations(sem):
  """Replaces fHIDE declarations that initialise their variables, such as
  `fHIDE(size4u_t tmp = 0; size4u_t i;)`, with the assignments."""

  def assignments(m):
    inits = []
    for decl in filter(None, (d.strip() for d in m.group(1).split(';'))):
      dm = re.fullmatch(r'(.+?)\s+(\w+)\s*=\s*(.+)', decl)
      if dm and c_type(dm.group(1)):
        inits.append('{} = {};'.format(dm.group(2), dm.group(3)))
    return ' '.join(inits) if inits else m.group(0)

  return re.sub(r'fHIDE\(\s*([^()]*=[^()]*?)\s*\)', assignments, sem)


_FOR_RE = re.compile(r'\bfor\s*\(\s*(\w+)\s*=\s*(\d+)\s*;\s*\1\s*<\s*(\d+)\s*;'
                     r'\s*\1\s*(?:\+\+|\+=\s*(\d+))\s*\)')


def unroll_loops(text):
  """Unrolls `for (i = A; i < B; i++)` (or `i += S`) loops, with the loop
  variable replaced by its value in each copy of the body."""
  while True:
    m = _FOR_RE.search(text)
    if not m:
      return text
    var, start, end = m.group(1), int(m.group(2)), int(m.group(3))
    step = int(m.group(4) or 1)
    j = m.end()
    while text[j].isspace():
      j += 1
    # The body: a block, or one statement.
    depth, k = 0, j
    while True:
      if text[k] in '({':
        depth += 1
      elif text[k] in ')}':
        depth -= 1
        if depth == 0 and text[j] == '{':
          break
      elif text[k] == ';' and depth == 0 and text[j] != '{':
        break
      k += 1
    body = text[j:k + 1]
    copies = ''.join(
        re.sub(r'\b{}\b'.format(var), str(v), body)
        for v in range(start, end, step))
    text = text[:m.start()] + '{' + copies + '}' + text[k + 1:]


LITERAL_SUFFIX_CASTS = {'ULL': 'fCAST8u', 'UL': 'fCAST8u', 'LL': 'fCAST8s',
                        'L': 'fCAST8s', 'U': 'fCAST4u'}


def type_literals(text):
  """Gives C literals with a suffix (0x80000000ULL, 1LL) their type, as a
  cast: the grammar's literals are ints."""
  return re.sub(
      r'\b(0[xX][0-9a-fA-F]+|\d+)([uU]?[lL]{0,2})\b', lambda m: '{}({})'.format(
          LITERAL_SUFFIX_CASTS[m.group(2).upper()], m.group(1))
      if m.group(2) else m.group(0), text)


def assign_locals(tag, decls, parts):
  """Gives the local variables used in |parts| temps by size, and renames
  them local_NAME for the grammar."""
  used = {
      name: decls[name]
      for name in decls
      if name not in FIXED_TEMP_NAMES and
      any(re.search(r'\b{}\b'.format(name), part) for part in parts)
  }
  counts = {}
  LOCALS[tag] = {}
  for name, (size, signed) in used.items():
    k = counts.get(size, 0)
    if k >= 8:
      raise ValueError('More than 8 {}-byte locals'.format(size))
    counts[size] = k + 1
    LOCALS[tag]['local_' + name] = ('LOCAL{}_REG + {}'.format(size, k), size,
                                    signed)
  return [
      re.sub(r'\b({})\b'.format('|'.join(used)), r'local_\1', part)
      if used else part for part in parts
  ]


def preprocess_semantics(tag):
  sem = semdict[tag]
  decls = local_declarations(sem)
  sem = initialise_declarations(sem)
  # fATOMIC_LDST(SIZE, DST, EA, SRC, OP, NEW) loads DST from EA and stores
  # NEW, in which *EA is the loaded value: a load and a store, as Binary Ninja
  # lifts other architectures' atomic read-modify-writes. :aq and :rl
  # ordering is not lifted.
  sem = re.sub(
      r'fATOMIC_LDST\((\d+),\s*(\w+),\s*EA,\s*\w+,\s*\d+,\s*(.+?)\);',
      lambda m: '{{ fLOAD(1, {0}, u, EA, {1}); fSTORE(1, {0}, EA, {2}); }}'.format(
          m.group(1), m.group(2), m.group(3).replace('*EA', m.group(2))), sem)
  # fHIDE((size8u_t)) X is a cast, which fHIDE(A) would remove.
  sem = re.sub(r'fHIDE\(\s*\(([^()]+)\)\s*\)',
               lambda m: '({})'.format(m.group(1))
               if c_type(m.group(1)) else m.group(0), sem)

  cpreprocessor = Preprocessor()

  # Remove no-op macros.
  cpreprocessor.define(
      'fBRANCH_SPECULATE_STALL(DOTNEWVAL, JUMP_COND, SPEC_DIR, HINTBITNUM, STRBITNUM)'
  )
  cpreprocessor.define('fHIDE(A)')
  cpreprocessor.define('CANCEL')
  cpreprocessor.define('LOAD_CANCEL(A)')
  cpreprocessor.define('STORE_CANCEL(A)')
  cpreprocessor.define('fFRAMECHECK(ADDR, EA)')
  cpreprocessor.define('fBARRIER()')
  cpreprocessor.define('fSYNCH()')
  cpreprocessor.define('fISYNC()')
  cpreprocessor.define('fICFETCH(REG)')
  cpreprocessor.define('fDCFETCH(REG)')
  cpreprocessor.define('fICINVA(REG)')
  cpreprocessor.define('fL2FETCH(ADDR, HEIGHT, WIDTH, STRIDE, FLAGS)')
  cpreprocessor.define('fDCCLEANA(REG)')
  cpreprocessor.define('fDCCLEANINVA(REG)')
  cpreprocessor.define('fDCINVA(REG)')

  # Refactor and simplify macros.
  cpreprocessor.define('fFRAME_UNSCRAMBLE(VAL) VAL')
  cpreprocessor.define('fECHO(A) A')
  cpreprocessor.define('fLSBOLDNOT(VAL) !fLSBOLD(VAL)')
  # A##LL in QEMU: a 64-bit literal. (0x80000000 is unsigned in C, so a
  # 32-bit literal sign-extended to 64 bits was negative.)
  cpreprocessor.define('fCONSTLL(A) fCONST64(A)')
  cpreprocessor.define('fPAUSE(IMM)')


  # Special branch macros.
  cpreprocessor.define('fCALL(A) { fBRANCH(A, COF_TYPE_CALL); }')
  cpreprocessor.define('fCALLR(A) { fBRANCH(A, COF_TYPE_CALLR); }')

  # Effective Address (EA) register macros.
  cpreprocessor.define('fEA_RI(REG, IMM) { EA = REG + IMM; }')
  cpreprocessor.define(
      'fEA_RRs(REG, REG2, SCALE) { EA = REG + (REG2 << SCALE); }')
  cpreprocessor.define(
      'fEA_IRs(IMM, REG, SCALE) { EA = IMM + (REG << SCALE); }')
  cpreprocessor.define('fEA_IMM(IMM) { EA = (IMM); }')
  cpreprocessor.define('fEA_REG(REG) { EA = (REG); }')
  cpreprocessor.define('fEA_GPI(IMM) { EA = (fREAD_GP() + (IMM)); }')
  cpreprocessor.define('fPM_I(REG, IMM) { REG = REG + (IMM); }')
  cpreprocessor.define('fPM_M(REG, MVAL) { REG = REG + (MVAL); }')

  # Bit operations.
  cpreprocessor.define('fCAST4_4s(A) fCAST4s(A)')
  cpreprocessor.define('fCAST4_4u(A) fCAST4u(A)')
  cpreprocessor.define('fCAST8_8s(A) fCAST8s(A)')
  cpreprocessor.define('fCAST8_8u(A) fCAST8u(A)')
  cpreprocessor.define(
      'fASHIFTL(SRC, SHAMT, REGSTYPE) (fCAST##REGSTYPE##s(SRC) << (SHAMT))')
  cpreprocessor.define(
      'fASHIFTR(SRC, SHAMT, REGSTYPE) (fCAST##REGSTYPE##s(SRC) >> (SHAMT))')
  cpreprocessor.define(
      'fLSHIFTR(SRC, SHAMT, REGSTYPE) (fCAST##REGSTYPE##u(SRC) >> (SHAMT))')
  cpreprocessor.define(
      'fROTL(SRC, SHAMT, REGSTYPE) (fROTL##REGSTYPE##u(SRC, SHAMT))')
  cpreprocessor.define('fCAST4_8s(A) fCAST8s(fCAST4s(A))')
  cpreprocessor.define('fCAST4_8u(A) fCAST8u(fCAST4u(A))')

  # Shifts by a register amount, as in QEMU's macros.h: a negative amount
  # shifts the other way. 32-bit registers shift as 64-bit values
  # (REGSTYPE 4_8), so amounts from 32 to 63 give QEMU's results.
  cpreprocessor.define(
      'fBIDIR_SHIFTL(SRC, SHAMT, REGSTYPE) (((SHAMT) < 0) ? '
      '((fCAST##REGSTYPE(SRC) >> ((-(SHAMT)) - 1)) >> 1) : '
      '(fCAST##REGSTYPE(SRC) << (SHAMT)))')
  cpreprocessor.define(
      'fBIDIR_SHIFTR(SRC, SHAMT, REGSTYPE) (((SHAMT) < 0) ? '
      '((fCAST##REGSTYPE(SRC) << ((-(SHAMT)) - 1)) << 1) : '
      '(fCAST##REGSTYPE(SRC) >> (SHAMT)))')
  # Saturating shifts by a register amount, as QEMU's macros.h.
  cpreprocessor.define(
      'fSAT_ORIG_SHL(A, ORIG_REG) ((((size4s_t)((fSAT(A)) ^ '
      '((size4s_t)(ORIG_REG)))) < 0) ? fSATVALN(32, ((size4s_t)(ORIG_REG))) : '
      '((((ORIG_REG) > 0) && ((A) == 0)) ? fSATVALN(32, (ORIG_REG)) : '
      'fSAT(A)))')
  cpreprocessor.define(
      'fBIDIR_ASHIFTL_SAT(SRC, SHAMT, REGSTYPE) (((SHAMT) < 0) ? '
      '((fCAST##REGSTYPE##s(SRC) >> ((-(SHAMT)) - 1)) >> 1) : '
      'fSAT_ORIG_SHL(fCAST##REGSTYPE##s(SRC) << (SHAMT), (SRC)))')
  cpreprocessor.define(
      'fBIDIR_ASHIFTR_SAT(SRC, SHAMT, REGSTYPE) (((SHAMT) < 0) ? '
      'fSAT_ORIG_SHL((fCAST##REGSTYPE##s(SRC) << ((-(SHAMT)) - 1)) << 1, '
      '(SRC)) : (fCAST##REGSTYPE##s(SRC) >> (SHAMT)))')
  cpreprocessor.define('fBIDIR_ASHIFTL(SRC, SHAMT, REGSTYPE) '
                       'fBIDIR_SHIFTL(SRC, SHAMT, REGSTYPE##s)')
  cpreprocessor.define('fBIDIR_LSHIFTL(SRC, SHAMT, REGSTYPE) '
                       'fBIDIR_SHIFTL(SRC, SHAMT, REGSTYPE##u)')
  cpreprocessor.define('fBIDIR_ASHIFTR(SRC, SHAMT, REGSTYPE) '
                       'fBIDIR_SHIFTR(SRC, SHAMT, REGSTYPE##s)')
  cpreprocessor.define('fBIDIR_LSHIFTR(SRC, SHAMT, REGSTYPE) '
                       'fBIDIR_SHIFTR(SRC, SHAMT, REGSTYPE##u)')

  # Multiply operations.
  cpreprocessor.define('fSE32_64(A) (fCAST8s(fCAST4s(A)))')
  cpreprocessor.define('fZE32_64(A) (fCAST8u(fCAST4u(A)))')
  cpreprocessor.define('fMPY32SS(A, B) (fSE32_64(A) * fSE32_64(B))')
  cpreprocessor.define('fMPY32UU(A, B) (fZE32_64(A) * fZE32_64(B))')
  cpreprocessor.define('fMPY32SU(A, B) (fSE32_64(A) * fZE32_64(B))')
  # 16-bit and 32x16-bit multiplies, as in QEMU's macros.h.
  cpreprocessor.define('fSE16_32(A) fSXTN(16, 32, A)')
  cpreprocessor.define('fZE16_32(A) fZXTN(16, 32, A)')
  cpreprocessor.define(
      'fMPY16SS(A, B) fSE32_64(fSE16_32(A) * fSE16_32(B))')
  cpreprocessor.define(
      'fMPY16UU(A, B) fZE32_64(fZE16_32(A) * fZE16_32(B))')
  cpreprocessor.define(
      'fMPY16SU(A, B) fSE32_64(fSE16_32(A) * fZE16_32(B))')
  cpreprocessor.define('fMPY16US(A, B) fMPY16SU(B, A)')
  cpreprocessor.define('fSCALE(N, A) (fCAST8s(A) << (N))')
  cpreprocessor.define('fPASS(A) A')
  cpreprocessor.define('fROUND(A) (A + 0x8000)')

  # Saturation, as QEMU's macros.h. QEMU also sets USR.OVF when a value
  # saturates; that is not lifted.
  cpreprocessor.define(
      'fSATVALN(N, VAL) (((VAL) < 0) ? (-(fCONST64(1) << ((N) - 1))) : '
      '((fCONST64(1) << ((N) - 1)) - 1))')
  cpreprocessor.define(
      'fSATUVALN(N, VAL) (((VAL) < 0) ? 0 : ((fCONST64(1) << (N)) - 1))')
  cpreprocessor.define(
      'fSATN(N, VAL) ((fSXTN(N, 64, VAL) == (VAL)) ? (VAL) : '
      'fSATVALN(N, VAL))')
  cpreprocessor.define(
      'fSATUN(N, VAL) ((fZXTN(N, 64, VAL) == (VAL)) ? (VAL) : '
      'fSATUVALN(N, VAL))')
  cpreprocessor.define('fSAT(A) fSATN(32, A)')
  cpreprocessor.define('fSATW(A) fSATN(32, fCAST8s(A))')
  cpreprocessor.define('fSATH(VAL) fSATN(16, VAL)')
  cpreprocessor.define('fSATUH(VAL) fSATUN(16, VAL)')
  cpreprocessor.define('fSATB(VAL) fSATN(8, VAL)')
  cpreprocessor.define('fSATUB(VAL) fSATUN(8, VAL)')
  # 64-bit saturating add: the sum, unless the operands have one sign and the
  # sum the other.
  cpreprocessor.define(
      'fADDSAT64(DST, A, B) { DST = ((((~(fCAST8u(A) ^ fCAST8u(B))) & '
      '(fCAST8u(A) ^ (fCAST8u(A) + fCAST8u(B)))) >> 63) != 0) ? '
      '((((fCAST8u(A) + fCAST8u(B)) >> 63) != 0) ? '
      'fCAST8u(0x7fffffffffffffff) : fCAST8u(0x8000000000000000)) : '
      '(fCAST8u(A) + fCAST8u(B)); }')
  # Rounding, as QEMU's macros.h; fCRNDN is its conv_round(), which rounds
  # to even.
  cpreprocessor.define(
      'fRNDN(A, N) (((N) == 0) ? fSE32_64(A) : '
      '(fSE32_64(A) + (1 << ((N) - 1))))')
  cpreprocessor.define('fCRND(A) ((((A) & 0x3) == 0x3) ? ((A) + 1) : (A))')
  cpreprocessor.define(
      'fCRNDN(A, N) (((N) == 0) ? fSE32_64(A) : '
      '((((A) & ((1 << ((N) - 1)) - 1)) == 0) ? '
      '((fSE32_64(A) + (fCAST4u((1 << (N)) & (A)) >> 1)) >> (N)) : '
      '((fSE32_64(A) + (1 << ((N) - 1))) >> (N))))')
  cpreprocessor.define(
      'fCLIP(DST, SRC, U) { DST = fMIN((1 << (U)) - 1, fMAX(SRC, -(1 << (U)))); }')
  # The carry out of A + B + C, from the operands' and the sum's top bits.
  cpreprocessor.define(
      'fCARRY_FROM_ADD(A, B, C) ((((fCAST8u(A) & fCAST8u(B)) | '
      '((fCAST8u(A) | fCAST8u(B)) & ~(fCAST8u(A) + fCAST8u(B) + (C)))) '
      '>> 63) != 0)')
  cpreprocessor.define(
      'fEXTRACTU_BIDIR(INREG, WIDTH, OFFSET) '
      '(fZXTN(WIDTH, 32, fBIDIR_LSHIFTR((INREG), (OFFSET), 4_8)))')
  cpreprocessor.define(
      'fINSERT_BITS(REG, WIDTH, OFFSET, INVAL) { REG = ((WIDTH) != 0) ? '
      '((REG & ~(((1 << (WIDTH)) - 1) << (OFFSET))) | '
      '((INVAL & ((1 << (WIDTH)) - 1)) << (OFFSET))) : REG; }')
  cpreprocessor.define(
      'fMPY3216SS(A, B) (fSE32_64(A) * fSXTN(16, 64, B))')
  cpreprocessor.define(
      'fMPY3216SU(A, B) (fSE32_64(A) * fZXTN(16, 64, B))')

  # Replace macro identifiers with call expressions.
  cpreprocessor.define('fLSBNEW0 fLSBNEW(0)')
  cpreprocessor.define('fLSBNEW1 fLSBNEW(1)')
  cpreprocessor.define('fLSBNEW0NOT !fLSBNEW(0)')
  cpreprocessor.define('fLSBNEW1NOT !fLSBNEW(1)')
  cpreprocessor.define('fLSBNEWNOT(PNUM) !fLSBNEW(PNUM)')
  cpreprocessor.define('fGET_LPCFG fREAD_LPCFG()')
  cpreprocessor.define('fREAD_SA0 fREAD_SA(0)')
  cpreprocessor.define('fREAD_SA1 fREAD_SA(1)')
  cpreprocessor.define('fREAD_LC0 fREAD_LC(0)')
  cpreprocessor.define('fREAD_LC1 fREAD_LC(1)')
  cpreprocessor.define('fWRITE_LC0(VAL) fWRITE_LC(0, VAL)')
  cpreprocessor.define('fWRITE_LC1(VAL) fWRITE_LC(1, VAL)')
  cpreprocessor.define(
      'fWRITE_LOOP_REGS0(START, COUNT) fWRITE_LOOP_REGS(0, START, COUNT)')
  cpreprocessor.define(
      'fWRITE_LOOP_REGS1(START, COUNT) fWRITE_LOOP_REGS(1, START, COUNT)')

  # Locked load/store.
  cpreprocessor.define(
      'fLOAD_LOCKED(NUM, SIZE, SIGN, EA, DST) fLOAD(NUM, SIZE, SIGN, EA, DST);')
  cpreprocessor.define(
      'fSTORE_LOCKED(NUM, SIZE, EA, SRC, PRED) fSTORE_LOCKED(NUM, SIZE, EA, SRC, PRED);'
  )

  # Immext.
  cpreprocessor.define('fMUST_IMMEXT(IMM) fIMMEXT(IMM)')

  parts = []
  if 'A_NEWCMPJUMP' in attribdict[tag]:
    # Extract compare part of a compare-jump instruction.
    cpreprocessor.define('fPART1(WORK) */{ WORK; }/*')
    clean = ''.join([tok.value for tok in cpreprocessor.parsegen(sem)])
    clean = ''.join(
        [tok.value for tok in cpreprocessor.parsegen('/*' + clean + '*/')])
    parts.append(clean)

  # Remove compare part of a compound compare-jump instruction.
  cpreprocessor.define('fPART1(WORK)')
  clean = ''.join([tok.value for tok in cpreprocessor.parsegen(sem)])
  clean = ''.join([tok.value for tok in cpreprocessor.parsegen(clean)])
  parts.append(clean)
  return assign_locals(tag, decls,
                       [type_literals(unroll_loops(part)) for part in parts])


def genptr_decl_fixed_pred(parts):
  ret = []
  seen = set()

  cpreprocessor = Preprocessor()
  cpreprocessor.define('fLSBNEW(PVAL) */PVAL/*')
  cpreprocessor.define('fWRITE_P0(PVAL) */0/*')
  cpreprocessor.define('fWRITE_P1(PVAL) */1/*')
  cpreprocessor.define('fWRITE_P2(PVAL) */2/*')
  cpreprocessor.define('fWRITE_P3(PVAL) */3/*')
  cpreprocessor.define('fREAD_P0(PVAL)  */0/*')
  for sem in parts:
    clean = ''.join([tok.value for tok in cpreprocessor.parsegen(sem)])
    clean = ''.join(
        [tok.value for tok in cpreprocessor.parsegen('/*' + clean + '*/')])
    pid = clean.strip()
    if pid != '' and pid in '0123' and pid not in seen:
      ret += [
          RawC(
              '''const int Pd{0} = ctx.AddDestReadWritePredReg(MapRegNum('P', {0}));'''
              .format(pid))
      ]
      seen.add(pid)
  return ret


def process_semantics(tag, sem):
  tree = semantics_parser.parse(sem)
  return SemanticsTreeTransformer(tag).transform(tree)


def gen_il_func(tag, regs, imms):
  ## Declare all the operands (regs and immediates)
  prog = []
  for i, (regtype, regid, toss, numregs) in enumerate(regs):
    prog += genptr_decl_opn(tag, regtype, regid, toss, numregs, i)
  for immlett, bits, immshift in imms:
    prog += genptr_decl_imm(immlett)

  parts = preprocess_semantics(tag)
  prog += genptr_decl_fixed_pred(parts)

  if len(parts) > 1:
    part1, part2 = parts
    prog += [RawC('''if (insn.part1) {''')]
    prog += process_semantics(tag, part1)
    prog += [RawC('''} else {''')]
    prog += process_semantics(tag, part2)
    prog += [RawC('''}''')]

  else:
    prog += process_semantics(tag, parts[0])

  lines = []
  branch_condition = find_branch_condition(tag, prog)
  for il_insn in prog:
    if isinstance(il_insn, IlBranch):
      # Branch instructions are deferred to the end of the packet.
      continue
    elif isinstance(il_insn, IlSetRegister) and is_predicate_dest(il_insn.reg):
      # The packet ANDs a predicate's writes together.
      lines.append('''ctx.WritePredicate({0}, {1});'''.format(
          il_insn.reg, il_insn.val))
    elif isinstance(il_insn, IlExprId):
      lines.append('''il.AddInstruction({0});'''.format(il_insn))
    elif isinstance(il_insn, IlLabel):
      lines.append('''il.MarkLabel({0});'''.format(il_insn))
    elif isinstance(il_insn, RawC):
      lines.append(il_insn)
    else:
      assert (0)

  if branch_condition:
    cond, reads = branch_condition
    lines.append(
        '''ctx.SetBranchCondition(insn_num, [=, &il]() {{ return {0}; }}, {{{1}}});'''
        .format(cond, ', '.join(reads)))
  return '\n'.join(lines)


def find_branch_condition(tag, prog):
  """Returns (condition, registers it reads) of a conditional branch.

  A conditional jump or call lifts as `if (cond) { branch-taken flag = 1 }`,
  and the branch is taken at the end of the packet. If the packet does not
  write the registers the condition reads, the end of the packet can test the
  condition itself (PacketContext::SetBranchCondition). The registers are the
  old-value operands (RsV, PuV) and fixed registers (HEX_REG_*); new values
  (PuN, Pd0) are temps the packet's write-back leaves alone.
  """
  attribs = attribdict[tag]
  if ('A_BN_COND_J' not in attribs or 'A_HWLOOP0_END' in attribs or
      'A_HWLOOP1_END' in attribs):
    return None
  taken = [
      k for k, insn in enumerate(prog) if isinstance(insn, IlSetRegister) and
      insn.reg == 'BRANCH_TAKEN_ARRAY + insn_num'
  ]
  if len(taken) != 1:
    return None
  # The branch's `if` is the last one before the flag is set.
  guards = [
      insn for insn in prog[:taken[0]]
      if isinstance(insn, IlIf) and insn.t == 'true_case'
  ]
  if not guards:
    return None
  cond = guards[-1].cond
  reads = []

  def collect(expr):
    if isinstance(expr, IlRegister):
      if re.fullmatch(r'[A-Z][a-z]{1,2}V|HEX_REG_\w+', expr.reg):
        reads.append(expr.reg)
    for value in vars(expr).values():
      if isinstance(value, IlExprId):
        collect(value)

  collect(cond)
  return str(cond), uniquify(reads)


# Opcodes without lifted semantics are lifted as intrinsics (plugin/
# intrinsics.h). Their operands come from these register types: general,
# control and predicate registers, new-value sources and the modifier
# registers (C6, C7). HVX vector and predicate registers, and system and guest
# registers, are not Binary Ninja registers and are left out.
INTRINSIC_REG_TYPES = 'RCPNM'
MAX_INTRINSIC_INPUTS = 12
MAX_INTRINSIC_OUTPUTS = 6

# Unlifted opcodes that are not intrinsics, and what they lift to.
SPECIAL_LIFTS = {
    # A hint for indirect jump prediction, with no other effect.
    'J4_hintjumpr': ['il.AddInstruction(il.Nop());'],
    # Trap to the guest operating system.
    'J2_trap1': ['il.AddInstruction(il.SystemCall());'],
    # Return from exception, to ELR, which is not modelled.
    'J2_rte': ['il.AddInstruction(il.Unimplemented());'],
}


def intrinsic_operands(tag, regs, imms):
  """Returns the declarations, inputs and outputs of an intrinsic lifter.

  Inputs are (name, size, C++ expression) and outputs (name, size, C++
  register variable). Destinations go through PacketContext temps, so packet
  semantics hold. A predicated instruction's destinations also come in as
  inputs, because a cancelled instruction leaves them unchanged.
  """
  predicated = 'A_CONDEXEC' in attribdict[tag]
  decls, inputs, outputs = [], [], []
  for i, (regtype, regid, _, _) in enumerate(regs):
    if regtype not in INTRINSIC_REG_TYPES:
      continue
    name = regtype + regid
    if regtype == 'M':
      inputs.append(
          (name, 4, 'il.Register(4, HEX_REG_M0 + insn.regno[{}])'.format(i)))
      continue
    if regtype == 'N':
      # New-value source: the producer's temp in this packet.
      var = 'N{}N'.format(regid)
      decls.append(
          "const int {0} = ctx.AddDestWriteOnlyReg(MapRegNum('N', insn.regno[{1}]));"
          .format(var, i))
      inputs.append((name, 4, 'il.Register(4, {})'.format(var)))
      continue
    mapped = "MapRegNum('{}', insn.regno[{}])".format(regtype, i)
    var = '{}{}V'.format(regtype, regid)
    if regtype == 'P':
      size, kind = 1, 'PredReg'
    elif is_pair(regid):
      size, kind = 8, 'RegPair'
    else:
      size, kind = 4, 'Reg'
    if is_written(regid):
      rw = is_readwrite(regid) or predicated
      decls.append('const int {} = ctx.AddDest{}{}({});'.format(
          var, 'ReadWrite' if rw else 'WriteOnly', kind, mapped))
      if rw:
        inputs.append((name, size, 'il.Register({}, {})'.format(size, var)))
      outputs.append((name, size, var))
    elif size == 8:
      decls.append(
          'SourcePairReg tmp_{0}({1}, il);\nconst int {0} = tmp_{0}.Reg();'
          .format(var, mapped))
      inputs.append((name, 8, 'il.Register(8, {})'.format(var)))
    else:
      inputs.append(
          (name, size, 'il.Register({}, {})'.format(size, mapped)))
  for n in range(4):
    if 'A_IMPLICIT_WRITES_P{}'.format(n) in attribdict[tag]:
      var = 'P{}_implicit'.format(n)
      decls.append('const int {} = ctx.AddDest{}PredReg(HEX_REG_P{});'.format(
          var, 'ReadWrite' if predicated else 'WriteOnly', n))
      if predicated:
        inputs.append(('P{}'.format(n), 1, 'il.Register(1, {})'.format(var)))
      outputs.append(('P{}'.format(n), 1, var))
  for immlett, bits, _ in imms:
    inputs.append(('#{}{}'.format(immlett, bits), 4, 'il.Const(4, insn.immed[{}])'
                   .format(1 if immlett.isupper() else 0)))
  assert len(inputs) <= MAX_INTRINSIC_INPUTS, tag
  assert len(outputs) <= MAX_INTRINSIC_OUTPUTS, tag
  return decls, inputs, outputs


def gen_intrinsic_func(tag, regs, imms):
  if tag in SPECIAL_LIFTS:
    return '\n'.join(SPECIAL_LIFTS[tag])
  decls, inputs, outputs = intrinsic_operands(tag, regs, imms)
  return '\n'.join(decls + [
      'il.AddInstruction(il.Intrinsic({{{0}}}, {1}, {{{2}}}));'.format(
          ', '.join('RegisterOrFlag::Register({})'.format(o[2])
                    for o in outputs), tag, ', '.join(i[2] for i in inputs))
  ])


def gen_intrinsic_info(tag, regs, imms):
  """Returns the opcode_intrinsics entry of a tag (plugin/intrinsics.h)."""
  if tag in SPECIAL_LIFTS:
    return '{false}'
  _, inputs, outputs = intrinsic_operands(tag, regs, imms)
  memory = 'A_LOAD' in attribdict[tag] or 'A_STORE' in attribdict[tag]
  operands = lambda ops: ', '.join('{{"{}", {}}}'.format(o[0], o[1]) for o in ops)
  return '{{true, {0}, {1}, {2}, {{{3}}}, {{{4}}}}}'.format(
      'true' if memory else 'false', len(inputs), len(outputs),
      operands(inputs), operands(outputs))


def main():
  read_semantics_file(sys.argv[1])
  read_attribs_file(sys.argv[2])
  set_overrides()
  calculate_attribs()
  tagregs = get_tagregs()
  tagimms = get_tagimms()

  f = StringIO()

  f.write('''
#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "third_party/qemu-hexagon/attribs.h"
#include "third_party/qemu-hexagon/iclass.h"
#include "third_party/qemu-hexagon/insn.h"
#include "third_party/qemu-hexagon/opcodes.h"
#include "plugin/packet_context.h"
#include "plugin/hex_regs.h"
#include "plugin/intrinsics.h"

using namespace BinaryNinja;

#define PCALIGN 4
#define PCALIGN_MASK (PCALIGN - 1)

// EA_REG, TMP_REG, WIDTH_REG, OFFSET_REG and SHAMT_REG come from
// packet_context.h, with the rest of the LLIL_TEMP layout.

''')

  # A legacy encoding's instruction, TAG_deprecated, lifts like TAG.
  supported_tags = SUPPORTED_TAGS + [
      tag for tag in tags if tag.endswith('_deprecated') and
      tag[:-len('_deprecated')] in SUPPORTED_TAGS
  ]
  for tag in supported_tags:
    f.write('''/*\n{0}:\n{1}\n{2}\n*/\n'''.format(tag, behdict[tag],
                                                  semdict[tag]))
    f.write('''void lift_{0}(Architecture *arch,
                             uint64_t pc,
                             const Packet &pkt,
                             const Insn &insn,
                             int insn_num,
                             PacketContext &ctx) {{
                LowLevelILFunction &il = ctx.IL();\n'''.format(tag))
    f.write(gen_il_func(tag, tagregs[tag], tagimms[tag]))
    f.write('}\n\n')

  supported_set = set(supported_tags)
  intrinsic_tags = [tag for tag in tags if tag not in supported_set]
  for tag in intrinsic_tags:
    f.write('''/*\n{0}: {1} (intrinsic)\n*/\n'''.format(tag, behdict[tag]))
    f.write('''void lift_{0}(Architecture *arch,
                             uint64_t pc,
                             const Packet &pkt,
                             const Insn &insn,
                             int insn_num,
                             PacketContext &ctx) {{
                LowLevelILFunction &il = ctx.IL();\n'''.format(tag))
    f.write(gen_intrinsic_func(tag, tagregs[tag], tagimms[tag]))
    f.write('\n}\n\n')

  f.write('extern const IntrinsicInfo opcode_intrinsics[XX_LAST_OPCODE] = {\n')
  for tag in intrinsic_tags:
    f.write('[{0}] = {1},\n'.format(
        tag, gen_intrinsic_info(tag, tagregs[tag], tagimms[tag])))
  f.write('};\n\n')

  f.write('''typedef void (*IlLiftFunc)(Architecture *arch,
                                        uint64_t pc,
                                        const Packet &pkt,
                                        const Insn &insn,
                                        int insn_num,
                                        PacketContext &ctx);\n\n''')
  f.write('extern const IlLiftFunc opcode_liftptr[XX_LAST_OPCODE] = {\n')
  for tag in tags:
    f.write('[{0}] = lift_{0},\n'.format(tag))
  f.write('};\n')

  realf = open(sys.argv[3], 'w')
  realf.write(f.getvalue())
  realf.close()
  f.close()


if __name__ == '__main__':
  main()
