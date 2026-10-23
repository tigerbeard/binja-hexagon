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
"""Runs Hexagon packets in QEMU's system emulator, through its gdbstub.

  with Qemu() as qemu:
    regs = qemu.run(code, {'r1': 10, 'r2': 32}, packets=1)

QEMU executes one packet per single step. Code goes into RAM at CODE_ADDR,
or the address given, and runs from there; the registers named in the result are the general
registers r0-r31, the predicates p0-p3, m0, m1 and usr.

Set QEMU_HEXAGON to the qemu-system-hexagon binary if it is not on PATH.
"""

import os
import shutil
import socket
import struct
import subprocess
import time

QEMU = os.environ.get('QEMU_HEXAGON', 'qemu-system-hexagon')
CPU = 'v73'
CODE_ADDR = 0x1000

# Register numbers in QEMU's target description (hexagon-core.xml): r0-r31,
# then the control registers, then p0-p3 as 8-bit registers.
_CONTROL = ['sa0', 'lc0', 'sa1', 'lc1', 'p3_0', 'c5', 'm0', 'm1', 'usr', 'pc',
            'ugp', 'gp', 'cs0', 'cs1']
REGNUM = dict({'r%d' % i: i for i in range(32)},
              **{name: 32 + i for i, name in enumerate(_CONTROL)},
              **{'p%d' % i: 64 + i for i in range(4)})
RESULT_REGS = ['r%d' % i for i in range(32)] + ['p0', 'p1', 'p2', 'p3', 'm0',
                                                'm1', 'usr']


def available():
  return shutil.which(QEMU) is not None


class Qemu:

  def __init__(self):
    with socket.socket() as probe:
      probe.bind(('127.0.0.1', 0))
      self.port = probe.getsockname()[1]
    self.proc = subprocess.Popen(
        [QEMU, '-M', 'virt', '-cpu', CPU, '-nographic', '-S', '-gdb',
         'tcp:127.0.0.1:%d' % self.port, '-monitor', 'none', '-serial',
         'none'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 10
    while True:
      try:
        self.sock = socket.create_connection(('127.0.0.1', self.port))
        break
      except ConnectionRefusedError:
        if time.time() > deadline:
          self.close()
          raise
        time.sleep(0.05)
    self.buf = b''
    self._send('?')

  def __enter__(self):
    return self

  def __exit__(self, *exc):
    self.close()

  def close(self):
    if getattr(self, 'sock', None):
      self.sock.close()
      self.sock = None
    self.proc.kill()
    self.proc.wait()

  def _send(self, cmd):
    """Sends a gdb remote packet and returns the reply's body."""
    self.sock.sendall(('$%s#%02x' % (cmd, sum(cmd.encode()) & 0xff)).encode())
    while True:
      start = self.buf.find(b'$')
      end = self.buf.find(b'#', start) if start >= 0 else -1
      if end >= 0 and len(self.buf) >= end + 3:
        break
      data = self.sock.recv(65536)
      if not data:
        raise ConnectionError('QEMU closed the gdb connection')
      self.buf += data
    body = self.buf[start + 1:end].decode('latin1')
    self.buf = self.buf[end + 3:]
    self.sock.sendall(b'+')
    return body

  def _set(self, name, value):
    size = 1 if name in ('p0', 'p1', 'p2', 'p3') else 4
    data = (value & ((1 << (8 * size)) - 1)).to_bytes(size, 'little').hex()
    if self._send('P%x=%s' % (REGNUM[name], data)) != 'OK':
      raise RuntimeError('cannot set ' + name)

  def _get(self, name):
    return int.from_bytes(bytes.fromhex(self._send('p%x' % REGNUM[name])),
                          'little')

  def run(self, code, regs, packets, address=CODE_ADDR):
    """Runs |packets| packets of |code| from |address|, with the registers in
    |regs| (others 0), and returns RESULT_REGS' values."""
    if self._send('M%x,%x:%s' % (address, len(code), code.hex())) != 'OK':
      raise RuntimeError('cannot write code')
    for name in RESULT_REGS:
      if name not in ('p0', 'p1', 'p2', 'p3'):
        self._set(name, 0)
    self._set('p3_0', 0)
    for name, value in regs.items():
      self._set(name, value)
    self._set('pc', address)
    for _ in range(packets):
      reply = self._send('s')
      if not reply.startswith('T05'):
        raise RuntimeError('step stopped with ' + reply)
    return {name: self._get(name) for name in RESULT_REGS}
