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
"""The Hexagon version that introduced each instruction.

Versions are numbers: 5, 55, 60 ... 85. They come from QEMU's
tag_rev_info.c.inc, which lists the instructions added since V5. HLX
instructions (LX_*) are not listed; they are an extension of the newest
cores, given here as NEWEST.
"""

import functools
import os
import re

TAG_REV_INFO = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..',
                            'third_party', 'qemu-hexagon',
                            'tag_rev_info.c.inc')
NEWEST = 85
LLVM_NEWEST = 81  # Homebrew LLVM 23's newest CPU, hexagonv81.


@functools.lru_cache()
def introduced_versions(path=TAG_REV_INFO):
  with open(path) as f:
    return {
        tag: int(version) for tag, version in re.findall(
            r'\[(\w+)\] = \{ \.introduced = HEX_VER_V(\d+)', f.read())
    }


def introduced(tag):
  if tag.startswith('LX_'):
    return NEWEST
  return introduced_versions().get(tag, 5)


def known_to_llvm(tag):
  """Whether LLVM decodes |tag|: it has no HMX (M8_*) or HLX instructions."""
  return introduced(tag) <= LLVM_NEWEST and not tag.startswith('M8_')
