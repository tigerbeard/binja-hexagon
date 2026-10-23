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
"""Helpers shared by the headless end-to-end IL tests."""

import os
import re
import sys

_TEMP_RE = re.compile(r'\btemp(\d+)')


def normalize_il(text):
  """Renames LLIL temps by order of first appearance and drops blank lines.

  Temp numbers depend on lifter internals, and Binary Ninja versions differ in
  the blank lines they put into HLIL listings. Renaming keeps temp identity,
  so two uses of one temp still compare equal and a collision stays visible.
  """
  names = {}

  def rename(match):
    if match.group(1) not in names:
      names[match.group(1)] = 'temp#{}'.format(len(names))
    return names[match.group(1)]

  lines = [_TEMP_RE.sub(rename, line) for line in text.split('\n')]
  # Listings start with an empty line so that they read well in a diff.
  return '\n'.join(lines[:1] + [l for l in lines[1:] if l.strip()])


def check_environment(binja):
  """Prints the BN build and checks that BN loaded this build's plugin."""
  print('Binary Ninja {}'.format(binja.core_version()), file=sys.stderr)
  if 'hexagon' not in binja.Architecture:
    raise RuntimeError('hexagon architecture is not registered; '
                       'is the plugin installed in the user plugins dir?')
  built = os.environ.get('HEXAGON_PLUGIN')
  if built:
    installed = os.path.join(binja.user_plugin_path(), os.path.basename(built))
    if os.path.realpath(installed) != os.path.realpath(built):
      raise RuntimeError('{} does not resolve to {}'.format(installed, built))
