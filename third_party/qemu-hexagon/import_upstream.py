#!/usr/bin/env python3
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
"""Imports the instruction definitions from a QEMU source checkout.

  python import_upstream.py ~/src/qemu

Replaces imported/ with QEMU's target/hexagon/imported/, unmodified, and
attribs_def.h with QEMU's attribs_def.h.inc plus the plugin's attributes from
attribs_local_def.h. Copies QEMU's tag_rev_info.c.inc, the version that
introduced each instruction, which the tests read. Records the QEMU commit in
UPSTREAM. The rest of this directory is an older, modified snapshot
(README.md) and is left alone.
"""

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
IMPORTED = 'target/hexagon/imported'
ATTRIBS = 'target/hexagon/attribs_def.h.inc'
TAG_REV_INFO = 'target/hexagon/tag_rev_info.c.inc'
LAST_ATTRIB = '/* Keep this as the last attribute: */'


def git(checkout, *args):
  return subprocess.run(['git', '-C', checkout] + list(args),
                        check=True,
                        capture_output=True,
                        text=True).stdout.strip()


def main():
  parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
  parser.add_argument('qemu', help='a QEMU git checkout')
  args = parser.parse_args()

  files = git(args.qemu, 'ls-files', IMPORTED).splitlines()
  if not files:
    sys.exit('{} has no {}'.format(args.qemu, IMPORTED))
  dst = os.path.join(HERE, 'imported')
  shutil.rmtree(dst)
  for name in files:
    target = os.path.join(dst, os.path.relpath(name, IMPORTED))
    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.copyfile(os.path.join(args.qemu, name), target)

  # The plugin's attributes go before the last one, which counts them.
  with open(os.path.join(args.qemu, ATTRIBS)) as f:
    attribs = f.read()
  if attribs.count(LAST_ATTRIB) != 1:
    sys.exit('{} has no single "{}"'.format(ATTRIBS, LAST_ATTRIB))
  with open(os.path.join(HERE, 'attribs_local_def.h')) as f:
    local = f.read()
  with open(os.path.join(HERE, 'attribs_def.h'), 'w') as f:
    f.write(attribs.replace(LAST_ATTRIB, local + '\n' + LAST_ATTRIB))

  shutil.copyfile(os.path.join(args.qemu, TAG_REV_INFO),
                  os.path.join(HERE, os.path.basename(TAG_REV_INFO)))

  with open(os.path.join(HERE, 'UPSTREAM'), 'w') as f:
    f.write('imported/ and attribs_def.h are from {}\nat commit {} ({}).\n'.format(
        git(args.qemu, 'remote', 'get-url', 'origin'),
        git(args.qemu, 'rev-parse', 'HEAD'),
        git(args.qemu, 'log', '-1', '--format=%cs')))
  print('Imported {} files.'.format(len(files)))


if __name__ == '__main__':
  main()
