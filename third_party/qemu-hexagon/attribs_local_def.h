/*
 * Copyright (C) 2026 The binja-hexagon contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * The plugin's own attributes, which hex_common.add_bn_attribs derives from
 * the semantics. import_upstream.py adds them to QEMU's attribs_def.h.inc,
 * before its last attribute, to make attribs_def.h.
 */
DEF_ATTRIB(BN_RETURN, "Return from function", "", "")
DEF_ATTRIB(BN_SYSTEM, "System call", "", "")
DEF_ATTRIB(BN_COND_J, "Conditional jump", "", "")
