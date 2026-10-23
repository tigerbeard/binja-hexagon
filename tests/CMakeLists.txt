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
#

# Regression tests on llvm-mc snippets, analysed headless in Binary Ninja.
# Set HEXAGON_LLVM_BIN to the directory holding llvm-mc if it is not
# /opt/homebrew/opt/llvm/bin or on PATH; without it the tests are skipped.
add_test(NAME regression_tests
  COMMAND ${Python3_EXECUTABLE} test_regressions.py
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
set_tests_properties(regression_tests PROPERTIES
  ENVIRONMENT "PYTHONPATH=${BN_PYTHON_DIR};HEXAGON_PLUGIN=$<TARGET_FILE:arch_hexagon>"
)
