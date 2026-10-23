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
#
cmake_minimum_required (VERSION 3.28)
project ("binja-hexagon" C CXX ASM)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# C++20 is used without modules, as in binaryninja-api.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

# Generators, generator tests and headless tests all run on this interpreter.
# It needs lark-parser and pcpp (requirements.txt); binaryninja-api needs >= 3.12.
find_package(Python3 3.12 COMPONENTS Interpreter REQUIRED)

# Binary Ninja installation, for the headless tests' Python path and the
# test executables' rpath. binaryninja-api locates the core library itself.
if(NOT BN_INSTALL_DIR)
  if(DEFINED ENV{BN_INSTALL_DIR})
    set(BN_INSTALL_DIR "$ENV{BN_INSTALL_DIR}")
  elseif(APPLE)
    set(BN_INSTALL_DIR "/Applications/Binary Ninja.app")
  else()
    set(BN_INSTALL_DIR "$ENV{HOME}/binaryninja")
  endif()
endif()
if(APPLE)
  set(BN_PYTHON_DIR "${BN_INSTALL_DIR}/Contents/Resources/python")
  set(BN_CORE_DIR "${BN_INSTALL_DIR}/Contents/MacOS")
else()
  set(BN_PYTHON_DIR "${BN_INSTALL_DIR}/python")
  set(BN_CORE_DIR "${BN_INSTALL_DIR}")
endif()
set(CMAKE_BUILD_RPATH "${BN_CORE_DIR}")

# Set default build type.
if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to 'Release' as none was specified.")
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING
      "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif()

SET( CMAKE_EXPORT_COMPILE_COMMANDS ON )

add_custom_target(
    copy-compile-commands ALL
    ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
)

# Binary Ninja plugins require "-fPIC".
set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

option(USE_DOCKER_BUILD
  "If ON, cross-builds Hexagon targets using a docker image from QEMU's registry" OFF)

# Enable testing.
enable_testing()
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

#
# third_party dependencies.
#
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL "" FORCE)
SET(HEADLESS ON)
add_subdirectory(third_party/googletest EXCLUDE_FROM_ALL)
add_subdirectory(third_party/abseil-cpp EXCLUDE_FROM_ALL)
add_subdirectory(third_party/binaryninja-api EXCLUDE_FROM_ALL)

#
# Plugin project.
#
include_directories(${CMAKE_SOURCE_DIR})
add_subdirectory(scripts)
add_subdirectory(test_binaries)
add_subdirectory(tests)
add_subdirectory(third_party/qemu-hexagon)
add_subdirectory(plugin)
