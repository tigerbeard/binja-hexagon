## Setup

The plugin builds against the Binary Ninja C++ API in
`third_party/binaryninja-api`. That submodule must match the Binary Ninja you
load the plugin into: Binary Ninja refuses plugins built for another core ABI
version. The pinned commit is the one named in your installation's
`api_REVISION.txt` (on macOS,
`/Applications/Binary Ninja.app/Contents/Resources/api_REVISION.txt`). It is
currently Binary Ninja 6.1.

### Third party dependencies

Download the plugin's third party repositories. Binary Ninja's API needs only
its `vendor/fmt` submodule; its other submodules are large and unused here:

```
$ git submodule update --init third_party/abseil-cpp third_party/gflags \
    third_party/glog third_party/googletest third_party/binaryninja-api
$ git -C third_party/binaryninja-api submodule update --init vendor/fmt
```

The code generators, their tests and the headless tests run on one Python
interpreter (3.12 or newer). Create a `venv` with the build dependencies:

```
$ python3 -m venv .venv
$ .venv/bin/pip install -r requirements.txt
```

### Build

```
$ cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DPython3_EXECUTABLE=$PWD/.venv/bin/python
$ cmake --build build
```

The build accepts the following variables, set using `cmake -D`:

- **BN_INSTALL_DIR**: Binary Ninja installation directory. Defaults to
  `/Applications/Binary Ninja.app` on macOS and `~/binaryninja` elsewhere.
  Used to find the Python API for the tests and the core library at run time.

- **CMAKE_POLICY_VERSION_MINIMUM**: needed with CMake 4, because the pinned
  gflags, glog and googletest declare CMake versions older than 3.5.

- **Python3_EXECUTABLE**: the interpreter from the `venv` above.

- **USE_DOCKER_BUILD**: Tells build system to cross-compile Hexagon targets in
  a custom Docker image. Image is downloaded from QEMU's registry.

On macOS, if linking fails with `unknown architecture` in `libSystem.tbd`, the
Command Line Tools linker is older than the default SDK. Point the build at an
older SDK, e.g.
`-DCMAKE_OSX_SYSROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk`.

To build using `clang` on Linux, override CC and include `clang_overrides.cmake`:

```
$ CC="$(which clang)" CXX="$(which clang++)" cmake -S . -B build \
  -DCMAKE_USER_MAKE_RULES_OVERRIDE="${PWD}/cmake/clang_overrides.cmake"
```

### Binary Ninja plugin

Link the plugin library into the user plugins directory:

```
# macOS
$ ln -s "$PWD/build/plugin/libarch_hexagon.dylib" \
    ~/Library/Application\ Support/Binary\ Ninja/plugins/
# Linux
$ ln -s "$PWD/build/plugin/libarch_hexagon.so" ~/.binaryninja/plugins/
```

### Tests

```
$ ctest --test-dir build --output-on-failure
```

This runs the C++ unit tests, the code generator tests and the headless
end-to-end tests. The end-to-end tests load the plugin from the user plugins
directory and check that it is this build's library. Headless use needs a
Binary Ninja license that allows it (Commercial or above).
