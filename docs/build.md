# Build the server

Build from the repository root. The analyzer engine is included under `vendor/analyzer`. Python runs the tests. The installed server runs as a native executable.

## Windows x64

In an MSYS2 UCRT64 shell, install the build dependencies.

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-{gcc,cmake,ninja,pkgconf,glib2,sqlite3,zlib,expat,libzip,libxlsxwriter,yyjson,python}
```

## Ubuntu 24.04 x64

```sh
sudo apt-get install build-essential cmake ninja-build pkg-config python3 ca-certificates \
  libglib2.0-dev libsqlite3-dev zlib1g-dev libexpat1-dev libzip-dev libxlsxwriter-dev
```

CMake uses the system yyjson library when available. Otherwise it fetches a pinned, checksum-verified source archive during the build.

## Compile and test

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix dist/local
```

Use the executable in `dist/local/bin`. On Windows, keep the bundled DLLs beside it. On Linux, install the runtime libraries for the distribution used to build it.
