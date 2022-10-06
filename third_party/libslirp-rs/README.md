Fork init'ed from 19553209436ae7b9e036641f4013246111192d5c.

This directory is NOT a crate. It contains heavily forked code from the
libslirp-rs project that has been tightly integrated with `net_util`.

libslirp-rs depends on a bunch of libraries (libslirp and its dependencies).
Run `upload_libslirp_prebuilts.ps1` helps to setup msys, fetch sources, build and
upload prebuilts given the version of the prebuilts.



## Manually building dependencies

### On windows

Install [Msys2](https://www.msys2.org) which is used for building libslirp, a third party library
used by the emulator. Open a msys2 window, install necessary packages with the following commands:

```sh
pacman -S mingw-w64-x86_64-meson ninja git mingw-w64-x86_64-gcc mingw-w64-x86_64-glib2 mingw-w64-x86_64-pkg-config
```

Note: You may need to add msys locations(which by default is C:\\msys64\\mingw64\\bin) to your PATH.

Following commands should build the libslirp library and place it in `build` directory.

```sh
git clone https://gitlab.freedesktop.org/slirp/libslirp.git
cd libslirp
meson build
ninja -C build
```

### Building on linux for windows

libslirp depends on msys2's package that provides
[libglib-2.0-0.dll](https://packages.msys2.org/package/mingw-w64-x86_64-glib2) and glib inturn
depends on a few other libraries. On linux libglib-2.0-0.dll is not available as a dll with mingw
setup or in another other apt packages. So you need to build dependent libraries either manually or
get them prebuilt from somewhere. Once you have those, create a file name `cross-compile` in
libslirp directory that looks something like

```
c = 'x86_64-w64-mingw32-gcc'
cpp = 'x86_64-w64-mingw32-g++'
ar = 'x86_64-w64-mingw32-ar'
strip = 'x86_64-w64-mingw32-strip'
pkgconfig = 'x86_64-w64-mingw32-pkg-config'
exe_wrapper = 'wine64'

[built-in options]
pkg_config_path = ['/tmp/x86_64-w64-mingw32/lib/', '/tmp/x86_64-w64-mingw32/', '/tmp/mingw64/lib/pkgconfig']

[host_machine]
system = 'windows'
cpu_family = 'x86_64'
cpu = 'x86_64'
endian = 'little'
```

and then run the following command to build

```sh
meson build --cross-file=cross-compile
ninja -C build
```

Note: Above steps highly depends on how you have setup your cross-compiling environment.
