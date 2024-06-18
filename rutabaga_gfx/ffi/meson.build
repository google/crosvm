# Copyright 2024 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

project('rutabaga_gfx_ffi', ['rust', 'c'],
         version: '0.1.3')

target_os = host_machine.system()

# By default cargo would generate rutabaga_gfx_ffi.dll (without the lib
# prefix) for a Windows cdylib
if target_os == 'windows'
  shared_lib = 'rutabaga_gfx_ffi.dll'
endif
if target_os == 'darwin'
  shared_lib = 'librutabaga_gfx_ffi.dylib'
endif
if target_os == 'linux'
  shared_lib = 'librutabaga_gfx_ffi.so'
endif

shared_lib_major = '@0@.0'.format(shared_lib)
shared_lib_full_ver = '@0@.@1@'.format(shared_lib, meson.project_version())

build_script = find_program('build.sh')
with_gfxstream = get_option('gfxstream')
features = ''
if with_gfxstream
  features += 'gfxstream'
endif

buildtype = 'debug'
cargo_release = ''
if get_option('buildtype') == 'release'
  buildtype = 'release'
  cargo_release = '--release'
endif

rutabaga_gfx_ffi_ct = custom_target(
  'rutabaga_gfx_ffi_build',
  output: [shared_lib, shared_lib_major, shared_lib_full_ver],
  input: ['src/lib.rs', 'Cargo.toml', 'build.rs', 'build.sh'],
  command: [build_script, features, meson.current_build_dir(),
            shared_lib, meson.project_version(), buildtype, cargo_release],
  install: true,
  install_dir: get_option('libdir'),
)

pkg = import('pkgconfig')
pkg.generate(
  libraries: '-L${libdir} -lrutabaga_gfx_ffi',
  name: 'rutabaga_gfx_ffi',
  version: meson.project_version(),
  description: 'C FFI bindings to Rutabaga VGI',
)

rutabaga_gfx_ffi_h = files('src/include/rutabaga_gfx_ffi.h')
install_headers(rutabaga_gfx_ffi_h,
                subdir: 'rutabaga_gfx')
