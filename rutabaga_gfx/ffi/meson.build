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

cargo = find_program('cargo')
cmd = [cargo, 'build']
with_gfxstream = get_option('gfxstream')
if with_gfxstream
  cmd += '--features=gfxstream'
endif

rutabaga_gfx_ffi_ct = custom_target(
  'rutabaga_gfx_ffi_build',
  output: shared_lib,
  input: ['src/lib.rs', 'Cargo.toml', 'build.rs'],
  command: cmd,
)

rutabaga_gfx_ffi_h = files('src/include/rutabaga_gfx_ffi.h')

rutabaga_gfx_ffi = library(
  'rutabaga_gfx_ffi',
  sources: [rutabaga_gfx_ffi_h, rutabaga_gfx_ffi_ct],
  version: '0.1.3',
  install: true,
)

install_headers(rutabaga_gfx_ffi_h,
                subdir: 'rutabaga_gfx')
