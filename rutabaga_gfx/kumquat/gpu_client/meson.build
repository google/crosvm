# Copyright 2024 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

project('virtgpu_kumquat_ffi', ['rust', 'c'],
         version: '0.1.3')

target_os = host_machine.system()

if target_os == 'windows'
  shared_lib = 'virtgpu_kumquat_ffi.dll'
endif
if target_os == 'darwin'
  shared_lib = 'libvirtgpu_kumquat_ffi.dylib'
endif
if target_os == 'linux'
  shared_lib = 'libvirtgpu_kumquat_ffi.so'
endif

shared_lib_major = '@0@.0'.format(shared_lib)
shared_lib_full_ver = '@0@.@1@'.format(shared_lib, meson.project_version())

build_script = find_program('build.sh')

buildtype = 'debug'
cargo_release = ''
if get_option('buildtype') == 'release'
  buildtype = 'release'
  cargo_release = '--release'
endif

virtgpu_kumquat_ffi_ct = custom_target(
  'virtgpu_kumquat_ffi_build',
  output: [shared_lib, shared_lib_major, shared_lib_full_ver],
  input: ['src/lib.rs', 'Cargo.toml', 'build.sh'],
  command: [build_script, meson.current_build_dir(), shared_lib,
            meson.project_version(), buildtype, cargo_release],
  install: true,
  install_dir: get_option('libdir'),
)

pkg = import('pkgconfig')
pkg.generate(
  libraries: '-L${libdir} -lvirtgpu_kumquat_ffi',
  name: 'virtgpu_kumquat_ffi',
  version: meson.project_version(),
  description: 'C FFI bindings to Rutabaga VGI',
)

virtgpu_kumquat_ffi_h = files('src/include/virtgpu_kumquat_ffi.h')
install_headers(virtgpu_kumquat_ffi_h,
                subdir: 'virtgpu_kumquat')
