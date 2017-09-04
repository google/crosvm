#!/usr/bin/env python3

"""Builds crosvm in debug/release mode on all supported target architectures.

A sysroot for each target architectures is required. The defaults are all
generic boards' sysroots, but they can be changed with the ARM_SYSROOT,
AARCH64_SYSROOT, X86_64_SYSROOT environment variables.

To test changes more quickly, set the NOCLEAN environment variable. This
prevents the target directories from being removed before building and testing.
"""

from __future__ import print_function
import multiprocessing.pool
import os
import shutil
import subprocess
import sys

NOCLEAN = os.getenv('NOCLEAN') is not None

ARM_TRIPLE = os.getenv('ARM_TRIPLE', 'armv7a-cros-linux-gnueabi')
AARCH64_TRIPLE = os.getenv('AARCH64_TRIPLE', 'aarch64-cros-linux-gnu')
X86_64_TRIPLE = os.getenv('X86_64_TRIPLE', 'x86_64-cros-linux-gnu')

ARM_SYSROOT = os.getenv('ARM_SYSROOT', '/build/arm-generic')
AARCH64_SYSROOT = os.getenv('AARCH64_SYSROOT', '/build/arm64-generic')
X86_64_SYSROOT = os.getenv('X86_64_SYSROOT', '/build/amd64-generic')

BUILD_TEST_CASES = [
    #(sysroot path, target triple, debug/release, should test?)
    (ARM_SYSROOT, ARM_TRIPLE, "debug", False),
    (ARM_SYSROOT, ARM_TRIPLE, "release", False),
    (AARCH64_SYSROOT, AARCH64_TRIPLE, "debug", False),
    (AARCH64_SYSROOT, AARCH64_TRIPLE, "release", False),
    (X86_64_SYSROOT, X86_64_TRIPLE, "debug", False),
    (X86_64_SYSROOT, X86_64_TRIPLE, "release", False),
    (X86_64_SYSROOT, X86_64_TRIPLE, "debug", True),
    (X86_64_SYSROOT, X86_64_TRIPLE, "release", True),
]

TEST_MODULES_PARALLEL = [
    'crosvm',
    'data_model',
    'kernel_loader',
    'kvm',
    'kvm_sys',
    'net_sys',
    'syscall_defines',
    'virtio_sys',
    'x86_64',
]

TEST_MODULES_SERIAL = [
    'io_jail',
    'sys_util',
  ]

# Bright green
PASS_COLOR = '\033[1;32m'
# Bright red
FAIL_COLOR = '\033[1;31m'
# Default color
END_COLOR = '\033[0m'

def get_target_path(triple, kind, test_it):
  target_path = '/tmp/%s_%s' % (triple, kind)
  if test_it:
    target_path += '_test'
  return target_path


def build_target(triple, is_release, env):
  args = ['cargo', 'build', '--target=%s' % triple]

  if is_release:
    args.append('--release')

  return subprocess.Popen(args, env=env).wait() == 0

def test_target_modules(triple, is_release, env, modules, parallel):
  args = ['cargo', 'test', '--target=%s' % triple]

  if is_release:
    args.append('--release')

  if not parallel:
    env = env.copy()
    env['RUST_TEST_THREADS'] = '1'

  for mod in modules:
    args.append('-p')
    args.append(mod)

  return subprocess.Popen(args, env=env).wait() == 0


def test_target(triple, is_release, env):
  return (
      test_target_modules(
          triple, is_release, env, TEST_MODULES_PARALLEL, True) and
      test_target_modules(
          triple, is_release, env, TEST_MODULES_SERIAL, False)
  )


def check_build(sysroot, triple, kind, test_it):
  if not os.path.isdir(sysroot):
    return 'sysroot missing'

  target_path = get_target_path(triple, kind, test_it)

  if not NOCLEAN:
    shutil.rmtree(target_path, True)

  is_release = kind == 'release'

  env = os.environ.copy()
  env['TARGET_CC'] = '%s-clang'%triple
  env['SYSROOT'] = sysroot
  env['CARGO_TARGET_DIR'] = target_path

  if test_it:
    if not test_target(triple, is_release, env):
      return 'test error'
  else:
    if not build_target(triple, is_release, env):
      return 'build error'

  return 'pass'


def get_stripped_size(triple):
  target_path = get_target_path(triple, 'release', False)
  bin_path = os.path.join(target_path, triple, 'release', 'crosvm')
  proc = subprocess.Popen(['%s-strip' % triple, bin_path])

  if proc.wait() != 0:
    return 'failed'

  return '%dKiB' % (os.path.getsize(bin_path) / 1024)


def main():
  os.chdir(os.path.dirname(sys.argv[0]))
  pool = multiprocessing.pool.Pool()
  results = pool.starmap(check_build, BUILD_TEST_CASES, 1)

  print('---')
  print('build test summary:')
  for test_case, result in zip(BUILD_TEST_CASES, results):
    _, triple, kind, test_it = test_case
    title = '%s_%s' % (triple.split('-')[0], kind)
    if test_it:
      title += "_test"

    result_color = FAIL_COLOR
    if result == 'pass':
      result_color = PASS_COLOR

    display_size = ''
    if result == 'pass' and kind == 'release' and not test_it:
      display_size = get_stripped_size(triple) + ' stripped binary'

    print('%20s: %s%15s%s %s' %
          (title, result_color, result, END_COLOR, display_size))


if __name__ == '__main__':
  main()
