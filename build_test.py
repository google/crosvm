#!/usr/bin/env python3
# Copyright 2017 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Builds crosvm in debug/release mode on all supported target architectures.

A sysroot for each target architectures is required. The defaults are all
generic boards' sysroots, but they can be changed with the command line
arguments.

To test changes more quickly, set the --noclean option. This prevents the
target directories from being removed before building and testing.
"""

from __future__ import print_function
import argparse
import multiprocessing.pool
import os
import shutil
import subprocess
import sys

ARM_TRIPLE = os.getenv('ARM_TRIPLE', 'armv7a-cros-linux-gnueabihf')
AARCH64_TRIPLE = os.getenv('AARCH64_TRIPLE', 'aarch64-cros-linux-gnu')
X86_64_TRIPLE = os.getenv('X86_64_TRIPLE', 'x86_64-cros-linux-gnu')

TEST_MODULES_PARALLEL = [
    'crosvm',
    'data_model',
    'kernel_loader',
    'kvm',
    'kvm_sys',
    'net_sys',
    'net_util',
    'syscall_defines',
    'vhost',
    'virtio_sys',
    'x86_64',
]

TEST_MODULES_SERIAL = [
    'io_jail',
    'sys_util',
]

# Bright green.
PASS_COLOR = '\033[1;32m'
# Bright red.
FAIL_COLOR = '\033[1;31m'
# Default color.
END_COLOR = '\033[0m'


def get_target_path(triple, kind, test_it):
  """Constructs a target path based on the configuration parameters.

  Args:
    triple: Target triple. Example: 'x86_64-unknown-linux-gnu'.
    kind: 'debug' or 'release'.
    test_it: If this target is tested.
  """
  target_path = '/tmp/%s_%s' % (triple, kind)
  if test_it:
    target_path += '_test'
  return target_path


def build_target(triple, is_release, env):
  """Does a cargo build for the triple in release or debug mode.

  Args:
    triple: Target triple. Example: 'x86_64-unknown-linux-gnu'.
    is_release: True to build a release version.
    env: Enviroment variables to run cargo with.
  """
  args = ['cargo', 'build', '--target=%s' % triple]

  if is_release:
    args.append('--release')

  return subprocess.Popen(args, env=env).wait() == 0


def test_target_modules(triple, is_release, env, modules, parallel):
  """Does a cargo test on given modules for the triple and configuration.

  Args:
    triple: Target triple. Example: 'x86_64-unknown-linux-gnu'.
    is_release: True to build a release version.
    env: Enviroment variables to run cargo with.
    modules: List of module strings to test.
    parallel: True to run the tests in parallel threads.
  """
  args = ['cargo', 'test', '--target=%s' % triple]

  if is_release:
    args.append('--release')

  for mod in modules:
    args.append('-p')
    args.append(mod)

  if not parallel:
    args.append('--')
    args.append('--test-threads=1')

  return subprocess.Popen(args, env=env).wait() == 0


def test_target(triple, is_release, env):
  """Does a cargo test for the given triple and configuration.

  Args:
    triple: Target triple. Example: 'x86_64-unknown-linux-gnu'.
    is_release: True to build a release version.
    env: Enviroment variables to run cargo with.
  """

  parallel_result = test_target_modules(
      triple, is_release, env, TEST_MODULES_PARALLEL, True)

  serial_result = test_target_modules(
      triple, is_release, env, TEST_MODULES_SERIAL, False)

  return parallel_result and serial_result


def check_build(sysroot, triple, kind, test_it, clean):
  """Runs relavent builds/tests for the given triple and configuration

  Args:
    sysroot: path to the target's sysroot directory.
    triple: Target triple. Example: 'x86_64-unknown-linux-gnu'.
    kind: 'debug' or 'release'.
    test_it: True to test this triple and kind.
    clean: True to skip cleaning the target path.
  """
  if not os.path.isdir(sysroot):
    return 'sysroot missing'

  target_path = get_target_path(triple, kind, test_it)

  if clean:
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
  """Returns the formatted size of the given triple's release binary.

  Args:
    triple: Target triple. Example: 'x86_64-unknown-linux-gnu'.
  """
  target_path = get_target_path(triple, 'release', False)
  bin_path = os.path.join(target_path, triple, 'release', 'crosvm')
  proc = subprocess.Popen(['%s-strip' % triple, bin_path])

  if proc.wait() != 0:
    return 'failed'

  return '%dKiB' % (os.path.getsize(bin_path) / 1024)


def get_parser():
  """Gets the argument parser"""
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--arm-sysroot',
                      default='/build/arm-generic',
                      help='ARM sysroot directory (default=%(default)s)')
  parser.add_argument('--aarch64-sysroot',
                      default='/build/arm64-generic',
                      help='AARCH64 sysroot directory (default=%(default)s)')
  parser.add_argument('--x86_64-sysroot',
                      default='/build/amd64-generic',
                      help='x86_64 sysroot directory (default=%(default)s)')
  parser.add_argument('--noclean', dest='clean', default=True,
                      action='store_false',
                      help='Keep the tempororary build directories.')
  return parser


def main(argv):
  opts = get_parser().parse_args(argv)
  build_test_cases = (
      #(sysroot path, target triple, debug/release, should test?)
      (opts.arm_sysroot, ARM_TRIPLE, "debug", False, opts.clean),
      (opts.arm_sysroot, ARM_TRIPLE, "release", False, opts.clean),
      (opts.aarch64_sysroot, AARCH64_TRIPLE, "debug", False, opts.clean),
      (opts.aarch64_sysroot, AARCH64_TRIPLE, "release", False, opts.clean),
      (opts.x86_64_sysroot, X86_64_TRIPLE, "debug", False, opts.clean),
      (opts.x86_64_sysroot, X86_64_TRIPLE, "release", False, opts.clean),
      (opts.x86_64_sysroot, X86_64_TRIPLE, "debug", True, opts.clean),
      (opts.x86_64_sysroot, X86_64_TRIPLE, "release", True, opts.clean),
  )

  os.chdir(os.path.dirname(sys.argv[0]))
  pool = multiprocessing.pool.Pool(len(build_test_cases))
  results = pool.starmap(check_build, build_test_cases, 1)

  print('---')
  print('build test summary:')
  for test_case, result in zip(build_test_cases, results):
    _, triple, kind, test_it, _ = test_case
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
  sys.exit(main(sys.argv[1:]))
