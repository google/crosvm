#!/usr/bin/env python3
# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from pathlib import Path
import argparse
import os
import subprocess
import tempfile

USAGE="""
Simulates a Kokoro run executing one of the build-* scripts.

Example:
  $ cd ./ci/kokoro
  $ ./simulate.py build-aarch64.sh
"""

CROSVM_ROOT = Path(__file__).parent.parent.parent.resolve()


def git_clone_source(source: Path, destination: Path):
  destination.mkdir(parents=True, exist_ok=True)
  print(f"Cloning {source} into {destination}:")
  subprocess.check_call(['git', 'clone', '-q', source, destination])


def run_kokoro_build_script(kokoro_root: Path, script_path: Path):
  print(f"Running {script_path}:")
  env=os.environ.copy()
  env['KOKORO_ARTIFACTS_DIR'] = str(kokoro_root / 'src')
  subprocess.check_call([script_path.resolve()], cwd=kokoro_root, env=env)


def simulate_kokoro(kokoro_root: Path, script_path: Path):
  git_clone_source(CROSVM_ROOT, kokoro_root / 'src/git/crosvm')
  run_kokoro_build_script(kokoro_root, script_path)


def main():
  parser = argparse.ArgumentParser(usage=USAGE)
  parser.add_argument("script_name", type=Path)
  args = parser.parse_args()

  script_path: Path= args.script_name
  if not script_path.exists():
    raise ValueError(f"Script '{script_path} not found.")

  with tempfile.TemporaryDirectory() as temp_dir:
    simulate_kokoro(Path(temp_dir), script_path)



if __name__ == '__main__':
  main()
