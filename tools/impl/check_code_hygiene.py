#!/usr/bin/env python3
# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
from pathlib import Path
import re
import subprocess
import sys


USAGE = """\
Checks code hygiene of a given directory.

The tool verifies that not code under given directory has conditionally
compiled platform specific code.

To check

    $ ./tools/impl/check_code_hygiene ./common/sys_util_core

On finding platform specific code, the tool prints the file, line number and the
line containing conditional compilation.
"""


def has_platform_dependent_code(rootdir: Path):
    """Recursively searches for target os specific code in the given rootdir.
        Returns false and relative file path if target specific code is found.
        Returns false and rootdir if rootdir does not exists or is not a directory.
        Otherwise returns true and empty string is returned.

    Args:
        rootdir: Base directory path to search for.
    """

    if not rootdir.is_dir():
        return False, "'" + str(rootdir) + "' does not exists or is not a directory"

    cfg_unix = 'cfg.*unix'
    cfg_linux = 'cfg.*linux'
    cfg_windows = 'cfg.*windows'
    cfg_android = 'cfg.*android'
    target_os = 'target_os = '

    target_os_pattern = re.compile('%s|%s|%s|%s|%s' % (
        cfg_android, cfg_linux, cfg_unix, cfg_windows, target_os))

    for file_path in rootdir.rglob('**/*.rs'):
        for line_number, line in enumerate(open(file_path, encoding="utf8")):
            if re.search(target_os_pattern, line):
                return False, str(file_path) + ':' + str(line_number) + ':' + line
    return True, ""


def main():
    parser = argparse.ArgumentParser(usage=USAGE)
    parser.add_argument('path', type=Path,
                        help="Path of the directory to check.")
    args = parser.parse_args()

    is_hygiene, error = has_platform_dependent_code(args.path)
    if not is_hygiene:
        print("Error: Platform dependent code not allowed in sys_util_core crate.")
        print("Offending line: " + error)
        sys.exit(-1)


if __name__ == "__main__":
    main()
