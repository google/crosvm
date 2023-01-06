# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
from pathlib import Path
from typing import List
import re
import subprocess
import sys


USAGE = """\
Checks code hygiene of a given directory.

The tool verifies that
- code under given directory has no conditionally compiled platform specific code.
- crates in current directory, excluding crates in ./common/, do not depend on
  on sys_util, sys_util_core or on win_sys_util.

To check

    $ ./tools/impl/check_code_hygiene ./common/sys_util_core

On finding platform specific code, the tool prints the file, line number and the
line containing conditional compilation.
On finding dependency on sys_util, sys_util_core or on win_sys_util, the tool prints
the names of crates.
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

    cfg_unix = "cfg.*unix"
    cfg_linux = "cfg.*linux"
    cfg_windows = "cfg.*windows"
    cfg_android = "cfg.*android"
    target_os = "target_os = "

    target_os_pattern = re.compile(
        "%s|%s|%s|%s|%s" % (cfg_android, cfg_linux, cfg_unix, cfg_windows, target_os)
    )

    for file_path in rootdir.rglob("**/*.rs"):
        for line_number, line in enumerate(open(file_path, encoding="utf8")):
            if re.search(target_os_pattern, line):
                return False, str(file_path) + ":" + str(line_number) + ":" + line
    return True, ""


def is_sys_util_independent():
    """Recursively searches for that depend on sys_util, sys_util_core or win_util.
    Does not search crates in common/ as they are allowed to be platform specific.
    Returns false and a list of crates that depend on those crates. Otherwise
    returns true and am empty list.

    """

    crates: list[str] = []
    sys_util_crates = re.compile("sys_util|sys_util_core|win_sys_util")
    files: list[Path] = list(Path(".").glob("**/Cargo.toml"))
    files.extend(Path("src").glob("**/*.rs"))

    # Exclude common as it is allowed to depend on sys_util and exclude Cargo.toml
    # from root directory as it contains workspace related entries for sys_util.
    files[:] = [
        file for file in files if not file.is_relative_to("common") and str(file) != "Cargo.toml"
    ]

    for file_path in files:
        with open(file_path) as open_file:
            for line in open_file:
                if sys_util_crates.match(line):
                    crates.append(str(file_path))

    return not crates, crates


def has_line_endings(file_pattern: str, line_ending_pattern: str):
    """Searches for files with crlf(dos) line endings in a git repo. Returns
    a list of files having crlf line endings.

    """
    process = subprocess.Popen(
        f"git ls-files --eol {file_pattern}",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        shell=True,
    )

    stdout, _ = process.communicate()
    dos_files: list[str] = []

    if process.returncode != 0:
        return dos_files

    crlf_re = re.compile(line_ending_pattern)
    assert process.stdout
    for line in iter(stdout.splitlines()):
        # A typical output of git ls-files --eol looks like below
        # i/lf    w/lf    attr/                   vhost/Cargo.toml
        fields = line.split()
        if fields and crlf_re.search(fields[0] + fields[1]):
            dos_files.append(fields[3] + "\n")

    return dos_files


def has_crlf_line_endings(files: List[Path]):
    f = " ".join([str(file) for file in files])
    return has_line_endings(f, "crlf|mixed")


def has_lf_line_endings(files: List[Path]):
    f = " ".join([str(file) for file in files])
    return has_line_endings(f, "\blf|mixed")


def main():
    parser = argparse.ArgumentParser(usage=USAGE)
    parser.add_argument("path", type=Path, help="Path of the directory to check.")
    args = parser.parse_args()

    hygiene, error = has_platform_dependent_code(args.path)
    if not hygiene:
        print("Error: Platform dependent code not allowed in sys_util_core crate.")
        print("Offending line: " + error)
        sys.exit(-1)

    hygiene, crates = is_sys_util_independent()
    if not hygiene:
        print("Error: Following files depend on sys_util, sys_util_core or on win_sys_util")
        print(crates)
        sys.exit(-1)

    crlf_endings = has_crlf_line_endings()
    if crlf_endings:
        print("Error: Following files have crlf(dos) line encodings")
        print(*crlf_endings)
        sys.exit(-1)


if __name__ == "__main__":
    main()
