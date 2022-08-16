#!/usr/bin/env python3
# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from time import time
from typing import Callable, List, NamedTuple

from impl.common import all_tracked_files, cmd, verbose

git = cmd("git")


@dataclass
class CheckContext(object):
    "Information passed to each check when it's called."

    # Whether or not --fix was set and checks should attempt to fix problems they encounter.
    fix: bool

    # Use rust nightly version for rust checks
    nightly: bool

    # All files that this check should cover (e.g. all python files on a python check).
    all_files: List[Path]

    # Those files of all_files that were modified locally.
    modified_files: List[Path]

    # Files that do not exist upstream and have been added locally.
    new_files: List[Path]


class Check(NamedTuple):
    "Metadata for each check, definining on which files it should run."

    # Function to call for this check
    check_function: Callable[[CheckContext], None]

    # List of globs that this check should be triggered on
    files: List[str] = []

    python_tools: bool = False

    # List of globs to exclude from this check
    exclude: List[str] = []

    @property
    def name(self):
        name = self.check_function.__name__
        if name.startswith("check_"):
            return name[len("check_") :]
        return name


def list_file_diff():
    """
    Lists files there were modified compared to the upstream branch.

    Falls back to all files tracked by git if there is no upstream branch.
    """
    upstream = git("rev-parse @{u}").stdout(check=False)
    if upstream:
        for line in git("diff --name-status", upstream).lines():
            parts = line.split("\t", 1)
            yield (parts[0].strip(), Path(parts[1].strip()))
    else:
        print("WARNING: Not tracking a branch. Checking all files.")
        for file in all_tracked_files():
            yield ("M", file)


def should_run_check_on_file(check: Check, file: Path):
    "Returns true if `file` should be run on `check`."

    # Skip third_party
    if str(file).startswith("third_party"):
        return False

    # Skip excluded files
    for glob in check.exclude:
        if fnmatch(str(file), glob):
            return False

    # Match python tools (no file-extension, but with a python shebang line)
    if check.python_tools:
        if fnmatch(str(file), "tools/*") and file.suffix == "" and file.is_file():
            if file.open(errors="ignore").read(32).startswith("#!/usr/bin/env python3"):
                return True

    # If no constraint is specified, match all files.
    if not check.files and not check.python_tools:
        return True

    # Otherwise, match only those specified by `files`.
    for glob in check.files:
        if fnmatch(str(file), glob):
            return True

    return False


def run_check(check: Check, context: CheckContext):
    "Runs `check` using the information in `context`. Prints status updates."
    start_time = time()
    if verbose():
        print(f"Checking {check.name}...")
    try:
        check.check_function(context)
        success = True
    except Exception as e:
        print(e)
        success = False

    duration = time() - start_time
    print(f"Check {check.name}", "OK" if success else "FAILED", f" ({duration:.2f} s)")
    return success


def run_checks(
    checks_list: List[Check],
    fix: bool,
    run_on_all_files: bool,
    nightly: bool,
):
    """
    Runs all checks in checks_list.

    Arguments:
        fix: Tell checks to fix issues if they can (e.g. run formatter).
        run_on_all_files: Do not use git delta, but run on all files.
        nightly: Use nightly version of rust tooling.
    """
    all_files = [*all_tracked_files()]
    file_diff = [*list_file_diff()]
    new_files = [f for (s, f) in file_diff if s == "A"]
    if run_on_all_files:
        modified_files = all_files
    else:
        modified_files = [f for (s, f) in file_diff if s in ("M", "A")]

    success = True
    for check in checks_list:
        context = CheckContext(
            fix=fix,
            nightly=nightly,
            all_files=[f for f in all_files if should_run_check_on_file(check, f)],
            modified_files=[f for f in modified_files if should_run_check_on_file(check, f)],
            new_files=[f for f in new_files if should_run_check_on_file(check, f)],
        )
        if context.modified_files:
            if not run_check(check, context):
                success = False
    return success
