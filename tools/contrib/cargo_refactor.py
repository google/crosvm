# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Refactoring tools for moving around crates and updating dependencies
# in toml files.
#
# Contains the last run refactoring for reference. Don't run this script, it'll
# fail, but use it as a foundation for other refactorings.

from contextlib import contextmanager
from pathlib import Path
import os
import re
import shutil
import subprocess
from typing import Callable, List, Tuple, Union


SearchPattern = Union[str, re.Pattern[str]]
Replacement = Union[str, Callable[[re.Match[str]], str]]


def append_to_file(file_path: Path, appendix: str):
    contents = file_path.read_text()
    file_path.write_text(contents.rstrip() + "\n" + appendix + "\n")


def replace_in_file(file_path: Path, search: SearchPattern, replace: Replacement):
    if not file_path.exists():
        print(f"WARNING: Does not exist {file_path}")
        return
    if isinstance(search, str):
        search = re.escape(search)
    contents = file_path.read_text()
    (contents, count) = re.subn(search, replace, contents)
    if count > 0:
        print(f"replacing '{search}' with '{replace}' in {file_path}")
        file_path.write_text(contents)


def replace_in_files(glob: str, replacements: List[Tuple[SearchPattern, Replacement]]):
    for file in Path().glob(glob):
        for (search, replace) in replacements:
            replace_in_file(file, search, replace)


def replace_path_in_all_cargo_toml(old_path: Path, new_path: Path):
    "Replace path in all cargo.toml files, accounting for relative paths."
    for toml in Path().glob("**/Cargo.toml"):
        crate_dir = toml.parent
        old_rel = os.path.relpath(old_path, crate_dir)
        new_rel = os.path.relpath(new_path, crate_dir)
        replace_in_file(toml, re.escape(f'path = "{old_rel}"'), f'path = "{new_rel}"')


def update_path_deps(toml: Path, from_path: Path, to_path: Path):
    "Update path deps in toml file after moving it"
    contents = toml.read_text()
    for old_dep in re.findall('{ path = "([^"]+)"', contents):
        new_dep = os.path.relpath((from_path / old_dep).resolve(), to_path)
        contents = contents.replace(f'path = "{old_dep}"', f'path = "{new_dep}"')
    toml.write_text(contents)


def move_crate(from_path: Path, to_path: Path):
    "Move crate and update dependencies"
    print(f"{from_path} -> {to_path}")
    if to_path.exists():
        shutil.rmtree(to_path)
    shutil.copytree(str(from_path), str(to_path))
    update_path_deps(to_path / "Cargo.toml", from_path, to_path)
    replace_in_files("**/*/Cargo.toml", [(str(from_path), str(to_path))])
    replace_in_file(Path("Cargo.toml"), str(from_path), str(to_path))


def update_workspace_members():
    members: list[str] = []
    members.append("members = [")
    for toml in sorted(Path().glob("*/Cargo.toml")):
        members.append(f'    "{toml.parent}",')
    members.append('    "third_party/vmm_vhost",')

    members.append("]")
    replace_in_file(Path("Cargo.toml"), re.compile(r"members = \[[^\]]+\]"), "\n".join(members))

    exclude: list[str] = []
    exclude.append("exclude = [")
    for toml in sorted(Path().glob("common/*/Cargo.toml")):
        exclude.append(f'    "{toml.parent}",')
    exclude.append("]")
    replace_in_file(Path("Cargo.toml"), re.compile(r"exclude = \[[^\]]+\]"), "\n".join(exclude))


@contextmanager
def chdir(path: Union[Path, str]):
    origin = Path().absolute()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(origin)


def copy_crate_src_to_module(source: str, destination: str):
    shutil.rmtree(destination, ignore_errors=True)
    shutil.copytree(source, destination)
    with chdir(destination):
        Path("lib.rs").rename("mod.rs")


IMPORT = """pub mod unix;

#[cfg(windows)]
pub mod windows;
"""

BUILD_RS = """\
// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

fn main() {
    cc::Build::new()
        .file("src/windows/stdio_fileno.c")
        .compile("stdio_fileno");
}
"""


def main():
    os.chdir(Path(__file__).parent.parent.parent)

    subprocess.check_call(["git", "checkout", "-f", "--", "base"])

    # Move crates to base
    move_crate(Path("common/win_util"), Path("win_util"))
    copy_crate_src_to_module("common/win_sys_util/src", "base/src/windows")
    Path("base/build.rs").write_text(BUILD_RS)

    # Load the added module
    replace_in_file(Path("base/src/lib.rs"), "pub mod unix;", IMPORT)

    # Flatten all imports for easier replacements
    subprocess.check_call(
        ["rustfmt", "+nightly", "--config=imports_granularity=item", "base/src/lib.rs"]
    )

    # Update references to the above crates in base:
    replace_in_files(
        "base/src/**/*.rs",
        [
            ("sys_util_core::", "crate::common::"),
            ("win_sys_util::", "crate::platform::"),
            ("crate::unix::", "crate::platform::"),
            ("use poll_token_derive::", "use base_poll_token_derive::"),
        ],
    )

    # Fixup macros since they like to have special treatement.
    macros = [
        "debug",
        "error",
        "handle_eintr_errno",
        "info",
        "ioctl_io_nr",
        "ioctl_ior_nr",
        "ioctl_iow_nr",
        "ioctl_iowr_nr",
        "syscall",
        "warn",
        "volatile_at_impl",
        "volatile_impl",
        "generate_scoped_event",
        "syslog_lock",
        "CHRONO_TIMESTAMP_FIXED_FMT",
    ]
    for macro in macros:
        # Update use statments. #[macro_export] exports them on the crate scoped
        replace_in_files(
            "base/src/windows/**/*.rs",
            [
                (f"crate::common::{macro}", f"crate::{macro}"),
                (f"super::super::{macro}", f"crate::{macro}"),
                (f"super::{macro}", f"crate::{macro}"),
            ],
        )

    # Replace $crate:: with $crate::windows (unless it's a macro invocation..)
    def replace_references_in_macros(match: re.Match[str]):
        name = match.group(0)
        if not name.endswith("!"):
            return name.replace("$crate", f"$crate::platform")
        return name

    replace_in_files(
        f"base/src/windows/**/*.rs",
        [(re.compile(r"([\w\*\_\$]+\:\:)+([\w\*\_\!]+)"), replace_references_in_macros)],
    )

    # Unflatten imports again
    subprocess.check_call(
        ["rustfmt", "+nightly", "--config=imports_granularity=crate", "base/src/lib.rs"]
    )

    subprocess.check_call(["git", "rm", "-r", "common/win_sys_util", "common/win_util"])


main()
