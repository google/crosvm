# Copyright 2021 The ChromiumOS Authors
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
        for search, replace in replacements:
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
    for toml in sorted(Path().glob("common/*/Cargo.toml")):
        members.append(f'    "{toml.parent}",')
    members.append('    "third_party/vmm_vhost",')

    members.append("]")
    replace_in_file(Path("Cargo.toml"), re.compile(r"members = \[[^\]]+\]"), "\n".join(members))


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


IMPORT = """pub mod linux;

#[cfg(windows)]
pub mod windows;
"""

BUILD_RS = """\
// Copyright 2022 The ChromiumOS Authors
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
    update_workspace_members()


main()
