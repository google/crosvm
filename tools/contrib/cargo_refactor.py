# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Refactoring tools for moving around crates and updating dependencies
# in toml files.
#
# Contains the last run refactoring for reference. Don't run this script, it'll
# fail, but use it as a foundation for other refactorings.

from pathlib import Path
import os
import re
import shutil
import subprocess
from typing import List, Tuple, Union

SearchPattern = Union[str, re.Pattern[str]]


def replace_in_file(file_path: Path, search: SearchPattern, replace: str):
    if not file_path.exists():
        print(f"WARNING: Does not exist {file_path}")
        return
    if isinstance(search, str):
        search = re.escape(search)
    with open(file_path, "r") as file:
        contents = file.read()
    (contents, count) = re.subn(search, replace, contents)
    if count > 0:
        print(f"replacing '{search}' with '{replace}' in {file_path}")
        with open(file_path, "w") as file:
            file.write(contents)


def replace_in_files(glob: str, replacements: List[Tuple[SearchPattern, str]]):
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
    with open(toml, "r") as file:
        contents = file.read()
    for old_dep in re.findall('{ path = "([^"]+)"', contents):
        new_dep = os.path.relpath((from_path / old_dep).resolve(), to_path)
        contents = contents.replace(f'path = "{old_dep}"', f'path = "{new_dep}"')
    with open(toml, "w") as file:
        file.write(contents)


def move_crate(from_path: Path, to_path: Path):
    "Move crate and update dependencies"
    print(f"{from_path} -> {to_path}")
    if to_path.exists():
        shutil.rmtree(to_path)
    subprocess.check_call(["git", "mv", str(from_path), str(to_path)])
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


def main():
    os.chdir(Path(__file__).parent.parent.parent)

    move_crate(Path("common/base"), Path("base"))
    update_workspace_members()


main()
