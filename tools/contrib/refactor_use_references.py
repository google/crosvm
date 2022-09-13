# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Tools for refactoring references in rust code.
#
# Contains the last run refactoring for reference. Don't run this script, it'll
# fail, but use it as a foundation for other refactorings.

from contextlib import contextmanager
import os
import re
import subprocess
from pathlib import Path
from typing import Callable, NamedTuple, Union

SearchPattern = Union[str, re.Pattern[str]]


class Token(NamedTuple):
    token: str
    start: int
    end: int


def tokenize(source: str):
    "Split source by whitespace with start/end indices annotated."
    start = 0
    for i in range(len(source)):
        if source[i] in (" ", "\n", "\t") and i - start > 0:
            token = source[start:i].strip()
            if token:
                yield Token(token, start, i)
            start = i


def parse_module_chunks(source: str):
    """Terrible parser to split code by `mod foo { ... }` statements. Please don't judge me.

    Returns the original source split with module names anntated as ('module name', 'source')
    """
    tokens = list(tokenize(source))
    prev = 0
    for i in range(len(tokens) - 2):
        if tokens[i].token == "mod" and tokens[i + 2].token == "{":
            brackets = 1
            for j in range(i + 3, len(tokens)):
                if "{" not in tokens[j].token or "}" not in tokens[j].token:
                    if "{" in tokens[j].token:
                        brackets += 1
                    elif "}" in tokens[j].token:
                        brackets -= 1
                if brackets == 0:
                    start = tokens[i + 2].end
                    end = tokens[j].start
                    yield ("", source[prev:start])
                    yield (tokens[i + 1].token, source[start:end])
                    prev = end
                    break
    if prev != len(source):
        yield ("", source[prev:])


def replace_use_references(file_path: Path, callback: Callable[[list[str], str], str]):
    """Calls 'callback' for each foo::bar reference in `file_path`.

    The callback is called with the reference as an argument and is expected to return the rewritten
    reference.
    Additionally, the absolute path in the module tree is provided, taking into account the file
    path as well as modules defined in the source itself.

    eg.
    src/foo.rs:
    ```
    mod tests {
        use crate::baz;
    }
    ```
    will call `callback(['foo', 'tests'], 'crate::baz')`
    """
    module_parts = list(file_path.parts[:-1])
    if file_path.stem not in ("mod", "lib"):
        module_parts.append(file_path.stem)

    with open(file_path, "r") as file:
        contents = file.read()
    chunks: list[str] = []
    for module, source in parse_module_chunks(contents):
        if module:
            full_module_parts = module_parts + [module]
        else:
            full_module_parts = module_parts
        chunks.append(
            re.sub(
                r"([\w\*\_\$]+\:\:)+[\w\*\_]+",
                lambda m: callback(full_module_parts, m.group(0)),
                source,
            )
        )
    with open(file_path, "w") as file:
        file.write("".join(chunks))


@contextmanager
def chdir(path: Union[Path, str]):
    origin = Path().absolute()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(origin)


def use_super_instead_of_crate(root: Path):
    """Expects to be run directly on the src directory and assumes
    that directory to be the module crate:: refers to."""

    def replace(module: list[str], use: str):
        # Patch up weird module structure...
        if len(module) > 1 and module[0] == "win":
            # Only the listed modules are actually in win::.
            # The rest is in the top level.
            if module[1] not in (
                "file_traits",
                "syslog",
                "platform_timer_utils",
                "file_util",
                "shm",
                "wait",
                "mmap",
                "stream_channel",
                "timer",
            ):
                del module[0]
        if len(module) > 0 and module[0] in ("punch_hole", "write_zeros"):
            module = ["write_zeroes", module[0]]

        if use.startswith("crate::"):
            new_use = use.replace("crate::", "super::" * len(module))
            print("::".join(module), use, "->", new_use)
            return new_use
        return use

    with chdir(root):
        for file in Path().glob("**/*.rs"):
            replace_use_references(file, replace)


def main():
    path = Path("common") / "win_sys_util/src"
    subprocess.check_call(["git", "checkout", "-f", str(path)])

    # Use rustfmt to re-format use statements to be one per line.
    subprocess.check_call(
        ["rustfmt", "+nightly", "--config=imports_granularity=item", f"{path}/lib.rs"]
    )
    use_super_instead_of_crate(path)
    subprocess.check_call(
        ["rustfmt", "+nightly", "--config=imports_granularity=crate", f"{path}/lib.rs"]
    )


main()
