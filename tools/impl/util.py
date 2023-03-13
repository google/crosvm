#!/usr/bin/env python3
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Provides general utility functions.
"""

import argparse
import contextlib
import datetime
import functools
import os
import re
import subprocess
import sys
import urllib
import urllib.request
import urllib.error
from pathlib import Path
from subprocess import DEVNULL, PIPE, STDOUT  # type: ignore
from typing import (
    Dict,
    List,
    NamedTuple,
    Optional,
    Tuple,
    Union,
)

PathLike = Union[Path, str]

# Regex that matches ANSI escape sequences
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def find_crosvm_root():
    "Walk up from CWD until we find the crosvm root dir."
    path = Path("").resolve()
    while True:
        if (path / "tools/impl/common.py").is_file():
            return path
        if path.parent:
            path = path.parent
        else:
            raise Exception("Cannot find crosvm root dir.")


"Root directory of crosvm derived from CWD."
CROSVM_ROOT = find_crosvm_root()

"Cargo.toml file of crosvm"
CROSVM_TOML = CROSVM_ROOT / "Cargo.toml"

"""
Root directory of crosvm devtools.

May be different from `CROSVM_ROOT/tools`, which is allows you to run the crosvm dev
tools from this directory on another crosvm repo.

Use this if you want to call crosvm dev tools, which will use the scripts relative
to this file.
"""
TOOLS_ROOT = Path(__file__).parent.parent.resolve()

"Cache directory that is preserved between builds in CI."
CACHE_DIR = Path(os.environ.get("CROSVM_CACHE_DIR", os.environ.get("TMPDIR", "/tmp")))

# Ensure that we really found the crosvm root directory
assert 'name = "crosvm"' in CROSVM_TOML.read_text()

# List of times recorded by `record_time` which will be printed if --timing-info is provided.
global_time_records: List[Tuple[str, datetime.timedelta]] = []


def crosvm_target_dir():
    crosvm_target = os.environ.get("CROSVM_TARGET_DIR")
    cargo_target = os.environ.get("CARGO_TARGET_DIR")
    if crosvm_target:
        return Path(crosvm_target)
    elif cargo_target:
        return Path(cargo_target) / "crosvm"
    else:
        return CROSVM_ROOT / "target/crosvm"


@functools.lru_cache(None)
def parse_common_args():
    """
    Parse args common to all scripts

    These args are parsed separately of the run_main/run_commands method so we can access
    verbose/etc before the commands arguments are parsed.
    """
    parser = argparse.ArgumentParser(add_help=False)
    add_common_args(parser)
    return parser.parse_known_args()[0]


def add_common_args(parser: argparse.ArgumentParser):
    "These args are added to all commands."
    parser.add_argument(
        "--color",
        default="auto",
        choices=("always", "never", "auto"),
        help="Force enable or disable colors. Defaults to automatic detection.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Print more details about the commands this script is running.",
    )
    parser.add_argument(
        "--very-verbose",
        "-vv",
        action="store_true",
        default=False,
        help="Print more debug output",
    )
    parser.add_argument(
        "--timing-info",
        action="store_true",
        default=False,
        help="Print info on how long which parts of the command take",
    )


def verbose():
    return very_verbose() or parse_common_args().verbose


def very_verbose():
    return parse_common_args().very_verbose


def color_enabled():
    color_arg = parse_common_args().color
    if color_arg == "never":
        return False
    if color_arg == "always":
        return True
    return sys.stdout.isatty()


def find_scripts(path: Path, shebang: str):
    for file in path.glob("*"):
        if file.is_file() and file.open(errors="ignore").read(512).startswith(f"#!{shebang}"):
            yield file


def confirm(message: str, default: bool = False):
    print(message, "[y/N]" if default == False else "[Y/n]", end=" ", flush=True)
    response = sys.stdin.readline().strip()
    if response in ("y", "Y"):
        return True
    if response in ("n", "N"):
        return False
    return default


def is_cros_repo():
    "Returns true if the crosvm repo is a symlink or worktree to a CrOS repo checkout."
    dot_git = CROSVM_ROOT / ".git"
    if not dot_git.is_symlink() and dot_git.is_dir():
        return False
    return (cros_repo_root() / ".repo").exists()


def cros_repo_root():
    "Root directory of the CrOS repo checkout."
    return (CROSVM_ROOT / "../../..").resolve()


def is_kiwi_repo():
    "Returns true if the crosvm repo contains .kiwi_repo file."
    dot_kiwi_repo = CROSVM_ROOT / ".kiwi_repo"
    return dot_kiwi_repo.exists()


def kiwi_repo_root():
    "Root directory of the kiwi repo checkout."
    return (CROSVM_ROOT / "../..").resolve()


def is_aosp_repo():
    "Returns true if the crosvm repo is an AOSP repo checkout."
    android_bp = CROSVM_ROOT / "Android.bp"
    return android_bp.exists()


def aosp_repo_root():
    "Root directory of AOSP repo checkout."
    return (CROSVM_ROOT / "../..").resolve()


def sudo_is_passwordless():
    # Run with --askpass but no askpass set, succeeds only if passwordless sudo
    # is available.
    (ret, _) = subprocess.getstatusoutput("SUDO_ASKPASS=false sudo --askpass true")
    return ret == 0


SHORTHANDS = {
    "mingw64": "x86_64-pc-windows-gnu",
    "msvc64": "x86_64-pc-windows-msvc",
    "armhf": "armv7-unknown-linux-gnueabihf",
    "aarch64": "aarch64-unknown-linux-gnu",
    "riscv64": "riscv64gc-unknown-linux-gnu",
    "x86_64": "x86_64-unknown-linux-gnu",
}


class Triple(NamedTuple):
    """
    Build triple in cargo format.

    The format is: <arch><sub>-<vendor>-<sys>-<abi>, However, we will treat <arch><sub> as a single
    arch to simplify things.
    """

    arch: str
    vendor: str
    sys: Optional[str]
    abi: Optional[str]

    @classmethod
    def from_shorthand(cls, shorthand: str):
        "These shorthands make it easier to specify triples on the command line."
        if "-" in shorthand:
            triple = shorthand
        elif shorthand in SHORTHANDS:
            triple = SHORTHANDS[shorthand]
        else:
            raise Exception(f"Not a valid build triple shorthand: {shorthand}")
        return cls.from_str(triple)

    @classmethod
    def from_str(cls, triple: str):
        parts = triple.split("-")
        if len(parts) < 2:
            raise Exception(f"Unsupported triple {triple}")
        return cls(
            parts[0],
            parts[1],
            parts[2] if len(parts) > 2 else None,
            parts[3] if len(parts) > 3 else None,
        )

    @classmethod
    def from_linux_arch(cls, arch: str):
        "Rough logic to convert the output of `arch` into a corresponding linux build triple."
        if arch == "armhf":
            return cls.from_str("armv7-unknown-linux-gnueabihf")
        else:
            return cls.from_str(f"{arch}-unknown-linux-gnu")

    @classmethod
    def host_default(cls):
        "Returns the default build triple of the host."
        rustc_info = subprocess.check_output(["rustc", "-vV"], text=True)
        match = re.search(r"host: (\S+)", rustc_info)
        if not match:
            raise Exception(f"Cannot parse rustc info: {rustc_info}")
        return cls.from_str(match.group(1))

    @property
    def feature_flag(self):
        triple_to_shorthand = {v: k for k, v in SHORTHANDS.items()}
        shorthand = triple_to_shorthand.get(str(self))
        if not shorthand:
            raise Exception(f"No feature set for triple {self}")
        return f"all-{shorthand}"

    @property
    def target_dir(self):
        return crosvm_target_dir() / str(self)

    def get_cargo_env(self):
        """Environment variables to make cargo use the test target."""
        env: Dict[str, str] = {}
        cargo_target = str(self)
        env["CARGO_BUILD_TARGET"] = cargo_target
        env["CARGO_TARGET_DIR"] = str(self.target_dir)
        env["CROSVM_TARGET_DIR"] = str(crosvm_target_dir())
        return env

    def __str__(self):
        return f"{self.arch}-{self.vendor}-{self.sys}-{self.abi}"


def download_file(url: str, filename: Path, attempts: int = 3):
    assert attempts > 0
    while True:
        attempts -= 1
        try:
            urllib.request.urlretrieve(url, filename)
            return
        except Exception as e:
            if attempts == 0:
                raise e
            else:
                print("Download failed:", e)


def strip_ansi_escape_sequences(line: str) -> str:
    return ANSI_ESCAPE.sub("", line)


def ensure_packages_exist(*packages: str):
    """
    Exits if one of the listed packages does not exist.
    """
    missing_packages: List[str] = []

    for package in packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        debian_packages = [f"python3-{p}" for p in missing_packages]
        package_list = " ".join(debian_packages)
        print("Missing python dependencies. Please re-run ./tools/install-deps")
        print(f"Or `sudo apt install {package_list}`")
        sys.exit(1)


@contextlib.contextmanager
def record_time(title: str):
    """
    Records wall-time of how long this context lasts.

    The results will be printed at the end of script executation if --timing-info is specified.
    """
    start_time = datetime.datetime.now()
    try:
        yield
    finally:
        global_time_records.append((title, datetime.datetime.now() - start_time))


def print_timing_info():
    print()
    print("Timing info:")
    print()
    for title, delta in global_time_records:
        print(f"  {title:20} {delta.total_seconds():.2f}s")
