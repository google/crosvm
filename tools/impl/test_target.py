#!/usr/bin/env python3
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file
import argparse
import platform
import subprocess
from pathlib import Path
from typing import Any, Literal, Optional, cast
import typing
import sys
import testvm
import os

USAGE = """Choose to run tests locally, in a vm or on a remote machine.

To set the default test target to run on one of the build-in VMs:

    ./tools/set_test_target vm:aarch64 && source .envrc

Then as usual run cargo or run_tests:

    ./tools/run_tests
    cargo test

The command will prepare the VM for testing (e.g. upload required shared
libraries for running rust tests) and set up run_tests as well as cargo
to build for the test target and execute tests on it.

Arbitrary SSH remotes can be used for running tests as well. e.g.

    ./tools/set_test_target ssh:remotehost

The `remotehost` needs to be properly configured for passwordless
authentication.

Tip: Use http://direnv.net to automatically load the envrc file instead of
having to source it after each call.
"""

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent.resolve()
TESTVM_DIR = SCRIPT_DIR.parent.joinpath("testvm")
TARGET_DIR = testvm.cargo_target_dir().joinpath("crosvm_tools")
ENVRC_PATH = SCRIPT_DIR.parent.parent.joinpath(".envrc")

Arch = Literal["x86_64", "aarch64", "armhf", "win64"]

# Enviroment variables needed for building with cargo
BUILD_ENV = {
    "PKG_CONFIG_aarch64_unknown_linux_gnu": "aarch64-linux-gnu-pkg-config",
    "PKG_CONFIG_armv7_unknown_linux_gnueabihf": "arm-linux-gnueabihf-pkg-config",
    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": "aarch64-linux-gnu-gcc",
}


class Ssh:
    """Wrapper around subprocess to execute commands remotely via SSH."""

    hostname: str
    opts: list[str]

    def __init__(self, hostname: str, opts: list[str] = []):
        self.hostname = hostname
        self.opts = opts

    def run(self, cmd: str, **kwargs: Any):
        """Equivalent of subprocess.run"""
        return subprocess.run(
            [
                "ssh",
                self.hostname,
                *self.opts,
                # Do not create a tty. This will mess with terminal output
                # when running multiple subprocesses.
                "-T",
                # Tell sh to kill children on hangup.
                f"shopt -s huponexit; {cmd}",
            ],
            **kwargs,
        )

    def check_output(self, cmd: str):
        """Equivalent of subprocess.check_output"""
        return subprocess.run(
            ["ssh", self.hostname, *self.opts, "-T", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True,
        ).stdout

    def upload_files(self, files: list[Path], remote_dir: str = "", quiet: bool = False):
        """Wrapper around SCP."""
        flags: list[str] = []
        if quiet:
            flags.append("-q")
        scp_cmd = [
            "scp",
            *flags,
            *self.opts,
            *files,
            f"{self.hostname}:{remote_dir}",
        ]
        subprocess.run(scp_cmd, check=True)


class TestTarget(object):
    """A test target can be the local host, a VM or a remote devica via SSH."""

    target_str: str
    is_host: bool = False
    vm: Optional[testvm.Arch] = None
    ssh: Optional[Ssh] = None
    __arch: Optional[Arch] = None

    @classmethod
    def default(cls):
        return cls(os.environ.get("CROSVM_TEST_TARGET", "host"))

    def __init__(self, target_str: str):
        """target_str can be "vm:arch", "ssh:hostname" or just "host" """
        self.target_str = target_str
        parts = target_str.split(":")
        if len(parts) == 2 and parts[0] == "vm":
            arch: testvm.Arch = parts[1]  # type: ignore
            self.vm = arch
            self.ssh = Ssh("localhost", testvm.ssh_cmd_args(arch))
        elif len(parts) == 2 and parts[0] == "ssh":
            self.ssh = Ssh(parts[1])
        elif len(parts) == 1 and parts[0] == "host":
            self.is_host = True
        else:
            raise Exception(f"Invalid target {target_str}")

    @property
    def arch(self) -> Arch:
        if not self.__arch:
            if self.vm:
                self.__arch = self.vm
            elif self.ssh:
                self.__arch = cast(Arch, self.ssh.check_output("arch").strip())
            else:
                self.__arch = cast(Arch, platform.machine())
        return self.__arch

    def __str__(self):
        return self.target_str


def find_rust_lib_dir():
    cargo_path = Path(subprocess.check_output(["rustup", "which", "cargo"], text=True))
    if os.name == "posix":
        return cargo_path.parent.parent.joinpath("lib")
    elif os.name == "nt":
        return cargo_path.parent
    else:
        raise Exception(f"Unsupported build target: {os.name}")


def find_rust_libs():
    lib_dir = find_rust_lib_dir()
    yield from lib_dir.glob("libstd-*")
    yield from lib_dir.glob("libtest-*")


def prepare_remote(ssh: Ssh, extra_files: list[Path] = []):
    print("Preparing remote")
    ssh.upload_files(list(find_rust_libs()) + extra_files)
    pass


def prepare_target(target: TestTarget, extra_files: list[Path] = []):
    if target.vm:
        testvm.build_if_needed(target.vm)
        testvm.wait(target.vm)
    if target.ssh:
        prepare_remote(target.ssh, extra_files)


def get_cargo_build_target(arch: Arch):
    if os.name == "posix":
        if arch == "armhf":
            return "armv7-unknown-linux-gnueabihf"
        elif arch == "win64":
            return "x86_64-pc-windows-gnu"
        else:
            return f"{arch}-unknown-linux-gnu"
    elif os.name == "nt":
        if arch == "win64":
            return f"x86_64-pc-windows-msvc"
        else:
            return f"{arch}-pc-windows-msvc"
    else:
        raise Exception(f"Unsupported build target: {os.name}")


def get_cargo_env(target: TestTarget, build_arch: Arch):
    """Environment variables to make cargo use the test target."""
    env: dict[str, str] = BUILD_ENV.copy()
    cargo_target = get_cargo_build_target(build_arch)
    upper_target = cargo_target.upper().replace("-", "_")
    if build_arch != platform.machine():
        env["CARGO_BUILD_TARGET"] = cargo_target
    if not target.is_host:
        env[f"CARGO_TARGET_{upper_target}_RUNNER"] = f"{SCRIPT_PATH} exec-file"
    env["CROSVM_TEST_TARGET"] = str(target)
    return env


def write_envrc(values: dict[str, str]):
    with open(ENVRC_PATH, "w") as file:
        for key, value in values.items():
            file.write(f'export {key}="{value}"\n')


def set_target(target: TestTarget, build_arch: Optional[Arch]):
    prepare_target(target)
    if not build_arch:
        build_arch = target.arch
    write_envrc(get_cargo_env(target, build_arch))
    print(f"Test target: {target}")
    print(f"Target Architecture: {build_arch}")


def exec_file_on_target(
    target: TestTarget,
    filepath: Path,
    timeout: int,
    args: list[str] = [],
    extra_files: list[Path] = [],
    **kwargs: Any,
):
    """Executes a file on the test target.

    The file is uploaded to the target's home directory (if it's an ssh or vm
    target) plus any additional extra files provided, then executed and
    deleted afterwards.

    If the test target is 'host', files will just be executed locally.

    Timeouts will trigger a subprocess.TimeoutExpired exception, which contanins
    any output produced by the subprocess until the timeout.
    """
    env = os.environ.copy()
    if not target.ssh:
        # Allow test binaries to find rust's test libs.
        if os.name == "posix":
            env["LD_LIBRARY_PATH"] = str(find_rust_lib_dir())
        elif os.name == "nt":
            if not env["PATH"]:
                env["PATH"] = str(find_rust_lib_dir())
            else:
                env["PATH"] += ";" + str(find_rust_lib_dir())
        else:
            raise Exception(f"Unsupported build target: {os.name}")

        cmd_line = [str(filepath), *args]
        return subprocess.run(
            cmd_line,
            env=env,
            timeout=timeout,
            text=True,
            **kwargs,
        )
    else:
        filename = Path(filepath).name
        target.ssh.upload_files([filepath] + extra_files, quiet=True)
        try:
            result = target.ssh.run(
                f"chmod +x {filename} && sudo LD_LIBRARY_PATH=. ./{filename} {' '.join(args)}",
                timeout=timeout,
                text=True,
                **kwargs,
            )
        finally:
            # Remove uploaded files regardless of test result
            all_filenames = [filename] + [f.name for f in extra_files]
            target.ssh.check_output(f"sudo rm {' '.join(all_filenames)}")
        return result


def exec_file(
    target: TestTarget,
    filepath: Path,
    args: list[str] = [],
    timeout: int = 60,
    extra_files: list[Path] = [],
):
    if not filepath.exists():
        raise Exception(f"File does not exist: {filepath}")

    print(f"Executing `{Path(filepath).name} {' '.join(args)}` on {target}")
    try:
        sys.exit(exec_file_on_target(target, filepath, timeout, args, extra_files).returncode)
    except subprocess.TimeoutExpired as e:
        print(f"Process timed out after {e.timeout}s")


def main():
    COMMANDS = [
        "set",
        "exec-file",
    ]

    parser = argparse.ArgumentParser(usage=USAGE)
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("--target", type=str, help="Override default test target.")
    parser.add_argument(
        "--arch",
        choices=typing.get_args(Arch),
        help="Override target build architecture.",
    )
    parser.add_argument(
        "--extra-files",
        type=str,
        nargs="*",
        default=[],
        help="Additional files required by the binary to execute.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Kill the process after the specified timeout.",
    )
    parser.add_argument("remainder", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.command == "set":
        if len(args.remainder) != 1:
            parser.error("Need to specify a target.")
        set_target(TestTarget(args.remainder[0]), args.arch)
        return

    if args.target:
        target = TestTarget(args.target)
    else:
        target = TestTarget.default()

    if args.command == "exec-file":
        if len(args.remainder) < 1:
            parser.error("Need to specify a file to execute.")
        exec_file(
            target,
            Path(args.remainder[0]),
            args=args.remainder[1:],
            timeout=args.timeout,
            extra_files=[Path(f) for f in args.extra_files],
        )


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print("Command failed:", e.cmd)
        print(e.stdout)
        print(e.stderr)
        sys.exit(-1)
