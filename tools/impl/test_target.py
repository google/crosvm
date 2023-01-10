# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import functools
import platform
import re
import subprocess
from pathlib import Path
from typing import Any, Literal, Optional, cast, List, Dict, NamedTuple
import sys
from . import testvm
import os

USAGE = """Choose to run tests locally, in a vm or on a remote machine.

To set the default test target to run on one of the build-in VMs:

    ./tools/test_target set vm:aarch64 && source .envrc

Then as usual run cargo or run_tests:

    ./tools/run_tests
    cargo test

The command will prepare the VM for testing (e.g. upload required shared
libraries for running rust tests) and set up run_tests as well as cargo
to build for the test target and execute tests on it.

Arbitrary SSH remotes can be used for running tests as well. e.g.

    ./tools/test_target set ssh:remotehost

The `remotehost` needs to be properly configured for passwordless
authentication.

Tip: Use http://direnv.net to automatically load the envrc file instead of
having to source it after each call.
"""

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent.resolve()
CROSVM_ROOT = (SCRIPT_DIR / "../../").resolve()
TESTVM_DIR = SCRIPT_DIR.parent.joinpath("testvm")
TARGET_DIR = testvm.cargo_target_dir().joinpath("crosvm_tools")
ENVRC_PATH = SCRIPT_DIR.parent.parent.joinpath(".envrc")

Arch = Literal["x86_64", "aarch64", "armhf", "win64"]

# Enviroment variables needed for building with cargo
BUILD_ENV = {
    "PKG_CONFIG_armv7_unknown_linux_gnueabihf": "arm-linux-gnueabihf-pkg-config",
}

if platform.machine() != "aarch64":
    BUILD_ENV.update(
        {
            "PKG_CONFIG_aarch64_unknown_linux_gnu": "aarch64-linux-gnu-pkg-config",
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": "aarch64-linux-gnu-gcc",
        }
    )


class Ssh:
    """Wrapper around subprocess to execute commands remotely via SSH."""

    hostname: str
    opts: List[str]

    def __init__(self, hostname: str, opts: List[str] = []):
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

    def upload_files(self, files: List[Path], remote_dir: str = "", quiet: bool = False):
        """Wrapper around SCP."""
        flags = ["-q"] if quiet else []
        scp_cmd = [
            "scp",
            *flags,
            *self.opts,
            *(str(f) for f in files),
            f"{self.hostname}:{remote_dir}",
        ]
        return subprocess.run(scp_cmd, check=True)

    def download_files(
        self, remote_file: str, target_dir: Path, quiet: bool = False, check: bool = True
    ):
        """Wrapper around SCP."""
        flags = ["-q"] if quiet else []
        scp_cmd = ["scp", *flags, *self.opts, f"{self.hostname}:{remote_file}", str(target_dir)]
        return subprocess.run(scp_cmd, check=check)


SHORTHANDS = {
    "mingw64": "x86_64-pc-windows-gnu",
    "msvc64": "x86_64-pc-windows-msvc",
    "armhf": "armv7-unknown-linux-gnueabihf",
    "aarch64": "aarch64-unknown-linux-gnu",
    "x86_64": "x86_64-unknown-linux-gnu",
}


def crosvm_target_dir():
    crosvm_target = os.environ.get("CROSVM_TARGET_DIR")
    cargo_target = os.environ.get("CARGO_TARGET_DIR")
    if crosvm_target:
        return Path(crosvm_target)
    elif cargo_target:
        return Path(cargo_target) / "crosvm"
    else:
        return CROSVM_ROOT / "target/crosvm"


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
        env: Dict[str, str] = BUILD_ENV.copy()
        cargo_target = str(self)
        env["CARGO_BUILD_TARGET"] = cargo_target
        env["CARGO_TARGET_DIR"] = str(self.target_dir)
        env["CROSVM_TARGET_DIR"] = str(crosvm_target_dir())
        return env

    def __str__(self):
        return f"{self.arch}-{self.vendor}-{self.sys}-{self.abi}"


def guess_emulator(native_triple: Triple, build_triple: Triple) -> Optional[List[str]]:
    "Guesses which emulator binary to use to run build_triple on a native_triple machine."
    if build_triple == native_triple:
        return None
    # aarch64 can natively run armv7 code in compatibility mode.
    if build_triple.arch == "armv7" and native_triple.arch == "aarch64":
        return None
    # Use wine64 to run windows binaries on linux
    if build_triple.sys == "windows" and str(native_triple) == "x86_64-unknown-linux-gnu":
        return ["wine64-stable"]
    # Use qemu to run aarch64 on x86
    if build_triple.arch == "aarch64" and native_triple.arch == "x86_64":
        return ["qemu-aarch64-static"]
    # Use qemu to run armv7 on x86
    if build_triple.arch == "armv7" and native_triple.arch == "x86_64":
        return ["qemu-arm-static"]
    raise Exception(f"Don't know how to emulate {build_triple} on {native_triple}")


class TestTarget(object):
    """
    A test target can be the local host, a VM or a remote devica via SSH.

    Allows an emulation command to be specified which can run a different build target than the
    devices native triple.
    """

    target_str: str
    is_host: bool = True
    vm: Optional[testvm.Arch] = None
    ssh: Optional[Ssh] = None

    override_build_triple: Optional[Triple] = None
    emulator_cmd: Optional[List[str]] = None

    @classmethod
    def default(cls):
        build_target = os.environ.get("CARGO_BUILD_TARGET", None)
        return cls(
            os.environ.get("CROSVM_TEST_TARGET", "host"),
            Triple.from_str(build_target) if build_target else None,
        )

    def __init__(
        self,
        target_str: str,
        override_build_triple: Optional[Triple] = None,
        emulator_cmd: Optional[List[str]] = None,
    ):
        """target_str can be "vm:arch", "ssh:hostname" or just "host" """
        self.target_str = target_str
        parts = target_str.split(":")
        if len(parts) == 2 and parts[0] == "vm":
            vm_arch = cast(testvm.Arch, parts[1])
            self.vm = vm_arch
            self.ssh = Ssh("localhost", testvm.ssh_cmd_args(vm_arch))
            self.is_host = False
        elif len(parts) == 2 and parts[0] == "ssh":
            self.ssh = Ssh(parts[1])
            self.is_host = False
        elif len(parts) == 1 and parts[0] == "host":
            pass
        else:
            raise Exception(f"Invalid target {target_str}")
        self.override_build_triple = override_build_triple

        if emulator_cmd is not None:
            self.emulator_cmd = emulator_cmd
        elif override_build_triple:
            self.emulator_cmd = guess_emulator(self.native_triple, override_build_triple)

    @property
    def is_native(self):
        if not self.override_build_triple:
            return True
        return self.build_triple.arch == self.native_triple.arch

    @property
    def build_triple(self):
        """
        Triple to build for to run on this test target.

        May not be the same as the native_triple of the device if an emulator is used or the triple
        has been overridden.
        """
        if self.override_build_triple:
            return self.override_build_triple
        return self.native_triple

    @functools.cached_property
    def native_triple(self):
        """Native triple of the the device on which the test is running."""
        if self.vm:
            return Triple.from_linux_arch(self.vm)
        elif self.ssh:
            return Triple.from_linux_arch(self.ssh.check_output("arch").strip())
        elif self.is_host:
            return Triple.host_default()
        else:
            raise Exception(f"Invalid TestTarget({self})")

    def __str__(self):
        if self.emulator_cmd:
            return f"{self.target_str} ({self.build_triple} via {' '.join(self.emulator_cmd)})"
        else:
            return f"{self.target_str} ({self.build_triple})"


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


def prepare_remote(ssh: Ssh, extra_files: List[Path] = []):
    print("Preparing remote")
    ssh.upload_files(list(find_rust_libs()) + extra_files)
    pass


def prepare_target(target: TestTarget, extra_files: List[Path] = []):
    if target.vm:
        testvm.build_if_needed(target.vm)
        testvm.wait(target.vm)
    if target.ssh:
        prepare_remote(target.ssh, extra_files)


def get_cargo_env(target: TestTarget):
    """Environment variables to make cargo use the test target."""
    env: Dict[str, str] = BUILD_ENV.copy()
    env.update(target.build_triple.get_cargo_env())
    cargo_target = str(target.build_triple)
    upper_target = cargo_target.upper().replace("-", "_")
    if not target.is_host or target.emulator_cmd:
        script_path = CROSVM_ROOT / "tools/test_target"
        env[f"CARGO_TARGET_{upper_target}_RUNNER"] = f"{script_path} exec-file"
    env["CROSVM_TEST_TARGET"] = target.target_str
    return env


def write_envrc(values: Dict[str, str]):
    with open(ENVRC_PATH, "w") as file:
        for key, value in values.items():
            file.write(f'export {key}="{value}"\n')


def set_target(target: TestTarget):
    prepare_target(target)
    write_envrc(get_cargo_env(target))
    print(f"Test target: {target}")
    print(f"Target Architecture: {target.build_triple}")


def list_profile_files(binary_path: Path):
    return binary_path.parent.glob(f"{binary_path.name}.profraw.*")


def exec_file_on_target(
    target: TestTarget,
    filepath: Path,
    timeout: int,
    args: List[str] = [],
    extra_files: List[Path] = [],
    generate_profile: bool = False,
    execute_as_root: bool = False,
    **kwargs: Any,
):
    """Executes a file on the test target.

    The file is uploaded to the target's home directory (if it's an ssh or vm
    target) plus any additional extra files provided, then executed and
    deleted afterwards.

    If the test target is 'host', files will just be executed locally.

    Timeouts will trigger a subprocess.TimeoutExpired exception, which contanins
    any output produced by the subprocess until the timeout.

    Coverage profiles can be generated by setting `generate_profile` and will be written to
    "$filepath.profraw.$PID". Existing profiles are deleted.
    """
    env = os.environ.copy()
    prefix = target.emulator_cmd if target.emulator_cmd else []

    # Delete existing profile files
    profile_prefix = filepath.with_suffix(".profraw")
    if generate_profile:
        for path in list_profile_files(filepath):
            path.unlink()

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
        if generate_profile:
            env["LLVM_PROFILE_FILE"] = f"{profile_prefix}.%p"

        cmd_line = [*prefix, str(filepath), *args]
        if execute_as_root:
            cmd_line = ["sudo", "--preserve-env", *cmd_line]
        return subprocess.run(
            cmd_line,
            env=env,
            timeout=timeout,
            text=True,
            shell=False,
            **kwargs,
        )
    else:
        filename = Path(filepath).name
        target.ssh.upload_files([filepath] + extra_files, quiet=True)
        cmd_line = [*prefix, f"./{filename}", *args]

        remote_profile_prefix = f"/tmp/{filename}.profraw"
        if generate_profile:
            target.ssh.check_output(f"sudo rm -f {remote_profile_prefix}*")
            cmd_line = [f"LLVM_PROFILE_FILE={remote_profile_prefix}.%p", *cmd_line]

        try:
            result = target.ssh.run(
                f"chmod +x {filename} && sudo LD_LIBRARY_PATH=. {' '.join(cmd_line)}",
                timeout=timeout,
                text=True,
                **kwargs,
            )
        finally:
            # Remove uploaded files regardless of test result
            all_filenames = [filename] + [f.name for f in extra_files]
            target.ssh.check_output(f"sudo rm {' '.join(all_filenames)}")
            if generate_profile:
                # Fail silently. Some tests don't write a profile file.
                target.ssh.download_files(
                    f"{remote_profile_prefix}*", profile_prefix.parent, check=False, quiet=True
                )
                target.ssh.check_output(f"sudo rm -f {remote_profile_prefix}*")

        return result


def exec_file(
    target: TestTarget,
    filepath: Path,
    args: List[str] = [],
    timeout: int = 60,
    extra_files: List[Path] = [],
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
        "--build-target",
        type=str,
        help="Override target build triple (e.g. x86_64-unknown-linux-gnu).",
    )
    parser.add_argument("--arch", help="Deprecated. Please use --build-target instead."),
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

    if args.arch:
        print("--arch is deprecated. Please use --build-target instead.")

    if args.command == "set":
        if len(args.remainder) != 1:
            parser.error("Need to specify a target.")
        set_target(TestTarget(args.remainder[0], Triple.from_shorthand(args.build_target)))
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
