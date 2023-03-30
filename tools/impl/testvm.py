# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import itertools
import json
import os
import socket
import subprocess
import sys
import time
import typing
from contextlib import closing
from pathlib import Path
from typing import Dict, Iterable, List, Literal, Optional, Tuple

from .common import CACHE_DIR, download_file

KVM_SUPPORT = os.access("/dev/kvm", os.W_OK)

Arch = Literal["x86_64", "aarch64"]
ARCH_OPTIONS = typing.get_args(Arch)

SCRIPT_DIR = Path(__file__).parent.resolve()
SRC_DIR = SCRIPT_DIR.joinpath("testvm")
ID_RSA = SRC_DIR.joinpath("id_rsa")
BASE_IMG_VERSION = open(SRC_DIR.joinpath("version"), "r").read().strip()

IMAGE_DIR_URL = "https://storage.googleapis.com/crosvm/testvm"


def cargo_target_dir():
    # Do not call cargo if we have the environment variable specified. This
    # allows the script to be used when cargo is not available but the target
    # dir is known.
    env_target = os.environ.get("CARGO_TARGET_DIR")
    if env_target:
        return Path(env_target)
    text = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version=1"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    metadata = json.loads(text)
    return Path(metadata["target_directory"])


def data_dir(arch: Arch):
    return CACHE_DIR.joinpath("crosvm_tools").joinpath(arch)


def pid_path(arch: Arch):
    return data_dir(arch).joinpath("pid")


def base_img_name(arch: Arch):
    return f"base-{arch}-{BASE_IMG_VERSION}.qcow2"


def base_img_url(arch: Arch):
    return f"{IMAGE_DIR_URL}/{base_img_name(arch)}"


def base_img_path(arch: Arch):
    return data_dir(arch).joinpath(base_img_name(arch))


def rootfs_img_path(arch: Arch):
    return data_dir(arch).joinpath(f"rootfs-{arch}-{BASE_IMG_VERSION}.qcow2")


# List of ports to use for SSH for each architecture
SSH_PORTS: Dict[Arch, int] = {
    "x86_64": 9000,
    "aarch64": 9001,
}

# QEMU arguments shared by all architectures
SHARED_ARGS: List[Tuple[str, str]] = [
    ("-display", "none"),
    ("-device", "virtio-net-pci,netdev=net0"),
    ("-smp", "8"),
    ("-m", "4G"),
]

# Arguments to QEMU for each architecture
ARCH_TO_QEMU: Dict[Arch, Tuple[str, List[Iterable[str]]]] = {
    # arch: (qemu-binary, [(param, value), ...])
    "x86_64": (
        "qemu-system-x86_64",
        [
            ("-cpu", "host"),
            ("-netdev", f"user,id=net0,hostfwd=tcp::{SSH_PORTS['x86_64']}-:22"),
            *([("-enable-kvm",)] if KVM_SUPPORT else []),
            *SHARED_ARGS,
        ],
    ),
    "aarch64": (
        "qemu-system-aarch64",
        [
            ("-M", "virt"),
            ("-machine", "virt,virtualization=true,gic-version=3"),
            ("-cpu", "cortex-a57"),
            ("-bios", "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"),
            (
                "-netdev",
                f"user,id=net0,hostfwd=tcp::{SSH_PORTS['aarch64']}-:22",
            ),
            *SHARED_ARGS,
        ],
    ),
}


def ssh_opts(arch: Arch) -> Dict[str, str]:
    return {
        "Port": str(SSH_PORTS[arch]),
        "User": "crosvm",
        "StrictHostKeyChecking": "no",
        "UserKnownHostsFile": "/dev/null",
        "LogLevel": "ERROR",
        "IdentityFile": str(ID_RSA),
    }


def ssh_cmd_args(arch: Arch):
    return [f"-o{k}={v}" for k, v in ssh_opts(arch).items()]


def ssh_exec(arch: Arch, cmd: Optional[str] = None):
    subprocess.run(
        [
            "ssh",
            "localhost",
            *ssh_cmd_args(arch),
            *(["-T", cmd] if cmd else []),
        ],
    ).check_returncode()


def ping_vm(arch: Arch):
    os.chmod(ID_RSA, 0o600)
    return (
        subprocess.run(
            [
                "ssh",
                "localhost",
                *ssh_cmd_args(arch),
                "-oConnectTimeout=1",
                "-T",
                "exit",
            ],
            capture_output=True,
        ).returncode
        == 0
    )


def write_pid_file(arch: Arch, pid: int):
    with open(pid_path(arch), "w") as pid_file:
        pid_file.write(str(pid))


def read_pid_file(arch: Arch):
    if not pid_path(arch).exists():
        return None

    with open(pid_path(arch), "r") as pid_file:
        return int(pid_file.read())


def run_qemu(
    arch: Arch,
    hda: Path,
    background: bool = False,
):
    if not is_ssh_port_available(arch):
        print(f"Port {SSH_PORTS[arch]} is occupied, but is required for the {arch} vm to run.")
        print(f"You may be running the {arch}vm in another place and need to kill it.")
        sys.exit(1)

    (binary, arch_args) = ARCH_TO_QEMU[arch]
    qemu_args = [*arch_args, ("-hda", str(hda))]
    if background:
        qemu_args.append(("-serial", f"file:{data_dir(arch).joinpath('vm_log')}"))
    else:
        qemu_args.append(("-serial", "stdio"))

    # Flatten list of tuples into flat list of arguments
    qemu_cmd = [binary, *itertools.chain(*qemu_args)]
    process = subprocess.Popen(qemu_cmd, start_new_session=background)
    write_pid_file(arch, process.pid)
    if not background:
        process.wait()


def run_vm(arch: Arch, background: bool = False):
    run_qemu(
        arch,
        rootfs_img_path(arch),
        background=background,
    )


def is_running(arch: Arch):
    pid = read_pid_file(arch)
    if pid is None:
        return False

    # Send signal 0 to check if the process is alive
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def kill_vm(arch: Arch):
    pid = read_pid_file(arch)
    if pid:
        os.kill(pid, 9)


def build_if_needed(arch: Arch, reset: bool = False):
    if reset and is_running(arch):
        print("Killing existing VM...")
        kill_vm(arch)
        time.sleep(1)

    data_dir(arch).mkdir(parents=True, exist_ok=True)

    base_img = base_img_path(arch)
    if not base_img.exists():
        print(f"Downloading base image ({base_img_url(arch)})...")
        download_file(base_img_url(arch), base_img_path(arch))

    rootfs_img = rootfs_img_path(arch)
    if not rootfs_img.exists() or reset:
        # The rootfs is backed by the base image generated above. So we can
        # easily reset to a clean VM by rebuilding an empty rootfs image.
        print("Creating rootfs overlay...")
        subprocess.run(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                base_img,
                rootfs_img,
                "4G",
            ]
        ).check_returncode()


def is_ssh_port_available(arch: Arch):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        return sock.connect_ex(("127.0.0.1", SSH_PORTS[arch])) != 0


def up(arch: Arch, reset: bool = False):
    "Start the VM if it's not already running."
    if is_running(arch):
        return

    build_if_needed(arch, reset)
    print("Booting VM...")
    run_qemu(
        arch,
        rootfs_img_path(arch),
        background=True,
    )


def wait(arch: Arch, timeout: int = 120):
    "Blocks until the VM is ready to use."
    up(arch)
    if ping_vm(arch):
        return

    print("Waiting for VM")
    start_time = time.time()
    while (time.time() - start_time) < timeout:
        time.sleep(1)
        sys.stdout.write(".")
        sys.stdout.flush()
        if ping_vm(arch):
            print()
            return
    raise Exception("Timeout while waiting for VM")
