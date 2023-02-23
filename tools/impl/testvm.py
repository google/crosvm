# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import itertools
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request as request
from contextlib import closing
from pathlib import Path
from typing import Dict, Iterable, List, Literal, Optional, Tuple

from .common import CACHE_DIR

USAGE = """%(prog)s {command} [options]

Manages VMs for testing crosvm.

Can run an x86_64 and an aarch64 vm via `./tools/x86vm` and `./tools/aarch64vm`.
The VM image will be downloaded and initialized on first use.

The easiest way to use the VM is:

  $ ./tools/aarch64vm ssh

Which will initialize and boot the VM, then wait for SSH to be available and
opens an SSH session. The VM will stay alive between calls.

Alternatively, you can set up an SSH config to connect to the VM. First ensure
the VM ready:

  $ ./tools/aarch64vm wait

Then append the VMs ssh config to your SSH config:

  $ ./tools/aarch64vm ssh_config >> ~/.ssh/config

And connect as usual:

  $ ssh crosvm_$ARCH

Commands:

  build: Download base image and create rootfs overlay.
  up: Ensure that the VM is running in the background.
  run: Run the VM in the foreground process for debugging.
  wait: Boot the VM if it's offline and wait until it's available.
  ssh: SSH into the VM. Boot and wait if it's not available.
  ssh_config: Prints the ssh config needed to connnect to the VM.
  stop: Gracefully shutdown the VM.
  kill: Kill the QEMU process. Might damage the image file.
  clean: Stop all VMs and delete all data.
"""

KVM_SUPPORT = os.access("/dev/kvm", os.W_OK)

Arch = Literal["x86_64", "aarch64"]

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
        request.urlretrieve(base_img_url(arch), base_img_path(arch))

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


def up(arch: Arch):
    if is_running(arch):
        return

    print("Booting VM...")
    run_qemu(
        arch,
        rootfs_img_path(arch),
        background=True,
    )


def run(arch: Arch):
    if is_running(arch):
        raise Exception("VM is already running")
    run_qemu(
        arch,
        rootfs_img_path(arch),
        background=False,
    )


def wait(arch: Arch, timeout: int = 120):
    if not is_running(arch):
        up(arch)
    elif ping_vm(arch):
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


def ssh(arch: Arch, timeout: int):
    wait(arch, timeout)
    ssh_exec(arch)


def ssh_config(arch: Arch):
    print(f"Host crosvm_{arch}")
    print(f"    HostName localhost")
    for opt, value in ssh_opts(arch).items():
        print(f"    {opt} {value}")


def stop(arch: Arch):
    if not is_running(arch):
        print("VM is not running.")
        return
    ssh_exec(arch, "sudo poweroff")


def kill(arch: Arch):
    if not is_running(arch):
        print("VM is not running.")
        return
    kill_vm(arch)


def clean(arch: Arch):
    if is_running(arch):
        kill(arch)
    if data_dir(arch).exists():
        shutil.rmtree(data_dir(arch))


def main(arch: Arch, argv: List[str]):
    COMMANDS = [
        "build",
        "up",
        "run",
        "wait",
        "ssh",
        "ssh_config",
        "stop",
        "kill",
        "clean",
    ]
    parser = argparse.ArgumentParser(usage=USAGE)
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset VM image to a fresh state. Removes all user modifications.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout in seconds while waiting for the VM to come up.",
    )
    args = parser.parse_args(argv)

    if args.command == "clean":
        clean(arch)
        return

    if args.command == "ssh_config":
        ssh_config(arch)
        return

    # Ensure the images are built regardless of which command we execute.
    build_if_needed(arch, reset=args.reset)

    if args.command == "build":
        return  # Nothing left to do.
    elif args.command == "run":
        run(arch)
    elif args.command == "up":
        up(arch)
    elif args.command == "ssh":
        ssh(arch, args.timeout)
    elif args.command == "stop":
        stop(arch)
    elif args.command == "kill":
        kill(arch)
    elif args.command == "wait":
        wait(arch, args.timeout)
    else:
        print(f"Unknown command {args.command}")
