# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from enum import Enum
import json
import os
import socket
import subprocess
import sys
import time
import typing
from contextlib import closing
from pathlib import Path
from random import randrange
from typing import Dict, List, Literal, Optional, Tuple

from .common import CACHE_DIR, download_file, cmd, rich, console

KVM_SUPPORT = os.access("/dev/kvm", os.W_OK)

Arch = Literal["x86_64", "aarch64"]
ARCH_OPTIONS = typing.cast(Tuple[Arch], typing.get_args(Arch))


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


def ssh_port_path(arch: Arch):
    return data_dir(arch).joinpath("ssh_port")


def log_path(arch: Arch):
    return data_dir(arch).joinpath("vm_log")


def base_img_name(arch: Arch):
    return f"base-{arch}-{BASE_IMG_VERSION}.qcow2"


def base_img_url(arch: Arch):
    return f"{IMAGE_DIR_URL}/{base_img_name(arch)}"


def base_img_path(arch: Arch):
    return data_dir(arch).joinpath(base_img_name(arch))


def rootfs_img_path(arch: Arch):
    return data_dir(arch).joinpath(f"rootfs-{arch}-{BASE_IMG_VERSION}.qcow2")


def ssh_port(arch: Arch) -> int:
    # Default to fixed ports used by VMs started by previous versions of this script.
    # TODO(b/275717656): Remove after a while
    if not ssh_port_path(arch).exists():
        return SSH_PORTS[arch]
    return int(ssh_port_path(arch).read_text())


ssh = cmd("ssh")
qemu_img = cmd("qemu-img")

# List of ports to use for SSH for each architecture
# TODO(b/275717656): Remove after a while
SSH_PORTS: Dict[Arch, int] = {
    "x86_64": 9000,
    "aarch64": 9001,
}

# QEMU arguments shared by all architectures
SHARED_ARGS: List[str] = [
    "-display none",
    "-device virtio-net-pci,netdev=net0",
    "-smp 8",
    "-m 4G",
]

# QEMU command for each architecture
ARCH_TO_QEMU: Dict[Arch, cmd] = {
    "x86_64": cmd(
        "qemu-system-x86_64",
        "-cpu host",
        "-enable-kvm" if KVM_SUPPORT else None,
        *SHARED_ARGS,
    ),
    "aarch64": cmd(
        "qemu-system-aarch64",
        "-M virt",
        "-machine virt,virtualization=true,gic-version=3",
        "-cpu cortex-a57",
        "-bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
        *SHARED_ARGS,
    ),
}


def ssh_opts(arch: Arch) -> Dict[str, str]:
    return {
        "Port": str(ssh_port(arch)),
        "User": "crosvm",
        "StrictHostKeyChecking": "no",
        "UserKnownHostsFile": "/dev/null",
        "LogLevel": "ERROR",
        "IdentityFile": str(ID_RSA),
    }


def ssh_cmd_args(arch: Arch):
    return [f"-o{k}={v}" for k, v in ssh_opts(arch).items()]


def ssh_exec(arch: Arch, cmd: Optional[str] = None):
    os.chmod(ID_RSA, 0o600)
    ssh.with_args(
        "localhost",
        *ssh_cmd_args(arch),
        *(["-T", cmd] if cmd else []),
    ).fg(check=False)


def ping_vm(arch: Arch):
    os.chmod(ID_RSA, 0o600)
    return ssh(
        "localhost",
        *ssh_cmd_args(arch),
        "-oConnectTimeout=1",
        "-T exit",
    ).success()


def write_pid_file(arch: Arch, pid: int):
    with open(pid_path(arch), "w") as pid_file:
        pid_file.write(str(pid))


def read_pid_file(arch: Arch):
    if not pid_path(arch).exists():
        return None

    with open(pid_path(arch), "r") as pid_file:
        return int(pid_file.read())


def is_port_available(port: int):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        return sock.connect_ex(("127.0.0.1", port)) != 0


def pick_ssh_port():
    for _ in range(5):
        port = randrange(1024, 32768)
        if is_port_available(port):
            return port
    raise Exception("Could not find a free port")


def run_qemu(
    arch: Arch,
    hda: Path,
    background: bool = False,
):
    port = pick_ssh_port()

    qemu = ARCH_TO_QEMU[arch]
    if background:
        serial = f"file:{data_dir(arch).joinpath('vm_log')}"
    else:
        serial = "stdio"

    console.print(f"Booting {arch} VM with disk", hda)
    command = qemu.with_args(
        f"-hda {hda}",
        f"-serial {serial}",
        f"-netdev user,id=net0,hostfwd=tcp::{port}-:22",
    )
    if background:
        # Start qemu in a new session so it can outlive this process.
        process = command.popen(
            start_new_session=background, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )

        # Wait for 1s to see if the qemu is staying alive.
        assert process.stdout
        for _ in range(10):
            if process.poll() is not None:
                sys.stdout.write(process.stdout.read())
                print(f"'{command}' exited with code {process.returncode}")
                sys.exit(process.returncode)
            time.sleep(0.1)

        # Print any warnings qemu might produce.
        sys.stdout.write(process.stdout.read(0))
        sys.stdout.flush()
        process.stdout.close()

        # Save port and pid so we can manage the process later.
        ssh_port_path(arch).write_text(str(port))
        write_pid_file(arch, process.pid)
    else:
        command.fg()


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
        try:
            os.kill(pid, 9)
            # Ping with signal 0 until we get an OSError indicating the process has shutdown.
            while True:
                os.kill(pid, 0)
        except OSError:
            return


def build_if_needed(arch: Arch, reset: bool = False):
    if reset and is_running(arch):
        print(f"Killing existing {arch} VM to perform reset...")
        kill_vm(arch)
        time.sleep(1)

    data_dir(arch).mkdir(parents=True, exist_ok=True)

    base_img = base_img_path(arch)
    if not base_img.exists():
        print(f"Downloading {arch} base image ({base_img_url(arch)})...")
        download_file(base_img_url(arch), base_img_path(arch))

    rootfs_img = rootfs_img_path(arch)
    if not rootfs_img.exists() or reset:
        # The rootfs is backed by the base image generated above. So we can
        # easily reset to a clean VM by rebuilding an empty rootfs image.
        print(f"Creating {arch} rootfs overlay...")
        qemu_img.with_args(
            "create",
            "-f qcow2",
            "-F qcow2",
            f"-b {base_img}",
            rootfs_img,
            "8G",
        ).fg(quiet=True)


def up(arch: Arch, reset: bool = False, wait: bool = False, timeout: int = 120):
    "Starts the test vm if it's not already running. Optionally wait for it to be reachable."

    # Try waiting for the running VM, if it does not become reachable, kill it.
    if is_running(arch):
        if not wait:
            console.print(f"{arch} VM is running on port {ssh_port(arch)}")
            return
        if not wait_until_reachable(arch, timeout):
            if is_running(arch):
                print(f"{arch} VM is not reachable. Restarting it.")
                kill_vm(arch)
            else:
                print(f"{arch} VM stopped. Starting it again.")
        else:
            console.print(f"{arch} VM is running on port {ssh_port(arch)}")
            return

    build_if_needed(arch, reset)
    run_qemu(
        arch,
        rootfs_img_path(arch),
        background=True,
    )

    if wait:
        if wait_until_reachable(arch, timeout):
            console.print(f"{arch} VM is running on port {ssh_port(arch)}")
        else:
            raise Exception(f"Waiting for {arch} VM timed out.")


def wait_until_reachable(arch: Arch, timeout: int = 120):
    "Blocks until the VM is ready to use."
    if not is_running(arch):
        return False
    if ping_vm(arch):
        return True

    with rich.live.Live(
        rich.spinner.Spinner("point", f"Waiting for {arch} VM to become reachable...")
    ):
        start_time = time.time()
        while (time.time() - start_time) < timeout:
            if not is_running(arch):
                return False
            if ping_vm(arch):
                return True
    return False


class VmState(Enum):
    REACHABLE = "Reachable"
    RUNNING_NOT_REACHABLE = "Running, but not reachable"
    STOPPED = "Stopped"


def state(arch: Arch):
    if is_running(arch):
        if ping_vm(arch):
            return VmState.REACHABLE
        else:
            return VmState.RUNNING_NOT_REACHABLE
    else:
        return VmState.STOPPED
