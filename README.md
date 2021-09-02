# crosvm - The Chrome OS Virtual Machine Monitor

This component, known as crosvm, runs untrusted operating systems along with
virtualized devices. This only runs VMs through the Linux's KVM interface. What
makes crosvm unique is a focus on safety within the programming language and a
sandbox around the virtual devices to protect the kernel from attack in case of
an exploit in the devices.

[TOC]

## Building for Linux

Crosvm uses submodules to manage external dependencies. Initialize them via:

```sh
git submodule update --init
```

It is recommended to enable automatic recursive operations to keep the
submodules in sync with the main repository (But do not push them, as that can
conflict with `repo`):

```sh
git config --global submodule.recurse true
git config push.recurseSubmodules no
```

Crosvm requires a couple of dependencies. For Debian derivatives these can be
installed by (Depending on which feature flags are used, not all of these will
actually be required):

```sh
sudo apt install \
    bindgen \
    build-essential \
    clang \
    libasound2-dev \
    libcap-dev \
    libdbus-1-dev \
    libdrm-dev \
    libepoxy-dev \
    libssl-dev \
    libwayland-bin \
    libwayland-dev \
    pkg-config \
    protobuf-compiler \
    python3 \
    wayland-protocols
```

And that's it! You should be able to `cargo build/run/test`.

### Known issues

-   By default, crosvm is running devices in sandboxed mode, which requires
    seccomp policy files to be set up. For local testing it is often easier to
    `--disable-sandbox` to run everything in a single process.
-   If your Linux header files are too old, you may find minijail rejecting
    seccomp filters for containing unknown syscalls. You can try removing the
    offending lines from the filter file, or add `--seccomp-log-failures` to the
    crosvm command line to turn these into warnings. Note that this option will
    also stop minijail from killing processes that violate the seccomp rule,
    making the sandboxing much less aggressive.
-   Seccomp policy files have hardcoded absolute paths. You can either fix up
    the paths locally, or set up an awesome hacky symlink:
    `sudo mkdir /usr/share/policy && sudo ln -s /path/to/crosvm/seccomp/x86_64 /usr/share/policy/crosvm`.
    We'll eventually build the precompiled policies
    [into the crosvm binary](http://crbug.com/1052126).
-   Devices can't be jailed if `/var/empty` doesn't exist.
    `sudo mkdir -p /var/empty` to work around this for now.
-   You need read/write permissions for `/dev/kvm` to run tests or other crosvm
    instances. Usually it's owned by the `kvm` group, so
    `sudo usermod -a -G kvm $USER` and then log out and back in again to fix
    this.
-   Some other features (networking) require `CAP_NET_ADMIN` so those usually
    need to be run as root.

## Running crosvm tests on Linux

### Installing Podman (or Docker)

See [Podman Installation](https://podman.io/getting-started/installation) for
instructions on how to install podman.

For Googlers, see [go/dont-install-docker](http://go/dont-install-docker) for
special instructions on how to set up podman.

If you already have docker installed, that will do as well. However podman is
recommended as it will not run containers with root privileges.

### Running all tests

To run all tests for all platforms, just run:

```
./test_all
```

This will run all tests using the x86 and aarch64 builder containers. What does
this do?

1.  It will start `./ci/[aarch64_]builder --vm`.

    This will start the builder container and launch a VM for running tests in
    the background. The VM is booting while the next step is running.

2.  It will call `./run_tests` inside the builder

    The script will pick which tests to execute and where. Simple tests can be
    executed directly, other tests require privileged access to devices and will
    be loaded into the VM to execute.

    Each test will in the end be executed by a call to
    `cargo test -p crate_name`.

Intermediate build data is stored in a scratch directory at `./target/ci/` to
allow for faster subsequent calls (Note: If running with docker, these files
will be owned by root).

### Fast, iterative test runs

For faster iteration time, you can directly invoke some of these steps directly:

To only run x86 tests: `./ci/[aarch64_]builder --vm ./run_tests`.

To run a simple test (e.g. the tempfile crate) that does not need the vm:
`./ci/[aarch64_]builder cargo test -p tempfile`.

Or run a single test (e.g. kvm_sys) inside the vm:
`./ci/[aarch64*]builder --vm cargo test -p kvm_sys`.

Since the VM (especially the fully emulated aarch64 VM) can be slow to boot, you
can start an interactive shell and run commands from there as usual. All cargo
tests will be executed inside the VM, without the need to restart the VM between
test calls.

```sh
host$ ./ci/aarch64_builder --vm
crosvm-aarch64$ ./run_tests
crosvm-aarch64$ cargo test -p kvm_sys
...
```

### Running tests without Docker

Specific crates can be tested as usual with `cargo test` without the need for
Docker. However, because of special requirements some of them will not work,
which means that `cargo test --workspace` will also not work to run all tests.

For this reason, we have a separate test runner `./run_tests` which documents
the requirements of each crate and picks the tests to run. It is used by the
Docker container to run tests, but can also be run outside of the container to
run a subset of tests.

See `./run_tests --help` for more information.

### Reproducing Kokoro locally

Kokoro runs presubmit tests on all crosvm changes. It uses the same builders and
the same `run_tests` script to run tests. This should match the results of the
`./test_all` script, but if it does not, the kokoro build scripts can be
simulated locally using: `./ci/kokoro/simulate_all`.

## Building for ChromeOS

crosvm is included in the ChromeOS source tree at `src/platform/crosvm`. Crosvm
can be built with ChromeOS features using Portage or cargo.

If ChromeOS-specific features are not needed, or you want to run the full test
suite of crosvm, the [Building for Linux](#building-for-linux) and
[Running crosvm tests](#running-crosvm-tests) workflows can be used from the
crosvm repository of ChromeOS as well.

### Using Portage

crosvm on ChromeOS is usually built with Portage, so it follows the same general
workflow as any `cros_workon` package. The full package name is
`chromeos-base/crosvm`.

See the [Chromium OS developer guide] for more on how to build and deploy with
Portage.

[chromium os developer guide]:
    https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_guide.md

NOTE: `cros_workon_make` modifies crosvm's Cargo.toml and Cargo.lock. Please be
careful not to commit the changes. Moreover, with the changes cargo will fail to
build and clippy preupload check will fail.

### Using Cargo

Since development using portage can be slow, it's possible to build crosvm for
ChromeOS using cargo for faster iteration times. To do so, the `Cargo.toml` file
needs to be updated to point to dependencies provided by ChromeOS using
`./setup_cros_cargo.sh`.

## Usage

To see the usage information for your version of crosvm, run `crosvm` or
`crosvm run --help`.

### Boot a Kernel

To run a very basic VM with just a kernel and default devices:

```bash
$ crosvm run "${KERNEL_PATH}"
```

The uncompressed kernel image, also known as vmlinux, can be found in your
kernel build directory in the case of x86 at `arch/x86/boot/compressed/vmlinux`.

### Rootfs

#### With a disk image

In most cases, you will want to give the VM a virtual block device to use as a
root file system:

```bash
$ crosvm run -r "${ROOT_IMAGE}" "${KERNEL_PATH}"
```

The root image must be a path to a disk image formatted in a way that the kernel
can read. Typically this is a squashfs image made with `mksquashfs` or an ext4
image made with `mkfs.ext4`. By using the `-r` argument, the kernel is
automatically told to use that image as the root, and therefore can only be
given once. More disks can be given with `-d` or `--rwdisk` if a writable disk
is desired.

To run crosvm with a writable rootfs:

> **WARNING:** Writable disks are at risk of corruption by a malicious or
> malfunctioning guest OS.

```bash
crosvm run --rwdisk "${ROOT_IMAGE}" -p "root=/dev/vda" vmlinux
```

> **NOTE:** If more disks arguments are added prior to the desired rootfs image,
> the `root=/dev/vda` must be adjusted to the appropriate letter.

#### With virtiofs

Linux kernel 5.4+ is required for using virtiofs. This is convenient for
testing. The file system must be named "mtd*" or "ubi*".

```bash
crosvm run --shared-dir "/:mtdfake:type=fs:cache=always" \
    -p "rootfstype=virtiofs root=mtdfake" vmlinux
```

### Control Socket

If the control socket was enabled with `-s`, the main process can be controlled
while crosvm is running. To tell crosvm to stop and exit, for example:

> **NOTE:** If the socket path given is for a directory, a socket name
> underneath that path will be generated based on crosvm's PID.

```bash
$ crosvm run -s /run/crosvm.sock ${USUAL_CROSVM_ARGS}
    <in another shell>
$ crosvm stop /run/crosvm.sock
```

> **WARNING:** The guest OS will not be notified or gracefully shutdown.

This will cause the original crosvm process to exit in an orderly fashion,
allowing it to clean up any OS resources that might have stuck around if crosvm
were terminated early.

### Multiprocess Mode

By default crosvm runs in multiprocess mode. Each device that supports running
inside of a sandbox will run in a jailed child process of crosvm. The
appropriate minijail seccomp policy files must be present either in
`/usr/share/policy/crosvm` or in the path specified by the
`--seccomp-policy-dir` argument. The sandbox can be disabled for testing with
the `--disable-sandbox` option.

### Virtio Wayland

Virtio Wayland support requires special support on the part of the guest and as
such is unlikely to work out of the box unless you are using a Chrome OS kernel
along with a `termina` rootfs.

To use it, ensure that the `XDG_RUNTIME_DIR` enviroment variable is set and that
the path `$XDG_RUNTIME_DIR/wayland-0` points to the socket of the Wayland
compositor you would like the guest to use.

### GDB Support

crosvm supports [GDB Remote Serial Protocol] to allow developers to debug guest
kernel via GDB.

You can enable the feature by `--gdb` flag:

```sh
# Use uncompressed vmlinux
$ crosvm run --gdb <port> ${USUAL_CROSVM_ARGS} vmlinux
```

Then, you can start GDB in another shell.

```sh
$ gdb vmlinux
(gdb) target remote :<port>
(gdb) hbreak start_kernel
(gdb) c
<start booting in the other shell>
```

For general techniques for debugging the Linux kernel via GDB, see this [kernel
documentation].

[gdb remote serial protocol]:
    https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html
[kernel documentation]:
    https://www.kernel.org/doc/html/latest/dev-tools/gdb-kernel-debugging.html

## Defaults

The following are crosvm's default arguments and how to override them.

-   256MB of memory (set with `-m`)
-   1 virtual CPU (set with `-c`)
-   no block devices (set with `-r`, `-d`, or `--rwdisk`)
-   no network (set with `--host_ip`, `--netmask`, and `--mac`)
-   virtio wayland support if `XDG_RUNTIME_DIR` enviroment variable is set
    (disable with `--no-wl`)
-   only the kernel arguments necessary to run with the supported devices (add
    more with `-p`)
-   run in multiprocess mode (run in single process mode with
    `--disable-sandbox`)
-   no control socket (set with `-s`)

## System Requirements

A Linux kernel with KVM support (check for `/dev/kvm`) is required to run
crosvm. In order to run certain devices, there are additional system
requirements:

-   `virtio-wayland` - The `memfd_create` syscall, introduced in Linux 3.17, and
    a Wayland compositor.
-   `vsock` - Host Linux kernel with vhost-vsock support, introduced in Linux
    4.8.
-   `multiprocess` - Host Linux kernel with seccomp-bpf and Linux namespacing
    support.
-   `virtio-net` - Host Linux kernel with TUN/TAP support (check for
    `/dev/net/tun`) and running with `CAP_NET_ADMIN` privileges.

## Emulated Devices

| Device           | Description                                                                        |
| ---------------- | ---------------------------------------------------------------------------------- |
| `CMOS/RTC`       | Used to get the current calendar time.                                             |
| `i8042`          | Used by the guest kernel to exit crosvm.                                           |
| `serial`         | x86 I/O port driven serial devices that print to stdout and take input from stdin. |
| `virtio-block`   | Basic read/write block device.                                                     |
| `virtio-net`     | Device to interface the host and guest networks.                                   |
| `virtio-rng`     | Entropy source used to seed guest OS's entropy pool.                               |
| `virtio-vsock`   | Enabled VSOCKs for the guests.                                                     |
| `virtio-wayland` | Allowed guest to use host Wayland socket.                                          |

## Contributing

### Code Health

#### `rustfmt`

All code should be formatted with `rustfmt`. We have a script that applies
rustfmt to all Rust code in the crosvm repo: please run `bin/fmt` before
checking in a change. This is different from `cargo fmt --all` which formats
multiple crates but a single workspace only; crosvm consists of multiple
workspaces.

#### `clippy`

The `clippy` linter is used to check for common Rust problems. The crosvm
project uses a specific set of `clippy` checks; please run `bin/clippy` before
checking in a change.

#### Dependencies

ChromeOS and Android both have a review process for third party dependencies to
ensure that code included in the product is safe. Since crosvm needs to build on
both, this means we are restricted in our usage of third party crates. When in
doubt, do not add new dependencies.

### Code Overview

The crosvm source code is written in Rust and C. To build, crosvm generally
requires the most recent stable version of rustc.

Source code is organized into crates, each with their own unit tests. These
crates are:

-   `crosvm` - The top-level binary front-end for using crosvm.
-   `devices` - Virtual devices exposed to the guest OS.
-   `kernel_loader` - Loads elf64 kernel files to a slice of memory.
-   `kvm_sys` - Low-level (mostly) auto-generated structures and constants for
    using KVM.
-   `kvm` - Unsafe, low-level wrapper code for using `kvm_sys`.
-   `net_sys` - Low-level (mostly) auto-generated structures and constants for
    creating TUN/TAP devices.
-   `net_util` - Wrapper for creating TUN/TAP devices.
-   `sys_util` - Mostly safe wrappers for small system facilities such as
    `eventfd` or `syslog`.
-   `syscall_defines` - Lists of syscall numbers in each architecture used to
    make syscalls not supported in `libc`.
-   `vhost` - Wrappers for creating vhost based devices.
-   `virtio_sys` - Low-level (mostly) auto-generated structures and constants
    for interfacing with kernel vhost support.
-   `vm_control` - IPC for the VM.
-   `x86_64` - Support code specific to 64 bit intel machines.

The `seccomp` folder contains minijail seccomp policy files for each sandboxed
device. Because some syscalls vary by architecture, the seccomp policies are
split by architecture.
