# crosvm - The Chrome OS Virtual Machine Monitor

This component, known as crosvm, runs untrusted operating systems along with
virtualized devices. No actual hardware is emulated. This only runs VMs
through the Linux's KVM interface. What makes crosvm unique is a focus on
safety within the programming language and a sandbox around the virtual
devices to protect the kernel from attack in case of an exploit in the
devices.

## Building with Docker

See the [README](docker/README.md) from the `docker` subdirectory to learn how
to build crosvm in enviroments outside of the Chrome OS chroot.

## Usage

To see the usage information for your version of crosvm, run `crosvm` or `crosvm
run --help`.

### Boot a Kernel

To run a very basic VM with just a kernel and default devices:

```bash
$ crosvm run "${KERNEL_PATH}"
```

The uncompressed kernel image, also known as vmlinux, can be found in your kernel
build directory in the case of x86 at `arch/x86/boot/compressed/vmlinux`.

### Rootfs

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

>**WARNING:** Writable disks are at risk of corruption by a malicious or
malfunctioning guest OS.
```bash
crosvm run --rwdisk "${ROOT_IMAGE}" -p "root=/dev/vda" vmlinux
```
>**NOTE:** If more disks arguments are added prior to the desired rootfs image,
the `root=/dev/vda` must be adjusted to the appropriate letter.

### Control Socket

If the control socket was enabled with `-s`, the main process can be controlled
while crosvm is running. To tell crosvm to stop and exit, for example:

>**NOTE:** If the socket path given is for a directory, a socket name underneath
that path will be generated based on crosvm's PID.
```bash
$ crosvm run -s /run/crosvm.sock ${USUAL_CROSVM_ARGS}
    <in another shell>
$ crosvm stop /run/crosvm.sock
```
>**WARNING:** The guest OS will not be notified or gracefully shutdown.

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

## Defaults

The following are crosvm's default arguments and how to override them.

* 256MB of memory (set with `-m`)
* 1 virtual CPU (set with `-c`)
* no block devices (set with `-r`, `-d`, or `--rwdisk`)
* no network (set with `--host_ip`, `--netmask`, and `--mac`)
* virtio wayland support if `XDG_RUNTIME_DIR` enviroment variable is set (disable with `--no-wl`)
* only the kernel arguments necessary to run with the supported devices (add more with `-p`)
* run in multiprocess mode (run in single process mode with `--disable-sandbox`)
* no control socket (set with `-s`)

## System Requirements

A Linux kernel with KVM support (check for `/dev/kvm`) is required to run
crosvm. In order to run certain devices, there are additional system
requirements:

* `virtio-wayland` - The `memfd_create` syscall, introduced in Linux 3.17, and a Wayland compositor.
* `vsock` - Host Linux kernel with vhost-vsock support, introduced in Linux 4.8.
* `multiprocess` - Host Linux kernel with seccomp-bpf and Linux namespacing support.
* `virtio-net` - Host Linux kernel with TUN/TAP support (check for `/dev/net/tun`) and running with `CAP_NET_ADMIN` privileges.

## Emulated Devices

| Device           | Description                                                                        |
|------------------|------------------------------------------------------------------------------------|
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

#### `build_test`

There are no automated tests run before code is committed to crosvm. In order to
maintain sanity, please execute `build_test` before submitting code for review.
All tests should be passing or ignored and there should be no compiler warnings
or errors. All supported architectures are built, but only tests for x86_64 are
run. In order to build everything without failures, sysroots must be supplied
for each architecture. See `build_test -h` for more information.

#### `rustfmt`

All code should be formatted with `rustfmt`. We have a script that applies
rustfmt to all Rust code in the crosvm repo: please run `bin/fmt` before
checking in a change. This is different from `cargo fmt --all` which formats
multiple crates but a single workspace only; crosvm consists of multiple
workspaces.

#### Dependencies

With a few exceptions, external dependencies inside of the `Cargo.toml` files
are not allowed. The reason being that community made crates tend to explode the
binary size by including dozens of transitive dependencies. All these
dependencies also must be reviewed to ensure their suitability to the crosvm
project. Currently allowed crates are:

* `byteorder` - A very small library used for endian swaps.
* `cc` - Build time dependency needed to build C source code used in crosvm.
* `libc` - Required to use the standard library, this crate is a simple wrapper around `libc`'s symbols.

### Code Overview

The crosvm source code is written in Rust and C. To build, crosvm generally
requires the most recent stable version of rustc.

Source code is organized into crates, each with their own unit tests. These
crates are:

* `crosvm` - The top-level binary front-end for using crosvm.
* `devices` - Virtual devices exposed to the guest OS.
* `io_jail` - Creates jailed process using `libminijail`.
* `kernel_loader` - Loads elf64 kernel files to a slice of memory.
* `kvm_sys` - Low-level (mostly) auto-generated structures and constants for using KVM.
* `kvm` - Unsafe, low-level wrapper code for using `kvm_sys`.
* `net_sys` - Low-level (mostly) auto-generated structures and constants for creating TUN/TAP devices.
* `net_util` - Wrapper for creating TUN/TAP devices.
* `sys_util` - Mostly safe wrappers for small system facilities such as `eventfd` or `syslog`.
* `syscall_defines` - Lists of syscall numbers in each architecture used to make syscalls not supported in `libc`.
* `vhost` - Wrappers for creating vhost based devices.
* `virtio_sys` - Low-level (mostly) auto-generated structures and constants for interfacing with kernel vhost support.
* `vm_control` - IPC for the VM.
* `x86_64` - Support code specific to 64 bit intel machines.

The `seccomp` folder contains minijail seccomp policy files for each sandboxed
device. Because some syscalls vary by architecture, the seccomp policies are
split by architecture.
