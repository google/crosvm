# crosvm

![crosvm logo](./logo/logo_120.png)

**The ChromeOS Virtual Machine Monitor**

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-crosvm.dev-blue)](https://crosvm.dev/book/)
[![Matrix](https://img.shields.io/matrix/crosvm:matrix.org)](https://matrix.to/#/#crosvm:matrix.org)

______________________________________________________________________

**crosvm** is a secure, lightweight, and performant Virtual Machine Monitor (VMM) written in Rust.
Originally developed for ChromeOS to run Linux ([Crostini](https://chromeos.dev/en/linux)) and
Android guests (ARCVM). It is now used across multiple products and platforms such as
[TerminalApp](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/Virtualization/android/TerminalApp/)
on Android, [Cuttlefish](https://github.com/google/android-cuttlefish), Windows and macOS.

crosvm focuses on security through strong isolation and a modern, memory-safe implementation. It
leverages hardware-assisted virtualization to provide a robust execution environment for untrusted
code.

## 🌟 Core Philosophy

- **Security First**: Built with Rust's memory safety guarantees. Each virtual device can be run in
  its own sandboxed process with restricted system access.
- **Isolation**: Uses Linux namespaces, seccomp filters, and Minijail to create a multi-layered
  security boundary.
- **Performance**: Optimized for modern workloads with features like `io_uring`, `vhost`, and an
  internal async runtime (`cros_async`).
- **Portability**: Supports multiple CPU architectures and hypervisor backends.

## 🛠️ Technical Specifications

### Supported Architectures

- **x86_64**
- **aarch64**
- **riscv64**

### Supported Hypervisors

- **Linux/Android**: KVM, Gunyah (Qualcomm), GenieZone (MediaTek), Halla (Exynos).
- **Windows**: WHPX (Windows Hypervisor Platform), HAXM (Intel).
- **macOS**: HVF (Apple's Hypervisor.framework).

### Virtio Device Support

crosvm implements a wide range of paravirtualized devices via the **virtio** standard:

- **Network**: `virtio-net` with optional vhost and slirp backends.
- **Storage**: `virtio-block` supporting raw, qcow2, zstd, and Android sparse formats.
- **Graphics**: `virtio-gpu` with 2D and 3D acceleration (via `virglrenderer`, `gfxstream`, or
  `vulkano`).
- **Display/Input**: Integrated virtio gpu cross domain support for wayland passthrough
- **Audio**: `virtio-snd` with backends for CRAS (ChromeOS), AAudio (Android), and more.
- **File System**: `virtio-fs` and `virtio-9p`.
- **Other**: Console, RNG, Balloon, Vsock, TPM, Pmem, Video Decoder/Encoder, etc.

## 🔒 Security Architecture

crosvm is designed with a "process-per-device" model:

1. **Main Process**: Handles VM initialization and core orchestration.
1. **Device Processes**: Each virtio device can be `fork`ed into its own process.
1. **Sandboxing**: Each device process is jailed using
   **[Minijail](https://github.com/google/minijail)**:
   - **Namespaces**: VFS (pivot_root), PID, User, and Network isolation.
   - **Seccomp**: Strict BPF filters restrict syscalls to only those required by the specific
     device.
   - **Capabilities**: All unnecessary Linux capabilities are dropped.

## 📖 Documentation

- **[User Guide & Documentation](https://crosvm.dev/book/)**: Comprehensive guide for users and
  developers.
- **[Architecture Deep Dive](./ARCHITECTURE.md)**: Details on the internal design and communication
  framework.
- **[API Documentation](https://crosvm.dev/doc/crosvm/)**: Auto-generated Rust API docs, useful for
  searching internal types and functions.
- **[Source Code](https://chromium.googlesource.com/crosvm/crosvm/)**: The authoritative Chromium
  Git repository.
- **[Contributor Guide](https://crosvm.dev/book/contributing/)**: Workflow and coding standards.
  - Note that the GitHub repository is a read-only mirror. All contributions are submitted via
    [Chromium Gerrit](https://chromium-review.googlesource.com/).

## 🚀 Getting Started

The recommended way to build and develop crosvm is using the provided development container.

### Prerequisites

- **Linux**: A modern kernel (5.x+) with KVM access.
- **Podman or Docker**: Installed and configured.

### Building

Use the dev container to build a release version of crosvm:

```bash
./tools/dev_container ./tools/build_release
```

### Basic Usage

Follow this [example usage](https://crosvm.dev/book/running_crosvm/example_usage.html) to run a
simple Linux guest.

## 🤝 Community & Support

- **[Announcements](https://groups.google.com/a/chromium.org/g/crosvm-announce)**: Join to watch for
  announcements
- **[Matrix Chat](https://matrix.to/#/#crosvm:matrix.org)**: Join the `#crosvm` channel on Matrix.
- **[Issue Tracker](https://issuetracker.google.com/issues?q=status:open%20componentid:1161302)**:
  Report bugs or request features.
  - For Googlers: See [go/crosvm#filing-bugs](https://goto.google.com/crosvm#filing-bugs).
- **[Mailing List](https://groups.google.com/a/chromium.org/g/crosvm-dev)**: Developer discussions.

______________________________________________________________________

crosvm is an open-source project licensed under the [BSD-3-Clause License](LICENSE).
