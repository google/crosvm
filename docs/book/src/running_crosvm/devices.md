# Devices

This document lists emulated devices in crosvm.

## Emulated Devices

-   [`CMOS/RTC`] - Used to get the current calendar time.
-   [`i8042`] - Used by the guest kernel to exit crosvm.
-   [`serial`] - x86 I/O port driven serial devices that print to stdout and
    take input from stdin.

[`cmos/rtc`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/cmos.rs
[`i8042`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/i8042.rs
[`serial`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/serial.rs

## VirtIO Devices

-   [`balloon`] - Allows the host to reclaim the guest's memories.
-   [`block`] - Basic read/write block device.
-   [`console`] - Input and outputs on console.
-   [`fs`] - Shares file systems over the FUSE protocol.
-   [`gpu`] - Graphics adapter.
-   [`input`] - Creates virtual human interface devices such as keyboards.
-   [`iommu`] - Emulates an IOMMU device to manage DMA from endpoints in the
    guest.
-   [`net`] - Device to interface the host and guest networks.
-   [`p9`] - Shares file systems over the 9P protocol.
-   [`pmem`] - Persistent memory.
-   [`rng`] - Entropy source used to seed guest OS's entropy pool.
-   [`snd`] - Encodes and decodes audio streams.
-   [`tpm`] - Creates a TPM (Trusted Platform Module) device backed by libtpm2
    simulator.
-   [`video`] - Encodes and decodes video streams.
-   [`wayland`] - Allows the guest to use the host's Wayland socket.
-   [`vsock`] - Enables use of virtual sockets for the guest.
-   `vhost-user` - VirtIO devices which offloads the device implementation to
    another process through the [vhost-user protocol].
    -   [vmm side]: Shares its virtqueues.
    -   [device side]: Consumes virtqueues.

[`balloon`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/balloon.rs
[`block`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/block/
[`console`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/console.rs
[`fs`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/fs/
[`gpu`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/gpu/
[`input`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/input/
[`iommu`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/iommu.rs
[`net`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/net.rs
[`p9`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/p9.rs
[`pmem`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/pmem.rs
[`rng`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/rng.rs
[`snd`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/snd/
[`tpm`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/tpm.rs
[`video`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/video/
[`wayland`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/wl.rs
[`vsock`]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/vhost/vsock.rs
[vhost-user protocol]:
  https://qemu.readthedocs.io/en/latest/interop/vhost-user.html
[vmm side]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/vhost/user/vmm/
[device side]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/devices/src/virtio/vhost/user/device/
