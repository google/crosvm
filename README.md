# crosvm - The Chrome OS Virtual Machine Monitor

![Logo](./logo.svg)

crosvm is a virtual machine monitor (VMM) based on Linux’s KVM hypervisor, with
a focus on simplicity, security, and speed. crosvm is intended to run Linux
guests, originally as a security boundary for running native applications on the
Chrome OS platform. Compared to QEMU, crosvm doesn’t emulate architectures or
real hardware, instead concentrating on paravirtualized devices, such as the
virtio standard.

crosvm is currently used to run Linux/Android guests on Chrome OS devices.

*   [Documentation](https://google.github.io/crosvm/)
*   [Source code](https://chromium.googlesource.com/chromiumos/platform/crosvm/)
    *   Also a mirror repository exists at
        [GitHub](https://github.com/google/crosvm), but we don't accept bug
        reports or pull requests there. For contribution, see
        [the contributor guide](https://google.github.io/crosvm/contributing.html).
*   [Issue tracker](https://bugs.chromium.org/p/chromium/issues/list?q=component:OS%3ESystems%3EContainers)
