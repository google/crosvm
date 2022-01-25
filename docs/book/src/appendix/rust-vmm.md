# Summary

crosvm is open to using rust-vmm modules. However, as of Fall 2020 there has been no progress toward
that goal. Among other areas, differences in host operating system support methods in `sys-util`
make integration challenging . It is possible to overcome this and enable crosvm to use common
modules, but that work is not yet started.

# Background

## VMMs

Soon after crosvm's code was public, Amazon used it as the basis for their own VMM named
Firecracker. After Firecracker came other rust-based VMM implementations, all using parts of crosvm.
In order to drive collaboration and code sharing, an independent organization was created, named
[rust-vmm](https://github.com/rust-vmm).

## Sharing Model

Rust-vmm aims to provide common components consumed by various implementations of VMMs using rust.
This allows for sharing components such as virtio queue parsing while allowing full customization by
individual VMM implementation. The goal is for several VMM projects, Firecracker, Cloud Hypervisor,
and crosvm to use the shared components.

## Future

crosvm and rust-vmm are most alike in the
[kvm-bindings](https://github.com/rust-vmm/kvm-bindings)(limited by crosvm's use of aarch64 bindings
on arm32 hosts), and [vmm-sys-util](https://github.com/rust-vmm/vmm-sys-util)(currently limited by
differences in non-linux OS support strategy). Integrating these two modules would open the gates to
sharing more code with rust-vmm, but that work remains low priority for crosvm.
