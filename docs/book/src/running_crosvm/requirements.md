# System Requirements

A Linux kernel with KVM support (check for `/dev/kvm`) is required to run crosvm. In order to run
certain devices, there are additional system requirements:

- `virtio-wayland` - The `memfd_create` syscall, introduced in Linux 3.17, and a Wayland compositor.
- `vsock` - Host Linux kernel with vhost-vsock support, introduced in Linux 4.8.
- `multiprocess` - Host Linux kernel with seccomp-bpf and Linux namespacing support.
- `virtio-net` - Host Linux kernel with TUN/TAP support (check for `/dev/net/tun`) and running with
  `CAP_NET_ADMIN` privileges.
