# System Requirements

## Linux

A Linux 4.14 or newer kernel with KVM support (check for `/dev/kvm`) is required to run crosvm. In
order to run certain devices, there are additional system requirements:

- `virtio-wayland` - A Wayland compositor.
- `vsock` - Host Linux kernel with vhost-vsock support.
- `multiprocess` - Host Linux kernel with seccomp-bpf and Linux namespacing support.
- `virtio-net` - Host Linux kernel with TUN/TAP support (check for `/dev/net/tun`) and running with
  `CAP_NET_ADMIN` privileges.
