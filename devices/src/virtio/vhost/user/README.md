# Vhost-user devices

This directory contains the implementation of [vhost-user] devices.

## Code Locations

- [`vmm`](./vmm/) - Implements vhost-user vmm device; i.e. vhost-user master.
- [`device`](./device/) - Implements vhost-user device backend; i.e. vhost-user slave.

## Usage

### Vhost-user

First, start a vhost-user device with the `crosvm devices` command. Here we use the block device as
an example, but the basic usage is same for all of devices.

```bash
$ crosvm devices --block vhost=/path/to/socket,path=/path/to/block.img
```

Then start a VM with a vhost-user block device by specifying the same socket path.

```bash
$ crosvm run -r rootfs.img --vhost-user block,socket=/path/to/socket <crosvm arguments>
```

[vhost-user]: https://qemu.readthedocs.io/en/latest/interop/vhost-user.html
