# Block

crosvm supports
[virtio-block](https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2390002)
device that works as a disk for the guest.

First, create a ext4 (or whatever file system you want) disk file.

```sh
fallocate -l 1G disk.img
mkfs.ext4 disk.img
```

Then, pass it with `--rwdisk` flag so the disk will be exposed as `/dev/vda`, `/dev/vdb`, etc. The
device can be mounted with the `mount` command.

```sh
crosvm run \
  --rwdisk disk.img
  ... # usual crosvm args
```

To expose the block device as a read-only disk, you can use `--disk` instead of `--rwdisk`.

## Rootfs

If you use a block device as guest's rootfs, you can specify `--root` (for a read-only disk) or
`--rwroot` (for writable disk). See `crosvm run --help` for the detailed usage.
