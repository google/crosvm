# Block

crosvm supports
[virtio-block](https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2390002)
device that works as a disk for the guest.

First, create a ext4 (or whatever file system you want) disk file.

```sh
fallocate -l 1G disk.img
mkfs.ext4 disk.img
```

Then, pass it with `--block` flag so the disk will be exposed as `/dev/vda`, `/dev/vdb`, etc. The
device can be mounted with the `mount` command.

```sh
crosvm run \
  --block disk.img
  ... # usual crosvm args
```

To expose the block device as a read-only disk, you can add the `ro` flag after the disk image path:

```sh
crosvm run \
  --block disk.img,ro
  ... # usual crosvm args
```

## Rootfs

If you use a block device as guest's rootfs, you can add the `root` flag to the `--block` parameter:

```sh
crosvm run \
  --block disk.img,root
  ... # usual crosvm args
```

This flag automatically adds a `root=/dev/vdX` kernel parameter with the corresponding virtio-block
device name and read-only (`ro`) or read-write (`rw`) option depending on whether the `ro` flag has
also been specified or not.

## Options

The `--block` parameter support additional options to enable features and control disk parameters.
These may be specified as extra comma-separated `key=value` options appended to the required
filename option. For example:

```sh
crosvm run
  --block disk.img,ro,sparse=false,o_direct=true,block_size=4096,id=MYSERIALNO
  ... # usual crosvm args
```

The available options are documented in the following sections.

### Sparse

- Syntax: `sparse=(true|false)`
- Default: `sparse=true`

The `sparse` option controls whether the disk exposes the thin provisioning `discard` command. If
`sparse` is set to `true`, the `VIRTIO_BLK_T_DISCARD` request will be available, and it will be
translated to the appropriate system call on the host disk image file (for example,
`fallocate(FALLOC_FL_PUNCH_HOLE)` for raw disk images on Linux). If `sparse` is set to `false`, the
disk will be fully allocated at startup (using [`fallocate()`] or equivalent on other platforms),
and the `VIRTIO_BLK_T_DISCARD` request will not be supported for this device.

### `O_DIRECT`

- Syntax: `o_direct=(true|false)`
- Default: `o_direct=false`

The `o_direct` option enables the Linux `O_DIRECT` flag on the underlying disk image, indicating
that I/O should be sent directly to the backing storage device rather than using the host page
cache. This should only be used with raw disk images, not qcow2 or other formats. The `block_size`
option may need to be adjusted to ensure that I/O is sufficiently aligned for the host block device
and filesystem requirements.

### Block size

- Syntax: `block_size=BYTES`
- Default: `block_size=512`

The `block_size` option overrides the reported block size (also known as sector size) of the
virtio-block device. This should be a power of two larger than or equal to 512.

### ID

- Syntax: `id=DISK_ID`
- Default: No identifier

The `id` option provides the virtio-block device with a unique identifier. The `DISK_ID` string must
be 20 or fewer ASCII printable characters. The `id` may be used by the guest environment to uniquely
identify a specific block device rather than making assumptions about block device names.

The Linux virtio-block driver exposes the disk identifer in a `sysfs` file named `serial`; an
example path looks like `/sys/devices/pci0000:00/0000:00:02.0/virtio1/block/vda/serial` (the PCI
address may differ depending on which other devices are enabled).

## Resizing

The crosvm block device supports run-time resizing. This can be accomplished by starting crosvm with
the `-s` control socket, then using the `crosvm disk` command to send a resize request:

`crosvm disk resize DISK_INDEX NEW_SIZE VM_SOCKET`

- `DISK_INDEX`: 0-based index of the block device (counting all `--block` in order).
- `NEW_SIZE`: desired size of the disk image in bytes.
- `VM_SOCKET`: path to the VM control socket specified when running crosvm (`-s`/`--socket` option).

For example:

```sh
# Create a 1 GiB disk image
truncate -s 1G disk.img

# Run crosvm with a control socket
crosvm run \
  --block disk.img,sparse=false \
  -s /tmp/crosvm.sock \
  ... # other crosvm args

# In another shell, extend the disk image to 2 GiB.
crosvm disk resize \
  0 \
  $((2 * 1024 * 1024 * 1024)) \
  /tmp/crosvm.sock

# The guest OS should recognize the updated size and log a message:
#   virtio_blk virtio1: [vda] new size: 4194304 512-byte logical blocks (2.15 GB/2.00 GiB)
```

The `crosvm disk resize` command only resizes the block device and its backing disk image. It is the
responsibility of the VM socket user to perform any partition table or filesystem resize operations,
if required.

[`fallocate()`]: https://man7.org/linux/man-pages/man2/fallocate.2.html#DESCRIPTION
