# SCSI (experimental)

crosvm supports
[virtio-scsi](https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-3430006)
devices that work as block devices for the guest.

The step for setting up a block device is similar to the virtio-blk device. After setting up the
block device, pass it with `--scsi-block` flag so the disk will be exposed as `/dev/sda`,
`/dev/sdb`, etc. The device can be mounted with the `mount` command.

```sh
crosvm run \
  --scsi-block disk.img
  ... # usual crosvm args
```

## Flags & Options

The `--scsi-block` parameter supports additional options and flags to enable features and control
disk parameters.

### Read-only

To expose the scsi device as a read-only disk, you can add the `ro` flag after the disk image path:

```sh
crosvm run \
  --scsi-block disk.img,ro
  ... # usual crosvm args
```

### Rootfs

If you use a scsi device as guest's rootfs, you can add the `root` flag to the `--scsi-block`
parameter:

```sh
crosvm run \
  --scsi-block disk.img,root
  ... # usual crosvm args
```

This flag automatically adds a `root=/dev/sdX` kernel parameter with the corresponding virtio-scsi
device name and read-only (`ro`) or read-write (`rw`) option depending on whether the `ro` flag has
also been specified or not.

### Block size

- Syntax: `block_size=BYTES`
- Default: `block_size=512`

The `block_size` option overrides the reported block size (also known as sector size) of the
virtio-scsi device. This should be a power of two larger than or equal to 512.
