# Pmem

crosvm supports `virtio-pmem` to provide a virtual device emulating a byte-addressable persistent
memory device. The disk image is provided to the guest using a memory-mapped view of the image file,
and this mapping can be directly mapped into the guest's address space if the guest operating system
and filesystem support [DAX](https://www.kernel.org/doc/html/latest/filesystems/dax.html).

Pmem devices may be added to crosvm using the `--pmem` flag, specifying the filename of the backing
image as the parameter. By default, the pmem device will be writable; add `ro=true` to create a
read-only pmem device instead.

```sh
crosvm run \
  --pmem disk.img \
  ... # usual crosvm args
```

The Linux virtio-pmem driver can be enabled with the `CONFIG_VIRTIO_PMEM` option. It will expose
pmem devices as `/dev/pmem0`, `/dev/pmem1`, etc., which may be mounted like any other block device.
A pmem device may also be used as the root filesystem by adding `root=true` to the `--pmem` flag:

```sh
crosvm run \
  --pmem rootfs.img,root=true,ro=true \
  ... # usual crosvm args
```

The advantage of pmem over a regular block device is the potential for less cache duplication; since
the guest can directly map pages of the pmem device, it does not need to perform an extra copy into
the guest page cache. This can result in lower memory overhead versus `virtio-block` (when not using
`O_DIRECT`).

The file backing a persistent memory device is mapped directly into the guest's address space, which
means that only the raw disk image format is supported; disk images in qcow2 or other formats may
not be used as a pmem device. See the [`block`](block.md) device for an alternative that supports
more file formats.
