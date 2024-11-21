# Sharing host directory with virtio-pmem

crosvm has an experimental feature to share a host directory with the guest as read-only via
virtio-pmem device.

## How it works

When this feature is enabled, `crosvm` creates a virtual ext2 filesystem in memory. This filesystem
contains the contents of the specified host directory. When creating the file system, `crosvm` do
`mmap` each file instead of data copy. As a result, the actual file data is read from disk only when
it's accessed by the guest.

## Usage

To share a host directory with the guest, you'll need to start `crosvm` with the device enabled, and
mount the device in the guest.

### Host

You can use `--pmem-ext2` flag to enable the device.

```console
$ mkdir host_shared_dir
$ HOST_SHARED_DIR=$(pwd)/host_shared_dir
$ echo "Hello!" > $HOST_SHARED_DIR/test.txt
$ crosvm run \
    --pmem-ext2 "$HOST_SHARED_DIR" \
    # usual crosvm args
```

You can check a full list of parameters for `--pmem-ext2` with `crosvm run --help`.

### Guest

Then, you can mount the ext2 file system from the guest. With `-o dax`, we can avoid duplicated page
caches between the guest and the host.

```console
$ mkdir /tmp/shared
$ mount -t ext2 -o dax /dev/pmem0 /tmp/shared
$ ls /tmp/shared
lost+found  test.txt
$ cat /tmp/shared/test.txt
Hello!
```

## Comparison with other methods

Since access to files provided by this device is through pmem, it is done as a host OS page fault.
This can reduce the number of context switches to the host userspace compared to virtio-blk or
virtio-fs.

This feature is similar to
[the VVFAT (Virtual FAT filesystem)](https://github.com/qemu/qemu/blob/master/block/vvfat.c) device
in QEMU, but our pmem-ext2 uses the ext2 filesystem and supports read-only accesses only.
