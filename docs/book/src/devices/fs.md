# Fs

Crosvm supports
[virtio-fs](https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-45800011),
a shared file system that lets virtual machines access a directory tree on the host. It allows the
guest to access files on the host machine. This section will explain how to create a shared
directory. You can also find a runnable sample in `tools/examples/example_fs`.

## Creating a Shared Directory on the Host Machine

To create a shared directory, run the following commands in the host machine:

```sh
mkdir host_shared_dir
HOST_SHARED_DIR=$(pwd)/host_shared_dir
crosvm run \
   --shared-dir "$HOST_SHARED_DIR:my_shared_tag:type=fs" \
  ... # usual crosvm args
```

In the `--shared-dir` argument:

- The first field is the directory to be shared (`$HOST_SHARED_DIR` in this example).
- The second field is the tag that the VM will use to identify the device (`my_shared_tag` in this
  example).
- The remaining fields are key-value pairs configuring the shared directory.

To see available options, run `crosvm run --help`.

## Mount the Shared Directory in the Guest OS

Next, switch to the guest OS and run the following commands to set up the shared directory:

```sh
sudo su
mkdir /tmp/guest_shared_dir
mount -t virtiofs my_shared_tag /tmp/guest_shared_dir
```

You can now add files to the shared directory. Any files you put in the `guest_shared_dir` will
appear in the `host_shared_dir` on the host machine, and vice versa.

## Running VirtioFS as root filesystem

It is also possible to boot crosvm directly from a virtio-fs directory, as long as the directory
structure matches that of a valid rootfs. The outcome is similar to running a chroot but inside a
VM.

Running VMs with virtio-fs as root filesystem may not be ideal as performance will not be as good as
running a root disk with virtio-block, but it can be useful to run tests and debug while sharing
files between host and guest.

You can refer to the [advanced usage](../running_crosvm/advanced_usage.md#with-virtiofs) page for
the instructions on how to run virtio-fs as rootfs.
