# Fs

Crosvm supports
[virtio-fs](https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-45800011),
a shared file system that lets virtual machines access a directory tree on the host. It allows the
guest to access files on the host machine. This section will explain how to create a shared
directory. You can also find a runnable sample in `tools/examples/example_fs`.

## Creating a Shared Directory on the Host Machine

Run following commands in host machine, to create a shared directory:

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
