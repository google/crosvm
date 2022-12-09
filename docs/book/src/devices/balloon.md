# Balloon

crosvm supports
[virtio-balloon](https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2790005)
for managing guest memory.

## How to control the balloon size

When running a VM, specify `VM_SOCKET` with `-s` option. (example: `/run/crosvm.sock`)

```sh
crosvm run \
    -s ${CROSVM_SOCKET} \
    # usual crosvm args
    /path/to/bzImage
```

Then, open another terminal and specify the balloon size in bytes with `crosvm balloon` command.

```sh
crosvm balloon 4096 ${CROSVM_SOCKET}
```

Note: The size of balloon is managed in 4096 bytes units. The specified value will be rounded down
to a multiple of 4096 bytes.

You can confirm the balloon size with `crosvm balloon_stats` command.

```sh
crosvm balloon_stats ${CROSVM_SOCKET}
```
