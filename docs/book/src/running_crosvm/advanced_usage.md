# Advanced Usage

To see the usage information for your version of crosvm, run `crosvm` or `crosvm run --help`.

## Boot a Kernel

To run a very basic VM with just a kernel and default devices:

```sh
crosvm run "${KERNEL_PATH}"
```

The uncompressed kernel image, also known as vmlinux, can be found in your kernel build directory in
the case of x86 at `arch/x86/boot/compressed/vmlinux`.

## Rootfs

### With a disk image

In most cases, you will want to give the VM a virtual block device to use as a root file system:

```sh
crosvm run -b "${ROOT_IMAGE},root,ro" "${KERNEL_PATH}"
```

The root image must be a path to a disk image formatted in a way that the kernel can read. Typically
this is a squashfs image made with `mksquashfs` or an ext4 image made with `mkfs.ext4`. By
specifying the `root` flag, the kernel is automatically told to use that image as the root, and
therefore it can only be given once. The `ro` flag also makes the disk image read-only for the
guest. More disks images can be given with `-b` or `--block` if needed.

To run crosvm with a writable rootfs, just remove the `ro` flag from the command-line above.

> **WARNING:** Writable disks are at risk of corruption by a malicious or malfunctioning guest OS.

Without the `root` flag, mounting a disk image as the root filesystem requires to pass the
corresponding kernel argument manually using the `-p` option:

```sh
crosvm run --block "${ROOT_IMAGE}" -p "root=/dev/vda" vmlinux
```

> **NOTE:** If more disks arguments are added prior to the desired rootfs image, the `root=/dev/vda`
> must be adjusted to the appropriate letter.

### With virtiofs

Linux kernel 5.4+ is required for using virtiofs. This is convenient for testing. The file system
must be named "mtd\*" or "ubi\*".

```sh
crosvm run --shared-dir "/:mtdfake:type=fs:cache=always" \
    -p "rootfstype=virtiofs root=mtdfake" vmlinux
```

## Device emulation

Crosvm supports several emulated devices and 15+ types of virtio devices. See
["Device" chapter](../devices/index.md) for the details.

## Control Socket

If the control socket was enabled with `-s`, the main process can be controlled while crosvm is
running. To tell crosvm to stop and exit, for example:

> **NOTE:** If the socket path given is for a directory, a socket name underneath that path will be
> generated based on crosvm's PID.

```sh
crosvm run -s /run/crosvm.sock ${USUAL_CROSVM_ARGS}
    <in another shell>
crosvm stop /run/crosvm.sock
```

> **WARNING:** The guest OS will not be notified or gracefully shutdown.

This will cause the original crosvm process to exit in an orderly fashion, allowing it to clean up
any OS resources that might have stuck around if crosvm were terminated early.

## Multiprocess Mode

By default crosvm runs in multiprocess mode. Each device that supports running inside of a sandbox
will run in a jailed child process of crosvm. The sandbox can be disabled for testing with the
`--disable-sandbox` option.

## GDB Support

crosvm supports [GDB Remote Serial Protocol] to allow developers to debug guest kernel via GDB
(**x86_64 or AArch64 only**).

You can enable the feature by `--gdb` flag:

```sh
# Use uncompressed vmlinux
crosvm run --gdb <port> ${USUAL_CROSVM_ARGS} vmlinux
```

Then, you can start GDB in another shell.

```sh
gdb vmlinux
(gdb) target remote :<port>
(gdb) hbreak start_kernel
(gdb) c
<start booting in the other shell>
```

For general techniques for debugging the Linux kernel via GDB, see this [kernel documentation].

## Defaults

The following are crosvm's default arguments and how to override them.

- 256MB of memory (set with `-m`)
- 1 virtual CPU (set with `-c`)
- no block devices (set with `-b`, `--block`)
- no network device (set with `--net`)
- only the kernel arguments necessary to run with the supported devices (add more with `-p`)
- run in multiprocess mode (run in single process mode with `--disable-sandbox`)
- no control socket (set with `-s`)

## Exit code

Crosvm will exit with a non-zero exit code on failure.

See [CommandStatus](https://crosvm.dev/doc/crosvm/enum.CommandStatus.html) for meaning of the major
exit codes.

[gdb remote serial protocol]: https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html
[kernel documentation]: https://www.kernel.org/doc/html/latest/dev-tools/gdb-kernel-debugging.html
