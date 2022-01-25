# Advanced Usage

To see the usage information for your version of crosvm, run `crosvm` or `crosvm run --help`.

## Boot a Kernel

To run a very basic VM with just a kernel and default devices:

```bash
$ crosvm run "${KERNEL_PATH}"
```

The uncompressed kernel image, also known as vmlinux, can be found in your kernel build directory in
the case of x86 at `arch/x86/boot/compressed/vmlinux`.

## Rootfs

### With a disk image

In most cases, you will want to give the VM a virtual block device to use as a root file system:

```bash
$ crosvm run -r "${ROOT_IMAGE}" "${KERNEL_PATH}"
```

The root image must be a path to a disk image formatted in a way that the kernel can read. Typically
this is a squashfs image made with `mksquashfs` or an ext4 image made with `mkfs.ext4`. By using the
`-r` argument, the kernel is automatically told to use that image as the root, and therefore can
only be given once. More disks can be given with `-d` or `--rwdisk` if a writable disk is desired.

To run crosvm with a writable rootfs:

> **WARNING:** Writable disks are at risk of corruption by a malicious or malfunctioning guest OS.

```bash
crosvm run --rwdisk "${ROOT_IMAGE}" -p "root=/dev/vda" vmlinux
```

> **NOTE:** If more disks arguments are added prior to the desired rootfs image, the `root=/dev/vda`
> must be adjusted to the appropriate letter.

### With virtiofs

Linux kernel 5.4+ is required for using virtiofs. This is convenient for testing. The file system
must be named "mtd\*" or "ubi\*".

```bash
crosvm run --shared-dir "/:mtdfake:type=fs:cache=always" \
    -p "rootfstype=virtiofs root=mtdfake" vmlinux
```

## Network device

The most convenient way to provide a network device to a guest is to setup a persistent TAP
interface on the host. This section will explain how to do this for basic IPv4 connectivity.

```bash
sudo ip tuntap add mode tap user $USER vnet_hdr crosvm_tap
sudo ip addr add 192.168.10.1/24 dev crosvm_tap
sudo ip link set crosvm_tap up
```

These commands create a TAP interface named `crosvm_tap` that is accessible to the current user,
configure the host to use the IP address `192.168.10.1`, and bring the interface up.

The next step is to make sure that traffic from/to this interface is properly routed:

```bash
sudo sysctl net.ipv4.ip_forward=1
# Network interface used to connect to the internet.
HOST_DEV=$(ip route get 8.8.8.8 | awk -- '{printf $5}')
sudo iptables -t nat -A POSTROUTING -o "${HOST_DEV}" -j MASQUERADE
sudo iptables -A FORWARD -i "${HOST_DEV}" -o crosvm_tap -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i crosvm_tap -o "${HOST_DEV}" -j ACCEPT
```

The interface is now configured and can be used by crosvm:

```bash
crosvm run \
  ...
  --tap-name crosvm_tap \
  ...
```

Provided the guest kernel had support for `VIRTIO_NET`, the network device should be visible and
configurable from the guest:

```bash
# Replace with the actual network interface name of the guest
# (use "ip addr" to list the interfaces)
GUEST_DEV=enp0s5
sudo ip addr add 192.168.10.2/24 dev "${GUEST_DEV}"
sudo ip link set "${GUEST_DEV}" up
sudo ip route add default via 192.168.10.1
# "8.8.8.8" is chosen arbitrarily as a default, please replace with your local (or preferred global)
# DNS provider, which should be visible in `/etc/resolv.conf` on the host.
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

These commands assign IP address `192.168.10.2` to the guest, activate the interface, and route all
network traffic to the host. The last line also ensures DNS will work.

Please refer to your distribution's documentation for instructions on how to make these settings
persistent for the host and guest if desired.

## Control Socket

If the control socket was enabled with `-s`, the main process can be controlled while crosvm is
running. To tell crosvm to stop and exit, for example:

> **NOTE:** If the socket path given is for a directory, a socket name underneath that path will be
> generated based on crosvm's PID.

```bash
$ crosvm run -s /run/crosvm.sock ${USUAL_CROSVM_ARGS}
    <in another shell>
$ crosvm stop /run/crosvm.sock
```

> **WARNING:** The guest OS will not be notified or gracefully shutdown.

This will cause the original crosvm process to exit in an orderly fashion, allowing it to clean up
any OS resources that might have stuck around if crosvm were terminated early.

## Multiprocess Mode

By default crosvm runs in multiprocess mode. Each device that supports running inside of a sandbox
will run in a jailed child process of crosvm. The appropriate minijail seccomp policy files must be
present either in `/usr/share/policy/crosvm` or in the path specified by the `--seccomp-policy-dir`
argument. The sandbox can be disabled for testing with the `--disable-sandbox` option.

## Virtio Wayland

Virtio Wayland support requires special support on the part of the guest and as such is unlikely to
work out of the box unless you are using a Chrome OS kernel along with a `termina` rootfs.

To use it, ensure that the `XDG_RUNTIME_DIR` enviroment variable is set and that the path
`$XDG_RUNTIME_DIR/wayland-0` points to the socket of the Wayland compositor you would like the guest
to use.

## GDB Support

crosvm supports [GDB Remote Serial Protocol] to allow developers to debug guest kernel via GDB.

You can enable the feature by `--gdb` flag:

```sh
# Use uncompressed vmlinux
$ crosvm run --gdb <port> ${USUAL_CROSVM_ARGS} vmlinux
```

Then, you can start GDB in another shell.

```sh
$ gdb vmlinux
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
- no block devices (set with `-r`, `-d`, or `--rwdisk`)
- no network (set with `--host_ip`, `--netmask`, and `--mac`)
- virtio wayland support if `XDG_RUNTIME_DIR` enviroment variable is set (disable with `--no-wl`)
- only the kernel arguments necessary to run with the supported devices (add more with `-p`)
- run in multiprocess mode (run in single process mode with `--disable-sandbox`)
- no control socket (set with `-s`)

[gdb remote serial protocol]: https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html
[kernel documentation]: https://www.kernel.org/doc/html/latest/dev-tools/gdb-kernel-debugging.html
