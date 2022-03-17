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
crosvm run -r "${ROOT_IMAGE}" "${KERNEL_PATH}"
```

The root image must be a path to a disk image formatted in a way that the kernel can read. Typically
this is a squashfs image made with `mksquashfs` or an ext4 image made with `mkfs.ext4`. By using the
`-r` argument, the kernel is automatically told to use that image as the root, and therefore can
only be given once. More disks can be given with `-d` or `--rwdisk` if a writable disk is desired.

To run crosvm with a writable rootfs:

> **WARNING:** Writable disks are at risk of corruption by a malicious or malfunctioning guest OS.

```sh
crosvm run --rwdisk "${ROOT_IMAGE}" -p "root=/dev/vda" vmlinux
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

## Network device

The most convenient way to provide a network device to a guest is to setup a persistent TAP
interface on the host. This section will explain how to do this for basic IPv4 connectivity.

```sh
sudo ip tuntap add mode tap user $USER vnet_hdr crosvm_tap
sudo ip addr add 192.168.10.1/24 dev crosvm_tap
sudo ip link set crosvm_tap up
```

These commands create a TAP interface named `crosvm_tap` that is accessible to the current user,
configure the host to use the IP address `192.168.10.1`, and bring the interface up.

The next step is to make sure that traffic from/to this interface is properly routed:

```sh
sudo sysctl net.ipv4.ip_forward=1
# Network interface used to connect to the internet.
HOST_DEV=$(ip route get 8.8.8.8 | awk -- '{printf $5}')
sudo iptables -t nat -A POSTROUTING -o "${HOST_DEV}" -j MASQUERADE
sudo iptables -A FORWARD -i "${HOST_DEV}" -o crosvm_tap -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i crosvm_tap -o "${HOST_DEV}" -j ACCEPT
```

The interface is now configured and can be used by crosvm:

```sh
crosvm run \
  ...
  --tap-name crosvm_tap \
  ...
```

Provided the guest kernel had support for `VIRTIO_NET`, the network device should be visible and
configurable from the guest:

```sh
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
will run in a jailed child process of crosvm. The appropriate minijail seccomp policy files must be
present either in `/usr/share/policy/crosvm` or in the path specified by the `--seccomp-policy-dir`
argument. The sandbox can be disabled for testing with the `--disable-sandbox` option.

## Wayland forwarding to host

If you have a Wayland compositor running on your host, it is possible to display and control guest
applications from it. This requires:

- A guest kernel version 5.16 or above with `CONFIG_DRM_VIRTIO_GPU` enabled,
- The `sommelier` Wayland proxy in your guest image.

This section will walk you through the steps needed to get this to work.

### Guest kernel requirements

Wayland support on crosvm relies on virtio-gpu contexts, which have been introduced in Linux 5.16.
Make sure your guest kernel is either this version or a more recent one, and that
`CONFIG_DRM_VIRTIO_GPU` is enabled in your kernel configuration.

### Crosvm requirements

Wayland forwarding requires the GPU feature and any non-2d virtio-gpu mode to be enabled, so pass
them to your `cargo build` or `cargo run` command, e.g:

```sh
cargo build --features "gpu,virgl_renderer,virgl_renderer_next"
```

### Building sommelier

[Sommelier] is a proxy Wayland compositor that forwards the Wayland protocol from a guest to a
compositor running on the host through the guest GPU device. As it is not a standard tool, we will
have to build it by ourselves. It is recommended to do this from the guest
[with networking enabled](./example_usage.md#add-networking-support).

Clone Chrome OS' `platform2` repository, which contains the source for sommelier:

```sh
git clone https://chromium.googlesource.com/chromiumos/platform2
```

Go into the sommelier directory and prepare for building:

```sh
cd platform2/vm_tools/sommelier/
meson setup build -Dwith_tests=false
```

This setup step will check for all libraries required to build sommelier. If some are missing,
install them using your guest's distro package manager and re-run `meson setup` until it passes.

Finally, build sommelier and install it:

```sh
meson compile -C build
sudo meson install -C build
```

This last step will put the `sommelier` binary into `/usr/local/bin`.

### Running guest Wayland apps

Crosvm can connect to a running Wayland server (e.g. [weston]) on the host and forward the protocol
from all Wayland guest applications to it. To enable this you need to know the socket of the Wayland
server running on your host - typically it would be `$XDG_RUNTIME_DIR/wayland-0`.

Once you have confirmed the socket, create a GPU device and enable forwarding by adding the
`--gpu --wayland-sock $XDG_RUNTIME_DIR/wayland-0` arguments to your crosvm command-line.

You can now run Wayland clients through sommelier, e.g:

```sh
sommelier --virtgpu-channel weston-terminal
```

Or

```sh
sommelier --virtgpu-channel gedit
```

Applications started that way should appear on and be controllable from the Wayland server running
on your host.

The `--virtgpu-channel` option is currently necessary for sommelier to work with the setup of this
document, but will likely not be required in the future.

If you have `Xwayland` installed in the guest you can also run X applications:

```sh
sommelier -X --xwayland-path=/usr/bin/Xwayland xeyes
```

## GDB Support

crosvm supports [GDB Remote Serial Protocol] to allow developers to debug guest kernel via GDB.

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
- no block devices (set with `-r`, `-d`, or `--rwdisk`)
- no network (set with `--host_ip`, `--netmask`, and `--mac`)
- only the kernel arguments necessary to run with the supported devices (add more with `-p`)
- run in multiprocess mode (run in single process mode with `--disable-sandbox`)
- no control socket (set with `-s`)

[gdb remote serial protocol]: https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html
[kernel documentation]: https://www.kernel.org/doc/html/latest/dev-tools/gdb-kernel-debugging.html
[sommelier]: https://chromium.googlesource.com/chromiumos/platform2/+/master/vm_tools/sommelier
[weston]: https://github.com/wayland-project/weston
