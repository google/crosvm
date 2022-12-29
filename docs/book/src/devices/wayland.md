# Wayland

If you have a Wayland compositor running on your host, it is possible to display and control guest
applications from it. This requires:

- A guest kernel version 5.16 or above with `CONFIG_DRM_VIRTIO_GPU` enabled,
- The `sommelier` Wayland proxy in your guest image.

This section will walk you through the steps needed to get this to work.

## Guest kernel requirements

Wayland support on crosvm relies on virtio-gpu contexts, which have been introduced in Linux 5.16.
Make sure your guest kernel is either this version or a more recent one, and that
`CONFIG_DRM_VIRTIO_GPU` is enabled in your kernel configuration.

## Crosvm requirements

Wayland forwarding requires the GPU feature and the virtio-gpu cross domain mode to be enabled.

```
cargo build --features "gpu"
```

## Building sommelier

[Sommelier] is a proxy Wayland compositor that forwards the Wayland protocol from a guest to a
compositor running on the host through the guest GPU device. As it is not a standard tool, we will
have to build it by ourselves. It is recommended to do this from the guest
[with networking enabled](../running_crosvm/example_usage.md#add-networking-support).

Clone ChromeOS' `platform2` repository, which contains the source for sommelier:

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

## Running guest Wayland apps

Crosvm can connect to a running Wayland server (e.g. [weston]) on the host and forward the protocol
from all Wayland guest applications to it. To enable this you need to know the socket of the Wayland
server running on your host - typically it would be `$XDG_RUNTIME_DIR/wayland-0`.

Once you have confirmed the socket, create a GPU device and enable forwarding by adding the
`--gpu=context-types=cross-domain --wayland-sock $XDG_RUNTIME_DIR/wayland-0` arguments to your
crosvm command-line. Other context types may be also enabled for those interested in 3D
acceleration.

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

[sommelier]: https://chromium.googlesource.com/chromiumos/platform2/+/master/vm_tools/sommelier
[weston]: https://github.com/wayland-project/weston
