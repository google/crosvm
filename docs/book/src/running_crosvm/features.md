# Features

These features can be enabled using cargo's `--features` flag. Refer to the top-level `Cargo.toml`
file to see which features are enabled by default.

## `audio`

Enables experimental audio input/ouput to the host. Requires some ChromeOS specific dependencies and
daemons currently.

## `chromeos`

This option enables features specific to a ChromeOS environment. Examples of that are usage of
non-upstream kernel security features in the ChromeOS kernel, which should be temporary until
upstream catches up. Another example would be code to use ChromeOS system daemons like the low
memory notifier.

These features exist because crosvm was historically a ChromeOS only project, but crosvm is intended
to be OS agnostic now. If ChromeOS specific code is identified, it should be conditionally compiled
in using this feature.

## `composite-disk`

Enables the composite-disk format, which adds protobufs as a dependency of the build. This format is
intended to speed up crosvm's usage in CI environments that might otherwise have to concatenate
large file system images into a single disk image.

## `default-no-sandbox`

This feature is useful only in testing so that the `--disable-sandbox` flag doesn't need to be
passed to crosvm every invocation. It is not secure to deploy crosvm with this flag.

## `direct`

Enables a set of features to passthrough devices to the guest via VFIO.

## `gdb`

Enables using gdb to debug the guest kernel.

## `gfxstream`

Enables 3D acceleration for guest via the `gfxstream` protocol over virtio-gpu. This is used for
compatibility with the Android Emulator. The protocol provides the best speed and compatibility with
GL/vulkan versions by forwarding the guest's calls to the host's graphics libraries and GPU.
However, this means the sandbox is not enabled for the virtio-gpu device.

## `gpu`

Enables basic virtio-gpu support. This includes basic display and input features, but lacks 3D
acceleration in the absence of other crosvm features.

## `plugin`

Enables the plugin mode of crosvm. The plugin mode delegates almost all device emulation to a
sandboxed child process. Unless you know what you're doing, you almost certainly don't need this
feature.

## `power-monitor-powerd`

Enables emulation of a battery using the host's power information provided by
[powerd](https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/README.md).

## `tpm`

Enables trusted platform module emulation for the guest. This relies on the software emulated vTPM
implementation from `libtpm2` which is suited only for testing purposes.

## `usb`

Enables USB host device passthrough via an emulated XHCI controller.

## `video-decoder`/`video-encoder`

Enables the unstable virtio video encoder or decoder devices.

## `virgl_renderer`/`virgl_renderer_next`

Enables 3D acceleration for the guest via the `virglrenderer` library over virtio-gpu. The
`virgl_renderer_next` variant is used to enable in development features of `virglrenderer` to
support newer OpenGL versions.

## `wl`

Enables the non-upstream virtio wayland protocol. This can be used in conjuction with the `gpu`
feature to enable a zero-copy display pipeline.

## `x`

Enables the usage of the X11 protocol for display on the host.
