# Input

crosvm supports
[virtio-input](https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-3850008)
devices that provide human input devices like multi-touch devices, trackpads, keyboards, and mice.

Events may be sent to the input device via a socket carrying `virtio_input_event` structures. On
Unix-like platforms, this socket must be a UNIX domain socket in stream mode (`AF_UNIX`/`AF_LOCAL`,
`SOCK_STREAM`). Typically this will be created by a separate program that listens and accepts a
connection on this socket and sends the desired events.

On Linux, it is also possible to grab an `evdev` device and forward its events to the guest.

The general syntax of the input option is as follows:

```
--input DEVICE-TYPE[KEY=VALUE,KEY=VALUE,...]
```

For example, to create a 1920x1080 multi-touch device reading data from `/tmp/multi-touch-socket`:

```sh
crosvm run \
  ...
  --input multi-touch[path=/tmp/multi-touch-socket,width=1920,height=1080]
  ...
```

The available device types and their specific options are listed below.

## Input device types

### Evdev

Linux only.

Passes an [event device](https://docs.kernel.org/input/input.html#evdev) node into the VM. The
device will be grabbed (unusable from the host) and made available to the guest with the same
configuration it shows on the host.

Options:

- `path` (required): path to `evdev` device, e.g. `/dev/input/event0`

Example:

```sh
crosvm run \
  --input evdev[path=/dev/input/event0] \
  ...
```

### Keyboard

Add a keyboard virtio-input device.

Options:

- `path` (required): path to event source socket

Example:

```sh
crosvm run \
  --input keyboard[path=/tmp/keyboard-socket] \
  ...
```

### Mouse

Add a mouse virtio-input device.

Options:

- `path` (required): path to event source socket

Example:

```sh
crosvm run \
  --input mouse[path=/tmp/mouse-socket] \
  ...
```

### Multi-Touch

Add a multi-touch touchscreen virtio-input device.

Options:

- `path` (required): path to event source socket
- `width` (optional): width of the touchscreen in pixels (default: 1280)
- `height` (optional): height of the touchscreen in pixels (default: 1024)
- `name` (optional): device name string

If `width` and `height` are not specified, the first multi-touch input device is sized to match the
GPU display size, if specified.

Example:

```sh
crosvm run \
  ...
  --input multi-touch[path=/tmp/multi-touch-socket,width=1920,height=1080,name=mytouch2]
  ...
```

### Rotary

Add a rotating side button/wheel virtio-input device.

Options:

- `path` (required): path to event source socket

Example:

```sh
crosvm run \
  --input rotary[path=/tmp/rotary-socket] \
  ...
```

### Single-Touch

Add a single-touch touchscreen virtio-input device.

Options:

- `path` (required): path to event source socket
- `width` (optional): width of the touchscreen in pixels (default: 1280)
- `height` (optional): height of the touchscreen in pixels (default: 1024)
- `name` (optional): device name string

If `width` and `height` are not specified, the first single-touch input device is sized to match the
GPU display size, if specified.

Example:

```sh
crosvm run \
  ...
  --input single-touch[path=/tmp/single-touch-socket,width=1920,height=1080,name=mytouch1]
  ...
```

### Switches

Add a switches virtio-input device. Switches are often used for accessibility, such as with the
Android [Switch Access](https://support.google.com/accessibility/android/topic/6151780) feature.

Options:

- `path` (required): path to event source socket

Example:

```sh
crosvm run \
  --input switches[path=/tmp/switches-socket] \
  ...
```

### Trackpad

Add a trackpad virtio-input device.

Options:

- `path` (required): path to event source socket
- `width` (optional): width of the touchscreen in pixels (default: 1280)
- `height` (optional): height of the touchscreen in pixels (default: 1024)
- `name` (optional): device name string

Example:

```sh
crosvm run \
  ...
  --input trackpad[path=/tmp/trackpad-socket,width=1920,height=1080,name=mytouch1]
  ...
```
