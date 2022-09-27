# Video (experimental)

The virtio video decoder and encoder devices allow a guest to leverage the host's
hardware-accelerated video decoding and encoding capabilities. The specification ([v3], [v5]) for
these devices is still a work-in-progress, so testing them requires an out-of-tree kernel driver on
the guest.

The virtio-video host device uses backends to perform the actual decoding. The currently supported
backends are:

- `libvda`, a hardware-accelerated backend that supports both decoding and encoding by delegating
  the work to a running instance of Chrome. It can only be built and used in a Chrome OS
  environment.
- `ffmpeg`, a software-based backend that supports encoding and decoding. It exists to make testing
  and development of virtio-video easier, as it does not require any particular hardware and is
  based on a reliable codec library.

The rest of this document will solely focus on the `ffmpeg` backend. More accelerated backends will
be added in the future.

## Guest kernel requirements

The `virtio_video` branch of this [kernel git repository](https://github.com/Gnurou/linux) contains
a work-in-progress version of the `virtio-video` guest kernel driver, based on a (hopefully) recent
version of mainline Linux. If you use this as your guest kernel, the `virtio_video_defconfig`
configuration should allow you to easily boot from crosvm, with the video (and a few other) virtio
devices support built-in.

Quick building guide after checking out this branch:

```sh
mkdir build_crosvm_x86
make O=build_crosvm_x86 virtio_video_defconfig
make O=build_crosvm_x86 -j16
```

The resulting kernel image that can be passed to `crosvm` will be in
`build_crosvm_x86/arch/x86/boot/compressed/vmlinux.bin`.

## Crosvm requirements

The virtio-video support is experimental and needs to be opted-in through the `"video-decoder"` or
`"video-encoder"` Cargo feature. In the instruction below we'll be using the FFmpeg backend which
requires the `"ffmpeg"` feature to be enabled as well.

The following example builds crosvm with FFmpeg encoder and decoder backend support:

```sh
cargo build --features "video-encoder,video-decoder,ffmpeg"
```

To enable the **decoder** device, start crosvm with the `--video-decoder=ffmpeg` command-line
argument:

```sh
crosvm run --disable-sandbox --video-decoder=ffmpeg -c 4 -m 2048 --rwroot /path/to/disk.img --serial type=stdout,hardware=virtio-console,console=true,stdin=true /path/to/vmlinux.bin
```

Alternatively, to enable the **encoder** device, start crosvm with the `--video-encoder=ffmpeg`
command-line argument:

```sh
crosvm run --disable-sandbox --video-encoder=ffmpeg -c 4 -m 2048 --rwroot /path/to/disk.img --serial type=stdout,hardware=virtio-console,console=true,stdin=true /path/to/vmlinux.bin
```

If the guest kernel includes the virtio-video driver, then the device should be probed and show up.

## Testing the device from the guest

Video capabilities are exposed to the guest using V4L2. The encoder or decoder device should appear
as `/dev/videoX`, probably `/dev/video0` if there are no additional V4L2 devices.

### Checking capabilities and formats

`v4l2-ctl`, part of the `v4l-utils` package, can be used to test the device's existence.

Example output for the decoder is shown below.

```sh
v4l2-ctl -d/dev/video0 --info
Driver Info:
        Driver name      : virtio-video
        Card type        : ffmpeg
        Bus info         : virtio:stateful-decoder
        Driver version   : 5.17.0
        Capabilities     : 0x84204000
                Video Memory-to-Memory Multiplanar
                Streaming
                Extended Pix Format
                Device Capabilities
        Device Caps      : 0x04204000
                Video Memory-to-Memory Multiplanar
                Streaming
                Extended Pix Format
```

Note that the `Card type` is `ffmpeg`, indicating that decoding will be performed in software on the
host. We can then query the support input (`OUTPUT` in V4L2-speak) formats, i.e. the encoded formats
we can send to the decoder:

```sh
v4l2-ctl -d/dev/video0 --list-formats-out
ioctl: VIDIOC_ENUM_FMT
        Type: Video Output Multiplanar

        [0]: 'VP90' (VP9, compressed)
        [1]: 'VP80' (VP8, compressed)
        [2]: 'HEVC' (HEVC, compressed)
        [3]: 'H264' (H.264, compressed)
```

Similarly, you can check the supported output (or CAPTURE) pixel formats for decoded frames:

```sh
v4l2-ctl -d/dev/video0 --list-formats
ioctl: VIDIOC_ENUM_FMT
        Type: Video Capture Multiplanar

        [0]: 'NV12' (Y/CbCr 4:2:0)
```

### Test decoding with ffmpeg

[FFmpeg](https://ffmpeg.org/) can be used to decode video streams with the virtio-video device.

Simple VP8 stream:

```sh
wget https://github.com/chromium/chromium/raw/main/media/test/data/test-25fps.vp8
ffmpeg -codec:v vp8_v4l2m2m -i test-25fps.vp8 test-25fps-%d.png
```

This should create 250 PNG files each containing a decoded frame from the stream.

WEBM VP9 stream:

```sh
wget https://test-videos.co.uk/vids/bigbuckbunny/webm/vp9/720/Big_Buck_Bunny_720_10s_1MB.webm
ffmpeg -codec:v vp9_v4l2m2m -i Big_Buck_Bunny_720_10s_1MB.webm Big_Buck_Bunny-%d.png
```

Should create 300 PNG files at 720p resolution.

### Test decoding with v4l2r

The [v4l2r](https://github.com/Gnurou/v4l2r) Rust crate also features an example program that can
use this driver to decode simple H.264 streams:

```sh
git clone https://github.com/Gnurou/v4l2r
cd v4l2r
wget https://github.com/chromium/chromium/raw/main/media/test/data/test-25fps.h264
cargo run --example simple_decoder test-25fps.h264 /dev/video0 --input_format h264 --save test-25fps.nv12
```

This will decode `test-25fps.h264` and write the raw decoded frames in `NV12` format into
`test-25fps.nv12`. You can check the result with e.g. [YUView](https://github.com/IENT/YUView).

### Test encoding with ffmpeg

[FFmpeg](https://ffmpeg.org/) can be used to encode video streams with the virtio-video device.

The following examples generates a test clip through libavfilter and encode it using the virtual
H.264, H.265 and VP8 encoder, respectively. (VP9 v4l2m2m support is missing in FFmpeg for some
reason.)

```sh
# H264
ffmpeg -f lavfi -i smptebars=duration=10:size=640x480:rate=30 \
  -pix_fmt nv12 -c:v h264_v4l2m2m smptebars.h264.mp4
# H265
ffmpeg -f lavfi -i smptebars=duration=10:size=640x480:rate=30 \
  -pix_fmt yuv420p -c:v hevc_v4l2m2m smptebars.h265.mp4
# VP8
ffmpeg -f lavfi -i smptebars=duration=10:size=640x480:rate=30 \
  -pix_fmt yuv420p -c:v vp8_v4l2m2m smptebars.vp8.webm
```

[v3]: https://markmail.org/message/dmw3pr4fuajvarth
[v5]: https://markmail.org/message/zqxmuf5x7aosbmmm
