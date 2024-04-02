# Libvda Rust wrapper

Note: This crate is specific to ChromeOS and requires the native
[libvda](https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/arc/vm/libvda)
library at link time.

Rust wrapper for libvda. This library is used to enable communication with Chrome's GPU process to
perform hardware accelerated decoding and encoding. It is currently in development to be used by
crosvm's virtio-video device.

### Building for the host environment

You can also execute `cargo` directly for faster build and tests. This would be useful when you are
developing this crate. Since this crate depends on libvda.so, you need to install it to host
environment first.

```shell
(chroot)$ sudo emerge chromeos-base/libvda        # Install libvda.so to host.
# Build
(chroot)$ cargo build
# Unit tests
(chroot)$ cargo test
```

## Updating generated bindings

`src/bindings.rs` is automatically generated from `libvda_common.h`. `src/decode/bindings.rs` is
automatically generated from `libvda_decode.h`. `src/encode/bindings.rs` is automatically generated
from `libvda_encode.h`.

See the header of the bindings file for the generation command.
