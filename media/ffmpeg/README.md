# FFmpeg wrapper

This is a minimal FFmpeg 5.0 wrapper for use with the virtio-video device, allowing to run a virtual
video device backed by software decoding or encoding. This is useful for development and testing in
situations where no supported video acceleration is available on the host.

Although several FFmpeg binding crates exist, most of them are not able to link against the system
FFmpeg, and [the only one that does](https://crates.io/crates/ffmpeg-sys) is released under a
software license that makes our lawyers nervous. Also they all run bindgen at build time, which is
not possible to do under the ChromeOS build system and would require to patch the crate with fully
generated bindings.

So taking this in consideration, as well as the extra work that it is to depend on external Rust
crates in ChromeOS, it is preferable to add our own simple bindings here that cover just the parts
of FFmpeg that we need.

This crate has minimal dependencies ; on the FFmpeg side, it just uses `libavcodec`, `libavutil` and
`libswscale`.

The bindings can be updated using the `bindgen.sh` script. A few elements that bindgen cannot
generate because they are behind C macros are re-defined in `avutil.rs` and `error.rs`, as well as
tests to ensure their correctness.

And that's about it.
