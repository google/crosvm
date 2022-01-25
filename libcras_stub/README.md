# Stub crate for libcras

libcras is used by ChromeOS to play audio through the cras server.

In ChromeOS builds, the `audio_cras` cargo feature is enabled and this crate is replaced with the
actual [libcras] implementation.

On other platforms, the feature flag will remain disabled and this crate is used to satisfy cargo
dependencies on libcras.

[libcras]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/third_party/adhd/cras/client/libcras/
