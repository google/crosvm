# Stub crate for system_api

system_api is used by ChromeOS to interact with other system services.

In ChromeOS builds, the `chromeos` cargo feature is enabled and this crate is replaced with the
actual [system_api] implementation.

On other platforms, the feature flag will remain disabled and this crate is used to satisfy cargo
dependencies on system_api.

[system_api]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/system_api/
