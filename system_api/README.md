# Crosvm version of ChromeOS's system_api

system_api is used by ChromeOS to interact with other system services and mainly contains
automatically generated bindings for dbus services and proto types.

The ground truth for this crate is in the ChromeOS codebase at [platform2/system_api].

To allow us to build ChromeOS features in upstream crosvm, we need to copy a subset of the generated
files into this repository. The `update_bindings.sh` script can be used to update them.

Note: Originally, the ChromeOS build would replace this crate with the ChromeOS
[platform2/system_api] crate. This is no longer the case and crosvm will always be built against the
version in this directory.

[platform2/system_api]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/system_api/
