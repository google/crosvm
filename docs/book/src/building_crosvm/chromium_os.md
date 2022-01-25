# Building for ChromeOS

crosvm is included in the ChromeOS source tree at `src/platform/crosvm`. Crosvm can be built with
ChromeOS features using Portage or cargo.

If ChromeOS-specific features are not needed, or you want to run the full test suite of crosvm, the
[Building for Linux](#building-for-linux) workflows can be used from the crosvm repository of
ChromeOS as well.

## Using Portage

crosvm on ChromeOS is usually built with Portage, so it follows the same general workflow as any
`cros_workon` package. The full package name is `chromeos-base/crosvm`.

See the [Chromium OS developer guide] for more on how to build and deploy with Portage.

> NOTE: `cros_workon_make` modifies crosvm's Cargo.toml and Cargo.lock. Please be careful not to
> commit the changes. Moreover, with the changes cargo will fail to build and clippy preupload check
> will fail.

## Using Cargo

Since development using portage can be slow, it's possible to build crosvm for ChromeOS using cargo
for faster iteration times. To do so, the `Cargo.toml` file needs to be updated to point to
dependencies provided by ChromeOS using `./tools/chromeos/setup_cargo`.

[chromium os developer guide]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_guide.md
