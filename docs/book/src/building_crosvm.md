# Building Crosvm

This page describes how to build and develop crosvm on linux. If you are targeting another OS such
as ChromeOS, please see [Integration](integration/index.md)

## Checking out

Obtain the source code via git clone.

```sh
git clone https://chromium.googlesource.com/crosvm/crosvm
```

## Setting up the development environment

Crosvm uses submodules to manage external dependencies. Initialize them via:

```sh
git submodule update --init
```

It is recommended to enable automatic recursive operations to keep the submodules in sync with the
main repository (But do not push them, as that can conflict with `repo`):

```sh
git config submodule.recurse true
git config push.recurseSubmodules no
```

Crosvm development best works on Debian derivatives. First install rust via <https://rustup.rs/>.
Then for the rest, we provide a script to install the necessary packages on Debian:

```sh
./tools/install-deps
```

For other systems, please see below for instructions on
[Using the development container](#using-the-development-container).

### Setting up for cross-compilation

Crosvm is built and tested on x86, aarch64 and armhf. Your host needs to be set up to allow
installation of foreign architecture packages.

On Debian this is as easy as:

```sh
sudo dpkg --add-architecture arm64
sudo dpkg --add-architecture armhf
sudo apt update
```

On ubuntu this is a little harder and needs some
[manual modifications](https://askubuntu.com/questions/430705/how-to-use-apt-get-to-download-multi-arch-library)
of APT sources.

For other systems (**including gLinux**), please see below for instructions on
[Using the development container](#using-the-development-container).

With that enabled, the following scripts will install the needed packages:

```sh
./tools/install-aarch64-deps
./tools/install-armhf-deps
```

### Using the development container

We provide a Debian container with the required packages installed. With
[Docker installed](https://docs.docker.com/get-docker/), it can be started with:

```sh
./tools/dev_container
```

The container image is big and may take a while to download when first used. **Once started, you can
follow all instructions in this document within the container shell.**

Instead of using the interactive shell, commands to execute can be provided directly:

```sh
./tools/dev_container cargo build
```

Note: The container and build artifacts are preserved between calls to `./tools/dev_container`. If
you wish to start fresh, use the `--reset` flag.

## Building a binary

If you simply want to try crosvm, run `cargo build`. Then the binary is generated at
`./target/debug/crosvm`. Now you can move to [Example Usage](running_crosvm/example_usage.md).

If you want to enable [additional features](running_crosvm/features.md), use the `--features` flag.
(e.g. `cargo build --features=gdb`)

## Development

### Iterative development

You can use cargo as usual for crosvm development to `cargo build` and `cargo test` single crates
that you are working on.

If you are working on aarch64 specific code, you can use the `test_target` tool to instruct cargo to
build for aarch64 and run tests on a VM:

```sh
./tools/test_target set vm:aarch64 && source .envrc
cd mycrate && cargo test
```

The script will start a VM for testing and write environment variables for cargo to `.envrc`. With
those `cargo build` will build for aarch64 and `cargo test` will run tests inside the VM.

The aarch64 VM can be managed with the `./tools/aarch64vm` script.

### Running all tests

Crosvm cannot use `cargo test --workspace` because of various restrictions of cargo. So we have our
own test runner:

```sh
./tools/run_tests
```

Which will run all tests locally. Since we have some architecture-dependent code, we also have the
option of running tests within an aarch64 VM:

```sh
./tools/run_tests --target=vm:aarch64
```

When working on a machine that does not support cross-compilation (e.g. gLinux), you can use the dev
container to build and run the tests.

```sh
./tools/dev_container ./tools/run_tests --target=vm:aarch64
```

It is also possible to run tests on a remote machine via ssh. The target architecture is
automatically detected:

```sh
./tools/run_tests --target=ssh:hostname
```

However, it is your responsibility to make sure the required libraries for crosvm are installed and
password-less authentication is set up. See `./tools/impl/testvm/cloud_init.yaml` for hints on what
the VM has installed.

### Presubmit checks

To verify changes before submitting, use the `presubmit` script:

```sh
./tools/presubmit
```

This will run clippy, formatters and runs all tests. The presubmits will use the dev container to
build for other platforms if your host is not set up to do so.

To run checks faster, they can be run in parallel in multiple tmux panes:

```sh
./tools/presubmit --tmux
```

The `--quick` variant will skip some slower checks, like building for other platforms altogether:

```sh
./tools/presubmit --quick
```

## Known issues

- Devices can't be jailed if `/var/empty` doesn't exist. `sudo mkdir -p /var/empty` to work around
  this for now.
- You need read/write permissions for `/dev/kvm` to run tests or other crosvm instances. Usually
  it's owned by the `kvm` group, so `sudo usermod -a -G kvm $USER` and then log out and back in
  again to fix this.
- Some other features (networking) require `CAP_NET_ADMIN` so those usually need to be run as root.
