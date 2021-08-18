# Building for Linux

Crosvm uses submodules to manage external dependencies. Initialize them via:

```sh
git submodule update --init
```

It is recommended to enable automatic recursive operations to keep the
submodules in sync with the main repository (But do not push them, as that can
conflict with `repo`):

```sh
git config --global submodule.recurse true
git config push.recurseSubmodules no
```

Crosvm requires a couple of dependencies. For Debian derivatives these can be
installed by (Depending on which feature flags are used, not all of these will
actually be required):

```sh
sudo apt install \
    bindgen \
    build-essential \
    clang \
    libasound2-dev \
    libcap-dev \
    libdbus-1-dev \
    libdrm-dev \
    libepoxy-dev \
    libssl-dev \
    libwayland-bin \
    libwayland-dev \
    pkg-config \
    protobuf-compiler \
    python3 \
    wayland-protocols
```

And that's it! You should be able to `cargo build/run/test`.

## Known issues

-   By default, crosvm is running devices in sandboxed mode, which requires
    seccomp policy files to be set up. For local testing it is often easier to
    `--disable-sandbox` to run everything in a single process.
-   If your Linux header files are too old, you may find minijail rejecting
    seccomp filters for containing unknown syscalls. You can try removing the
    offending lines from the filter file, or add `--seccomp-log-failures` to the
    crosvm command line to turn these into warnings. Note that this option will
    also stop minijail from killing processes that violate the seccomp rule,
    making the sandboxing much less aggressive.
-   Seccomp policy files have hardcoded absolute paths. You can either fix up
    the paths locally, or set up an awesome hacky symlink:
    `sudo mkdir /usr/share/policy && sudo ln -s /path/to/crosvm/seccomp/x86_64 /usr/share/policy/crosvm`.
    We'll eventually build the precompiled policies
    [into the crosvm binary](http://crbug.com/1052126).
-   Devices can't be jailed if `/var/empty` doesn't exist.
    `sudo mkdir -p /var/empty` to work around this for now.
-   You need read/write permissions for `/dev/kvm` to run tests or other crosvm
    instances. Usually it's owned by the `kvm` group, so
    `sudo usermod -a -G kvm $USER` and then log out and back in again to fix
    this.
-   Some other features (networking) require `CAP_NET_ADMIN` so those usually
    need to be run as root.

## Running crosvm tests on Linux

### Installing Podman (or Docker)

See [Podman Installation](https://podman.io/getting-started/installation) for
instructions on how to install podman.

For Googlers, see [go/dont-install-docker](http://go/dont-install-docker) for
special instructions on how to set up podman.

If you already have docker installed, that will do as well. However podman is
recommended as it will not run containers with root privileges.

### Running all tests

To run all tests for all platforms, just run:

```
./test_all
```

This will run all tests using the x86 and aarch64 builder containers. What does
this do?

1.  It will start `./ci/[aarch64_]builder --vm`.

    This will start the builder container and launch a VM for running tests in
    the background. The VM is booting while the next step is running.

2.  It will call `./run_tests` inside the builder

    The script will pick which tests to execute and where. Simple tests can be
    executed directly, other tests require privileged access to devices and will
    be loaded into the VM to execute.

    Each test will in the end be executed by a call to
    `cargo test -p crate_name`.

Intermediate build data is stored in a scratch directory at `./target/ci/` to
allow for faster subsequent calls (Note: If running with docker, these files
will be owned by root).

### Fast, iterative test runs

For faster iteration time, you can directly invoke some of these steps directly:

To only run x86 tests: `./ci/[aarch64_]builder --vm ./run_tests`.

To run a simple test (e.g. the tempfile crate) that does not need the vm:
`./ci/[aarch64_]builder cargo test -p tempfile`.

Or run a single test (e.g. kvm_sys) inside the vm:
`./ci/[aarch64*]builder --vm cargo test -p kvm_sys`.

Since the VM (especially the fully emulated aarch64 VM) can be slow to boot, you
can start an interactive shell and run commands from there as usual. All cargo
tests will be executed inside the VM, without the need to restart the VM between
test calls.

```sh
host$ ./ci/aarch64_builder --vm
crosvm-aarch64$ ./run_tests
crosvm-aarch64$ cargo test -p kvm_sys
...
```

### Running tests without Docker

Specific crates can be tested as usual with `cargo test` without the need for
Docker. However, because of special requirements some of them will not work,
which means that `cargo test --workspace` will also not work to run all tests.

For this reason, we have a separate test runner `./run_tests` which documents
the requirements of each crate and picks the tests to run. It is used by the
Docker container to run tests, but can also be run outside of the container to
run a subset of tests.

See `./run_tests --help` for more information.

### Reproducing Kokoro locally

Kokoro runs presubmit tests on all crosvm changes. It uses the same builders and
the same `run_tests` script to run tests. This should match the results of the
`./test_all` script, but if it does not, the kokoro build scripts can be
simulated locally using: `./ci/kokoro/simulate_all`.
