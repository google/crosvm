# Testing

Crosvm runs on a variety of platforms with a significant amount of platform-specific code. Testing
on all the supported platforms is crucial to keep crosvm healthy.

## Types of tests

### Unit Tests

Unit tests are your standard rust tests embedded with the rest of the code in `src/` and wrapped in
a `#[cfg(test)]` attribute.

Unit tests **cannot make any guarantees on the runtime environment**. Avoid doing the following in
unit tests:

- Avoid kernel features such as io_uring or userfaultfd, which may not be available on all kernels.
- Avoid functionality that requires privileges (e.g. CAP_NET_ADMIN)
- Avoid spawning threads or processes
- Avoid accessing kernel devices
- Avoid global state in unit tests

This allows us to execute unit tests for any platform using emulators such as qemu-static or wine64.

### Integration tests

Cargo has native support for
[integration testing](https://doc.rust-lang.org/rust-by-example/testing/integration_testing.html).
Integration tests are written just like unit tests, but live in a separate directory at `tests/`.

Integration tests **guarantee that the test has privileged access to the test environment**. They
are only executed when a device-under-test (DUT) is specified when running tests:

```sh
./tools/run_tests --dut=vm|host
```

### End To End (E2E) tests

End to end tests live in the `e2e_tests` crate. The crate provides a framework to boot a guest with
crosvm and execut commands in the guest to validate functionality at a high level.

E2E tests are executed just like integration tests.

### Downstream Product tests

Each downstream product that uses crosvm is performing their own testing, e.g. ChromeOS is running
high level testing of its VM features on ChromeOS hardware, while AOSP is running testing of their
VM features on AOSP hardware.

Upstream crosvm is not involved in these tests and they are not executed in crosvm CI.

## Parallel test execution

Crosvm tests are executed in parallel, each test case in its own process via
[cargo nextest](http://nexte.st).

This requires tests to be cautious about global state, especially integration tests which interact
with system devices.

If you require exclusive access to a device or file, you have to use
[file-based locking](https://docs.rs/named-lock/latest/named_lock) to prevent access by other test
processes.

## Platorms tested

The platforms below can all be tested using `tools/run_tests -p $platform`. The table indicates how
these tests are executed:

| Platform                    | Build |          Unit Tests           | Integration Tests | E2E Tests |
| :-------------------------- | :---: | :---------------------------: | :---------------: | :-------: |
| x86_64 (linux)              |   ✅   |               ✅               |         ✅         |     ✅     |
| aarch64 (linux)             |   ✅   | ✅ (qemu-static[^qemu-static]) |  ✅ (qemu[^qemu])  |     ❌     |
| armhf (linux)               |   ✅   | ✅ (qemu-static[^qemu-static]) |         ❌         |     ❌     |
| mingw64[^windows] (linux)   |   🚧   |          🚧 (wine64)           |         ❌         |     ❌     |
| mingw64[^windows] (windows) |   🚧   |               🚧               |         🚧         |     ❌     |

Crosvm CI will use the same configuration as `tools/run_tests`.

[^qemu-static]: qemu-static-aarch64 or qemu-static-arm translate instructions into x86 and executes them on the
    host kernel. This works well for unit tests, but will fail when interacting with platform
    specific kernel features.

[^qemu]: run_tests will launch a VM for testing in the background. This VM is using full system
    emulation, which causes tests to be slow. Also not all aarch64 features are properly emulated,
    which prevents us from running e2e tests.

[^windows]: Windows builds of crosvm are a work in progress. Some tests are executed via wine64 on linux
