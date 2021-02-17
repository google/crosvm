## Intro

This article goes into detail about multiple areas of interest to contributors,
which includes reviewers, developers, and integrators who each share an interest
in guiding crosvm's direction.

## Guidelines

The following is high level guidance for producing contributions to crosvm.

- Prefer mechanism to policy.
- Use existing protocols when they are adequate, such as virtio.
- Prefer security over code re-use and speed of development.
- Only the version of Rust in use by the Chrome OS toolchain is supported. This
  is ordinarily the stable version of Rust, but can be behind a version for a
  few weeks.
- Avoid distribution specific code.

## Code Health

### Scripts

In the `bin/` directory of the crosvm repository, there is the `clippy` script
which lints the Rust code and the `fmt` script which will format the crosvm Rust
code inplace.

### Running tests

The `./test_all` script will use docker containers to run all tests for crosvm.
When submitting changes, these tests will be run by Kokoro, the internal Google
run cloud builder, and the results will be posted to the change. Kokoro is only
informational, so if Kokoro rejects a change, it can still be submitted.

For more details on using the docker containers for running tests locally,
including faster, iterative test runs, see `ci/README.md`.

### Submitting Code

See also,
[Chrome OS Contributing Guide](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/contributing.md)

When a change is approved, verified, and added to the
[commit queue](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/contributing.md#send-your-changes-to-the-commit-queue),
crosvm will be built and the unit tests (with some exceptions) will be run by
the Chrome OS infrastructure. Only if that passes, will the change be submitted.
Failures here will cause the commit queue to reject the change until it is
re-added (CQ+2). Unfortunately, it is extremely common for false negatives to
cause a change to get rejected, so be ready to re-apply the CQ+2 label if you're
the owner of a ready to submit change.

### Style guidelines

To format all code, crosvm defers to rustfmt. In addition, the code adheres to
the following rules:

The `use` statements for each module should be grouped in this order

1.  `std`
2.  third-party crates
3.  chrome os crates
4.  crosvm crates
5.  `crate`

crosvm uses the [remain](https://github.com/dtolnay/remain) crate to keep error
enums sorted, along with the `#[sorted]` attribute to keep their corresponding
match statements in the same order.
