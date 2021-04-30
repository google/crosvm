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

For more details on using the docker containers for running tests locally,
including faster, iterative test runs, see `ci/README.md`.

### Submitting Code

See also,
[Chrome OS Contributing Guide](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/contributing.md)

Once your change is reviewed by a crosvm
[owner](https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform/crosvm/OWNERS)
it will need to go through two layers of presubmit checks.

The review will trigger Kokoro to run crosvm specific tests. If you want to
check kokoro results before a review, you can set 'Commit Queue +1' in gerrit to
trigger a dry-run.

If you upload further changes after the you were given 'Code Review +2', Kokoro
will automatically trigger another test run. But you can also always comment
'kokoro rerun' to manually trigger another build if needed.

When Kokoro passes, it will set Verified +1 and the change is ready to be sent
to the
[ChromeOS commit queue](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/contributing.md#send-your-changes-to-the-commit-queue)
by setting CQ+2.

Note: This is different from other ChromeOS repositories, where Verified +1 bit
is set by the developers to indicate that they successfully tested a change. The
Verified bit can only be set by Kokoro in the crosvm repository.

The commit queue will test your change on ChromeOS hardware, including high
level end-to-end tests. Only if all of those pass, will the change be submitted.

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
