# Contributing

## Intro

This article goes into detail about multiple areas of interest to contributors, which includes
reviewers, developers, and integrators who each share an interest in guiding crosvm's direction.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License Agreement (CLA). You (or
your employer) retain the copyright to your contribution; this simply gives us permission to use and
redistribute your contributions as part of the project. Head over to
<https://cla.developers.google.com/> to see your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one (even if it was for
a different project), you probably don't need to do it again.

## Bug Reports

We use the Chromium issue tracker. Please use
[`OS>Systems>Containers`](https://bugs.chromium.org/p/chromium/issues/list?q=component:OS%3ESystems%3EContainers)
component.

## Philosophy

The following is high level guidance for producing contributions to crosvm.

- Prefer mechanism to policy.
- Use existing protocols when they are adequate, such as virtio.
- Prefer security over code re-use and speed of development.
- Only the version of Rust in use by the Chrome OS toolchain is supported. This is ordinarily the
  stable version of Rust, but can be behind a version for a few weeks.
- Avoid distribution specific code.

## Code Health

### Scripts

In the `bin/` directory of the crosvm repository, there is the `clippy` script which lints the Rust
code and the `fmt` script which will format the crosvm Rust code inplace.

### Running tests

The `./test_all` script will use docker containers to run all tests for crosvm.

For more details on using the docker containers for running tests locally, including faster,
iterative test runs, see `ci/README.md`.

### Style guidelines

To format all code, crosvm defers to rustfmt. In addition, the code adheres to the following rules:

The `use` statements for each module should be grouped in this order

1. `std`
1. third-party crates
1. chrome os crates
1. crosvm crates
1. `crate`

crosvm uses the [remain](https://github.com/dtolnay/remain) crate to keep error enums sorted, along
with the `#[sorted]` attribute to keep their corresponding match statements in the same order.

## Submitting Code

Since crosvm is one of Chromium OS projects, please read through [Chrome OS Contributing Guide]
first. This section describes the crosvm-specific workflow.

### Trying crosvm

Please see [the book of crosvm].

### Sending for code review

We use [Chromium Gerrit](https://chromium-review.googlesource.com/) for code reviewing. All crosvm
CLs are listed at the [crosvm component].

> Note: We don't accept any pull requests on the [GitHub mirror].

#### For Chromium OS Developers {#chromiumos-cl}

If you have already set up the `chromiumos` repository and the `repo` command, you can simply create
and upload your CL in a similar manner as other Chromium OS projects.

`repo start` will create a branch tracking `cros/chromeos` so you can develop with the latest,
CQ-tested code as a foundation.

However, changes are not acceped to the `cros/chromeos` branch, and should be submitted to
`cros/main` instead.

Use `repo upload -D main` to upload changes to the main branch, which works fine in most cases where
gerrit can rebase the commit cleanly. If not, please rebase to `cros/main` manually.

#### For non-Chromium OS Developers

If you are not interested in other Chromium OS components, you can simply
[clone and contribute crosvm only](https://google.github.io/crosvm/building_crosvm/linux.html).
Before you make a commit locally, please set up [Gerrit's Change-Id hook] on your system.

```sh
# Modify code and make a git commit with a commit message following this rule:
# https://chromium.googlesource.com/chromiumos/docs/+/HEAD/contributing.md#Commit-messages
git commit
# Push your commit to Chromium Gerrit (https://chromium-review.googlesource.com/).
git push origin HEAD:refs/for/main
```

### Code review

Your change must be reviewed and approved by one of [crosvm owners].

### Presubmit checking {#presubmit}

Once your change is reviewed, it will need to go through two layers of presubmit checks.

The review will trigger Kokoro to run crosvm specific tests. If you want to check kokoro results
before a review, you can set 'Commit Queue +1' in gerrit to trigger a dry-run.

If you upload further changes after the you were given 'Code Review +2', Kokoro will automatically
trigger another test run. But you can also always comment 'kokoro rerun' to manually trigger another
build if needed.

When Kokoro passes, it will set Verified +1 and the change is ready to be sent to the
[ChromeOS commit queue](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/contributing.md#send-your-changes-to-the-commit-queue)
by setting CQ+2.

Note: This is different from other ChromeOS repositories, where Verified +1 bit is set by the
developers to indicate that they successfully tested a change. The Verified bit can only be set by
Kokoro in the crosvm repository.

### Postsubmit merging to Chrome OS {#chromiumos-postsubmit}

Crosvm has a unique setup to integrate with ChromeOS infrastructure.

The chromeos checkout tracks the
[cros/chromeos](https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/chromeos)
branch of crosvm, not the
[cros/main](https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main) branch.

While upstream development is happening on the `main` branch, changes submitted to that branch are
only tested by the crosvm kokoro CI system, not by the ChromeOS CQ.

There is a
[daily process](https://chromium-review.googlesource.com/q/project:chromiumos%252Fplatform%252Fcrosvm+branch:chromeos)
that creates a commit to merge changes from `main` into the `chromeos` branch, which is then tested
through the CQ and watched by the crosvm-uprev rotation.

## Contributing to the documentation

[The book of crosvm] is build with [mdBook]. Each markdown files must follow
[Google Markdown style guide].

To render the book locally, you need to install mdbook and [mdbook-mermaid], which should be
installed when you run `./tools/install-deps`script.

```sh
cd crosvm/docs/book/
mdbook build
```

> Note: If you make a certain size of changes, it's recommended to reinstall mdbook manually with
> `cargo install mdbook`, as `./tools/install-deps` only installs a binary with some convenient
> features disabled. For example, the full version of mdbook allows you to edit files while checking
> rendered results.

[chrome os contributing guide]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/contributing.md
[crosvm component]: https://chromium-review.googlesource.com/q/project:chromiumos%252Fplatform%252Fcrosvm
[crosvm owners]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/HEAD/OWNERS
[gerrit's change-id hook]: https://gerrit-review.googlesource.com/Documentation/user-changeid.html
[github mirror]: https://github.com/google/crosvm
[google markdown style guide]: https://github.com/google/styleguide/blob/gh-pages/docguide/style.md
[mdbook]: https://rust-lang.github.io/mdBook/
[mdbook-mermaid]: https://github.com/badboy/mdbook-mermaid
[the book of crosvm]: https://google.github.io/crosvm/
