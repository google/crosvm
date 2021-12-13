# Contributing

## Intro

This article goes into detail about multiple areas of interest to contributors,
which includes reviewers, developers, and integrators who each share an interest
in guiding crosvm's direction.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement (CLA). You (or your employer) retain the copyright to your
contribution; this simply gives us permission to use and redistribute your
contributions as part of the project. Head over to
<https://cla.developers.google.com/> to see your current agreements on file or
to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Bug Reports

We use the Chromium issue tracker. Please use
[`OS>Systems>Containers`](https://bugs.chromium.org/p/chromium/issues/list?q=component:OS%3ESystems%3EContainers)
component.

## Philosophy

The following is high level guidance for producing contributions to crosvm.

-   Prefer mechanism to policy.
-   Use existing protocols when they are adequate, such as virtio.
-   Prefer security over code re-use and speed of development.
-   Only the version of Rust in use by the Chrome OS toolchain is supported.
    This is ordinarily the stable version of Rust, but can be behind a version
    for a few weeks.
-   Avoid distribution specific code.

## Code Health

### Scripts

In the `bin/` directory of the crosvm repository, there is the `clippy` script
which lints the Rust code and the `fmt` script which will format the crosvm Rust
code inplace.

### Running tests

The `./test_all` script will use docker containers to run all tests for crosvm.

For more details on using the docker containers for running tests locally,
including faster, iterative test runs, see `ci/README.md`.

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

## Submitting Code

Since crosvm is one of Chromium OS projects, please read through
[Chrome OS Contributing Guide] first. This section describes the crosvm-specific
workflow.

[Chrome OS Contributing Guide]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/contributing.md

### Creating a CL

We use [Chromium Gerrit](https://chromium-review.googlesource.com/) for code
reviewing. All crosvm CLs are listed at the [crosvm component].

> Note: We don't accept any pull requests on the [GitHub mirror].

[Chromium Gerrit]: https://chromium-review.googlesource.com
[crosvm component]: https://chromium-review.googlesource.com/q/project:chromiumos%252Fplatform%252Fcrosvm
[GitHub mirror]: https://github.com/google/crosvm

#### For Chromium OS Developers

If you have already set up the `chromiumos` repository and the `repo` command,
you can simply create and upload your CL in the same way as other Chromium OS
projects.

#### For non-Chromium OS Developers

If you are not interested in other Chromium OS components, you can simply clone
and contribute crosvm only. Before you make a commit locally, please set up
[Gerrit's Change-Id hook] on your system.

[Gerrit's Change-Id hook]: https://gerrit-review.googlesource.com/Documentation/user-changeid.html

```bash
$ git clone https://chromium.googlesource.com/chromiumos/platform/crosvm
# Modify code and make a git commit with a commit message following this rule:
# https://chromium.googlesource.com/chromiumos/docs/+/HEAD/contributing.md#Commit-messages
$ git commit
# Push your commit to Chromium Gerrit (https://chromium-review.googlesource.com/).
$ git push origin HEAD:refs/for/main
```

### Code review

Your change must be reviewed and approved by one of [crosvm owners].

[crosvm owners]: https://chromium.googlesource.com/chromiumos/platform/crosvm/+/HEAD/OWNERS

### Presubmit checking

Once your change is reviewed, it will need to go through two layers of presubmit
checks.

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

## Contributing to the documentation

[The book of crosvm] is build with [mdBook]. Each markdown files must follow
[Google Markdown style guide].

To render the book locally, you need to install mdbook and [mdbook-mermaid],
which should be installed when you run `./tools/install-deps`script.

```bash
cd crosvm/docs/book/
mdbook build
```

> Note: If you make a certain size of changes, it's recommended to reinstall
> mdbook manually with `cargo install mdbook`, as `./tools/install-deps` only
> installs a binary with some convenient features disabled. For example, the
> full version of mdbook allows you to edit files while checking rendered
> results.

[The book of crosvm]: https://google.github.io/crosvm/
[mdBook]: https://rust-lang.github.io/mdBook/
[Google Markdown style guide]: https://github.com/google/styleguide/blob/gh-pages/docguide/style.md
[mdbook-mermaid]: https://github.com/badboy/mdbook-mermaid
