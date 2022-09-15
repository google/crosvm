# Contributing

## Intro

This article goes into detail about multiple areas of interest to contributors, which includes
reviewers, developers, and integrators who each share an interest in guiding crosvm's direction.

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

## Style guidelines

### Formatting

To format all code, crosvm defers to rustfmt. In addition, the code adheres to the following rules:

The `use` statements for each module should be grouped in this order

1. `std`
1. third-party crates
1. chrome os crates
1. crosvm crates
1. `crate`

crosvm uses the [remain](https://github.com/dtolnay/remain) crate to keep error enums sorted, along
with the `#[sorted]` attribute to keep their corresponding match statements in the same order.

### Unit test code

Unit tests and other highly-specific tests (which may include some small, but not all, integration
tests) should be written differently than how non-test code is written. Tests prevent regressions
from being committed, show how APIs can be used, and help with understanding bugs in code. That
means tests must be clear both now and in the future to a developer with low familiarity of the code
under test. They should be understandable by reading from top to bottom without referencing any
other code. Towards these goals, tests should:

- To the extent reasonable, be structured as Arrange-Act-Assert.
- Test the minimum number of behaviors in a single test. Make separate tests for separate behavior.
- Avoid helper methods that send critical inputs or assert outputs within the helper itself. It
  should be easy to read a test and determine the critical inputs/outputs without digging through
  helper methods. Setup common to many tests is fine to factor out, but lean toward duplicating code
  if it aids readability.
- Avoid branching statements like conditionals and loops (which can make debugging more difficult).
- Document the reason constants were chosen in the test, including if they were picked arbitrarily
  such that in the future, changing the value is okay. (This can be done with constant variable
  names, which is ideal if the value is used more than once, or in a comment.)
- Name tests to describe what is being tested and the expected outcome, for example
  `test_foo_invalid_bar_returns_baz`.

Less-specific tests, such as most integration tests and system tests, are more likely to require
obfuscating work behind helper methods. It is still good to strive for clarity and ease of debugging
in those tests, but they do not need to follow these guidelines.

## Contributing Code

### Prerequisites

You need to set up a user account with [gerrit](https://chromium-review.googlesource.com/). Once
logged in, you can obtain
[HTTP Credentials](https://chromium-review.googlesource.com/settings/#HTTPCredentials) to set up git
to upload changes.

Once set up, run `./tools/cl` to install the gerrit commit message hook. This will insert a unique
"Change-Id" into all commit messages so gerrit can identify changes.

### Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License Agreement (CLA). You (or
your employer) retain the copyright to your contribution; this simply gives us permission to use and
redistribute your contributions as part of the project. Head over to
<https://cla.developers.google.com/> to see your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one (even if it was for
a different project), you probably don't need to do it again.

### Uploading changes

To make changes to crosvm, start your work on a new branch tracking `origin/main`.

```bash
git checkout --branch myfeature --track origin/main
```

After making the necessary changes, and testing them via
[Presubmit Checks](https://crosvm.dev/book/building_crosvm.html#presubmit-checks), you can commit
and upload them:

```bash
git commit
./tools/cl upload
```

If you need to revise your change, you can amend the existing commit and upload again:

```bash
git commit --amend
./tools/cl upload
```

This will create a new version of the same change in gerrit.

> Note: We don't accept any pull requests on the [GitHub mirror].

### Getting Reviews

All submissions needs to be reviewed by one of the [crosvm owners]. Use the gerrit UI to request a
review. If you are uncertain about the correct person to review, reach out to the team via
[chat](https://matrix.to/#/#crosvm:matrix.org) or
[email list](https://groups.google.com/a/chromium.org/g/crosvm-dev).

### Submitting code

Crosvm uses a Commit Queue, which will run pre-submit testing on all changes before merging them
into crosvm.

Once one of the [crosvm owners] has voted "Code-Review+2" on your change, you can use the "Submit to
CQ" button, which will trigger the test process.

Gerrit will show any test failures. Refer to
[Building Crosvm](https://crosvm.dev/book/building_crosvm.html) for information on how to run the
same tests locally.

When all tests pass, your change is merged into `origin/main`.

## Contributing to the documentation

[The book of crosvm] is build with [mdBook]. Each markdown files must follow
[Google Markdown style guide].

To render the book locally, you need to install mdbook and [mdbook-mermaid], which should be
installed when you run `./tools/install-deps`script. Or you can use the `tools/dev_container`
environment.

```sh
cd docs/book/
mdbook build
```

Output is found at `docs/book/book/html/`.

> Note: If you make a certain size of changes, it's recommended to reinstall mdbook manually with
> `cargo install mdbook`, as `./tools/install-deps` only installs a binary with some convenient
> features disabled. For example, the full version of mdbook allows you to edit files while checking
> rendered results.

[crosvm owners]: https://chromium.googlesource.com/crosvm/crosvm/+/HEAD/OWNERS
[github mirror]: https://github.com/google/crosvm
[google markdown style guide]: https://github.com/google/styleguide/blob/gh-pages/docguide/style.md
[mdbook]: https://rust-lang.github.io/mdBook/
[mdbook-mermaid]: https://github.com/badboy/mdbook-mermaid
[the book of crosvm]: https://crosvm.dev/book/
