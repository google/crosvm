# Contributing

## How to report bugs

We use Google issue tracker. Please use
[the public crosvm component](https://issuetracker.google.com/issues?q=status:open%20componentid:1161302).

**For Googlers**: See [go/crosvm#filing-bugs](https://goto.google.com/crosvm#filing-bugs).

## Contributing code

### Gerrit Account

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

### Commit Messages

As for commit messages, we follow
[ChromeOS's guideline](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/contributing.md#commit-messages)
in general.

Here is an example of a good commit message:

```
devices: vhost: user: vmm: Add Connection type

This abstracts away the cross-platform differences: cfg(unix) uses a
Unix domain stream socket to connect to the vhost-user backend, and
cfg(windows) uses a Tube.

BUG=b:249361790
TEST=tools/presubmit --all

Change-Id: I47651060c2ce3a7e9f850b7ed9af8bd035f82de6
```

- The first line is a subject that starts with a tag that represents which components your commit
  relates to. Tags are usually the name of the crate you modified such as `devices:` or `base:`. If
  you only modified a specific component in a crate, you can specify the path to the component as a
  tag like `devices: vhost: user:`. If your commit modified multiple crates, specify the crate where
  your main change exists. The subject should be no more than 50 characters, including any tags.
- The body should consist of a motivation followed by an impact/action. The body text should be
  wrapped to 72 characters.
- `BUG` lines are used to specify an associated issue number. If the issue is filed at
  [Google's issue tracker](https://issuetracker.google.com/), write `BUG=b:<bug number>`. If no
  issue is associated, write `BUG=None`. You can have multiple `BUG` lines.
- `TEST` lines are used to describe how you tested your commit in a free form. You can have multiple
  `TEST` lines.
- `Change-Id` is used to identify your change on Gerrit. It's inserted by the gerrit commit message
  hook as explained in
  [the previous section](https://crosvm.dev/book/contributing/index.html#gerrit-account). If a new
  commit is uploaded with the same `Change-Id` as an existing CL's `Change-Id`, gerrit will
  recognize the new commit as a new patchset of the existing CL.

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

## Philosophy

The following is high level guidance for producing contributions to crosvm.

- Prefer mechanism to policy.
- Use existing protocols when they are adequate, such as virtio.
- Prefer security over code re-use and speed of development.
- Only the version of Rust in use by the ChromeOS toolchain is supported. This is ordinarily the
  stable version of Rust, but can be behind a version for a few weeks.
- Avoid distribution specific code.

## Style guidelines

### Formatting

To format all code, crosvm defers to `rustfmt`. In addition, the code adheres to the following
rules:

Each `use` statement should import a single item, as produced by `rustfmt` with
[`imports_granularity=item`]. Do not use braces to import multiple items.

The `use` statements for each module should be grouped into blocks separated by whitespace in the
order produced by `rustfmt` with [`group_imports=StdExternalCrate`] and sorted alphabetically:

1. `std`
1. third-party + crosvm crates
1. `crate` + `super`

The import formatting options of `rustfmt` are currently unstable, so these are not enforced
automatically. If a nightly Rust toolchain is present, it is possible to automatically reformat the
code to match these guidelines by running `tools/fmt --nightly`.

crosvm uses the [remain](https://github.com/dtolnay/remain) crate to keep error enums sorted, along
with the `#[sorted]` attribute to keep their corresponding match statements in the same order.

### Unit test code

Unit tests and other highly-specific tests (which may include some small, but not all, integration
tests) should be written differently than how non-test code is written. Tests prevent regressions
from being committed, show how APIs can be used, and help with understanding bugs in code. That
means tests must be clear both now and in the future to a developer with low familiarity of the code
under test. They should be understandable by reading from top to bottom without referencing any
other code. Towards these goals, tests should:

- To a reasonable extent, be structured as Arrange-Act-Assert.
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

## Contributing to the documentation

[The book of crosvm] is built with [mdBook]. Each markdown file must follow
[Google Markdown style guide].

To render the book locally, you need to install mdbook and [mdbook-mermaid], which should be
installed when you run `./tools/install-deps` script. Or you can use the `tools/dev_container`
environment.

```sh
cd docs/book/
mdbook build
```

Output is found at `docs/book/book/html/`.

[crosvm owners]: https://chromium.googlesource.com/crosvm/crosvm/+/HEAD/OWNERS
[github mirror]: https://github.com/google/crosvm
[google markdown style guide]: https://github.com/google/styleguide/blob/gh-pages/docguide/style.md
[mdbook]: https://rust-lang.github.io/mdBook/
[mdbook-mermaid]: https://github.com/badboy/mdbook-mermaid
[the book of crosvm]: https://crosvm.dev/book/
[`group_imports=stdexternalcrate`]: https://rust-lang.github.io/rustfmt/?version=v1.5.1&search=#group_imports
[`imports_granularity=item`]: https://rust-lang.github.io/rustfmt/?version=v1.5.1&search=#imports_granularity
