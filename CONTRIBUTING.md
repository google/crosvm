# How to Contribute to crosvm

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
"Change-Id" into all commit messages so gerrit can identify changes. Even warning messages appear,
the message hook will be installed.

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

This abstracts away the cross-platform differences:
cfg(any(target_os = "android", target_os = "linux")) uses a Unix
domain domain stream socket to connect to the vhost-user backend, and
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
git checkout -b myfeature --track origin/main
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

If the branch contains multiple commits, each one will be uploaded as a separate review, and they
will be linked in Gerrit as [related changes]. You may revise any commit in a branch using tools
like `git rebase` and then re-upload the whole series with `./tools/cl upload` when `HEAD` is
pointing to the tip of the branch.

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

Each individual change in a patch series must build and pass the tests. If you are working on a
series of related changes, ensure that each incremental commit does not cause test regressions or
break the build if it is merged without the later changes in the series. For example, an
intermediate change must not trigger any unused code warnings or cause test failures that are fixed
by later changes in the series.

When all tests pass, your change is merged into `origin/main`.

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

To format markdown files, run `./tools/fmt` in the `dev_container`.

[crosvm owners]: https://chromium.googlesource.com/crosvm/crosvm/+/HEAD/OWNERS
[github mirror]: https://github.com/google/crosvm
[google markdown style guide]: https://github.com/google/styleguide/blob/gh-pages/docguide/style.md
[mdbook]: https://rust-lang.github.io/mdBook/
[mdbook-mermaid]: https://github.com/badboy/mdbook-mermaid
[related changes]: https://gerrit-review.googlesource.com/Documentation/user-review-ui.html#related-changes
[the book of crosvm]: https://crosvm.dev/book/
