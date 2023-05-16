# Coding Style Guide

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

[`group_imports=stdexternalcrate`]: https://rust-lang.github.io/rustfmt/?version=v1.5.1&search=#group_imports
[`imports_granularity=item`]: https://rust-lang.github.io/rustfmt/?version=v1.5.1&search=#imports_granularity
