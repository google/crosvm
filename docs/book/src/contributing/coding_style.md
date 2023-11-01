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

### Prefer single responsibility functions

Functions should have a single responsibility. This helps keep functions short and readable. We
prefer this because functions with multiple responsibilities are hard to follow, often suffer from
extensive indentation (very short effective line length), and are trickier to test.

When you encounter large/complex functions or are about to add complexity, consider split them into
multiple functions. Useful patterns that can help with this include splitting enums into sub-enums,
or broader refactoring to split unrelated responsibilities from each other.

### Avoid large argument lists

When a function exceeds roughly 6 parameters, this is usually a signal that we should be creating a
struct to handle the parameters. More than 6 arguments tends to make call sites unwieldy & hard to
read. It could also be a hint that the function has too many responsibilities and should be split
up.

### Avoid extensive indentation

Sometimes indentation becomes excessive in functions and severely limits the usable line length.
Even with editor support, it can be tricky to tell which code is associated with which block.
Classic examples of this are function calls that pass lambdas, where the call site is nested inside
multiple matches or conditionals. In these cases, try to remove indentation by creating helpers to
reset the indentation level, but be thoughtful about whether this makes the situation worse by
creating an onion (too many layers / an overly deep stack).

### Unsafe code: minimize code under `unsafe`

Every line of unsafe code can cause memory safety issues. As such, we want to minimize code under
`unsafe`. Often times we want to have an `unsafe` function because the caller must satisfy safety
conditions, but we only have one or two actual `unsafe` lines in the function, along with many safe
lines. In these situations, mark the function `unsafe`, but apply
[`#[deny(unsafe_op_in_unsafe_fn)]`](https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html#unsafe-op-in-unsafe-fn).
This requires us to explicitly mark the `unsafe` code inside as `unsafe` rather than allowing any
line in the function to be unsafe.

### Unsafe code: write standard safety statements

Rust tooling expects documentation for `unsafe` code and functions to follow the stdlib's
[guidelines](https://std-dev-guide.rust-lang.org/policy/safety-comments.html). Notably, use
`// SAFETY:` for `unsafe` blocks, and always have a `# Safety` section for `unsafe` functions in
their doc comment. This helps us comply with
[`undocumented_unsafe_blocks`](https://rust-lang.github.io/rust-clippy/master/#/undocumented_unsafe_blocks),
which will eventually be turned on.

Note that not all existing code follows this pattern. `// Safe because` comments are still common in
the codebase, and should be migrated to the new pattern as they are encountered.

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

## Handling technical debt

During development, we don't always have cycles or expertise available to fix problematic patterns
or overly complex code. In these situations where we find an existing problem, or are tacking on
code to a problematic area, we should document the problem in a bug and add it to the
[Code Health](https://issuetracker.google.com/hotlists/4285957) hotlist. This is where maintainers
look to determine what debt most needs attention. The bug should cover:

- Which style guidance is being violated.
- What the impact is (readability, easy to introduce bugs, hard to test, etc)
- Any recommendations for a fix.

[`group_imports=stdexternalcrate`]: https://rust-lang.github.io/rustfmt/?version=v1.5.1&search=#group_imports
[`imports_granularity=item`]: https://rust-lang.github.io/rustfmt/?version=v1.5.1&search=#imports_granularity
