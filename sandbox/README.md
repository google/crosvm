# Sandbox dependencies

This crate links against chromium project's
[sandbox library](https://chromium.googlesource.com/chromium/src/+/6bb3606c2b1a60265fc7f1632896b640fa0d7865/sandbox/win/).
The library is provided as a prebuilt because

- The build system's toolchain doesn't support building that library.
- The original library is C++ based and we have added a small C wrapper around it to which rust
  binds.

`build.rs` downloads the prebuilt library during build.

Googlers can build the library by following [these](http://shortn/_pKqdJVrziE) instructions.
