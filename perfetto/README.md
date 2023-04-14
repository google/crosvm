# Perfetto Rust wrapper

The following instructions are based on `tools/impl/bindgen-common.sh`

When the Perfetto C API is updated, in order to regenerate the bindings:

1. [Download the bindgen cmdline tool.](https://rust-lang.github.io/rust-bindgen/command-line-usage.html)
1. Run the bindgen command. If you are in crosvm:
   ```
   $ bindgen third_party/perfetto/include/perfetto/tracing/ctrace.h --disable-header-comment --no-layout-tests --no-doc-comments --with-derive-default --size_t-is-usize -o ./perfetto/src/bindings.rs
   ```
1. Add the following to the top of the new bindings.rs file:
   ```
   #![allow(clippy::missing_safety_doc)]
   #![allow(clippy::upper_case_acronyms)]
   #![allow(non_upper_case_globals)]
   #![allow(non_camel_case_types)]
   #![allow(non_snake_case)]
   #![allow(dead_code)]
   ```
1. Finally, add a copyright header to the bindings.
