# Fuzzing

Crosvm contains several [fuzz testing](https://en.wikipedia.org/wiki/Fuzzing) programs that are
intended to exercise specific subsets of the code with automatically generated inputs to help
uncover bugs that were not found by human-written unit tests.

The source code for the fuzzer target programs can be found in [`fuzz/fuzz_targets`] in the crosvm
source tree.

## OSS-Fuzz

Crosvm makes use of the OSS-Fuzz service, which automatically builds and runs fuzzers for many open
source projects. Once a crosvm change is committed and pushed to the main branch, it will be tested
automatically by [ClusterFuzz], and if new issues are found, a bug will be filed.

- [crosvm oss-fuzz configuration]
- [crosvm oss-fuzz build status]

## Running fuzzers locally

It can be useful to run a fuzzer in order to test new changes locally or to reproduce a bug filed by
ClusterFuzz.

To build and run a specific fuzz target, install [`cargo fuzz`], then run it in the crosvm source
tree, specifying the desired fuzz target to run. If you have a testcase provided by the automated
fuzzing infrastructure in a bug report, you can add that file to the fuzzer command line to
reproduce the same fuzzer execution rather than using randomly generating inputs.

```sh
# Run virtqueue_fuzzer with randomly-generated input.
# This will run indefinitely; it can be stopped with Ctrl+C.
cargo +nightly fuzz run virtqueue_fuzzer

# Run virtqueue_fuzzer with a specific input file from ClusterFuzz.
cargo +nightly fuzz run virtqueue_fuzzer clusterfuzz-testcase-minimized-...
```

[clusterfuzz]: https://google.github.io/clusterfuzz/
[crosvm oss-fuzz build status]: https://oss-fuzz-build-logs.storage.googleapis.com/index.html#crosvm
[crosvm oss-fuzz configuration]: https://github.com/google/oss-fuzz/tree/master/projects/crosvm
[`cargo fuzz`]: https://github.com/rust-fuzz/cargo-fuzz
[`fuzz/fuzz_targets`]: https://chromium.googlesource.com/crosvm/crosvm/+/refs/heads/main/fuzz/fuzz_targets/
