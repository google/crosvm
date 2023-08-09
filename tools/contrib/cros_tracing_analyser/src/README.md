# cros_tracing_analyser

Extract event_data and timestamp from input file from `trace-cmd record` and calculate average
latency of cros_tracing event

## Build

Build the tool with cargo, and then run the binary with an input and output file path.

```
$ cargo run
$ cargo run -- --input /* path */ --output /* path */
```
