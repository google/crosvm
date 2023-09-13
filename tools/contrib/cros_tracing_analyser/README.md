# Analyzes cros_tracing event

Extract event_data and timestamp from input file from `trace-cmd record` and calculate average
latency of cros_tracing events

## How to list cros_tracing event name

```
$ cargo run -- list --input trace.dat --count 10
```

Print list of function names and sum of latency in the trace.dat. Example log:

```
#1: read: 728685132 usec
#2: readdir: 719231760 usec
#3: lookup: 460496754 usec
#4: open: 38860424 usec
#5: opendir: 38159576 usec
#6: getxattr: 21408816 usec
#7: release: 17821045 usec
#8: releasedir: 17783896 usec
#9: forget: 2942940 usec
#10: getattr: 301824 usec
```

## How to calculate event average latency

```
$ cargo run -- average --input trace.dat --output-json tracing_data.json
```

calculate the average latency for each virtiofs event and output it to json file

## How to generate flamegraph data

```
$ cargo run -- flamegraph --input trace.dat --output-json tracing_data.json
```

Extract all events and calculate its latency and output it to a json file compatibile with d3
flamegraph.

To visualize the html page with the flamegraph, you need to run a local webserver. You can do this
with a simple python http server:

```
$ python3 -m http.server
```

And then open the page at http://localhost:8000/flamegraph.html and the flamegraph will be
displayed.

### How to apply filters to the flamegraph

```
$ cargo run -- flamegraph --input trace.dat --output-json tracing_data.json --function "lookup" --count 20
```

For example this command outputs the data of the top 20 "lookup" functions that are taking the most
time:
