# Analyzes cros_tracing event

Extract event_data and timestamp from input file from `trace-cmd record` and calculate average
latency of cros_tracing events

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
