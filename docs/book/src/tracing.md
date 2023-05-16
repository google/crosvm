# Tracing

Crosvm supports tracing to allow developers to debug and diagnose problems and check performance
optimizations.

The crate `cros_tracing` is used as a frontend for trace points across the crosvm codebase. It is
disabled by default but we can enable it with a compile-time flag. It is written to be extensible
and support multiple backends.

The currently supported backends are:

- [`noop`](https://github.com/google/crosvm/blob/main/cros_tracing/src/noop.rs): No tracing is
  enabled. All trace points are compiled out of the application so there is no performance
  degradation. This is the default backend when no tracing flag is provided.
- [`trace_marker`](https://crosvm.dev/doc/cros_tracing/trace_marker/index.html):
  [ftrace](https://docs.kernel.org/trace/ftrace.html) backend to log trace events to the Linux
  kernel. Only supported on Linux systems. Enabled by compiling crosvm with the
  `--features trace_marker` flag.

## cros_tracing Overview

The cros_tracing API consists of the following:

- `cros_tracing::init()`: called at initialization time in `src/main.rs` to set up any
  tracing-specific initialization logic (opening files, set up global state, etc).
- `cros_tracing::push_descriptors!()`: a macro that needs to be called every time crosvm sets up a
  sandbox jail before forking. It adds trace-specific file descriptors to the list of descriptors
  allowed to be accessed inside the jail, if any.
- `cros_tracing::trace_simple_print!()`: a simple macro that behaves like a log() print and sends a
  simple message to the tracing backend. In case of the `trace_marker` backend, this will show up as
  a message in the ftrace/print list of events.
- `cros_tracing::trace_event_begin!()`: a macro that tracks a tracing context for the given category
  and emits tracing events. It increased the counter of trace events for that context, if the
  category is enabled.
- `cros_tracing::trace_event_end!()`: the opposite of `trace_event_begin!()`. It decreases the
  counter of currently traced events for that category, if the category is enabled.
- `cros_tracing::trace_event!()`: a macro that returns a trace context. It records when it is first
  executed and the given tag + state. When the returned structure goes out of scope, it is
  automatically collected and the event is recorded. It is useful to trace entry and exit points in
  function calls. It is equivalent to calling `trace_event_begin!()`, logging data, and then calling
  `trace_event_end!()` before it goes out of scope. It's recommended to use `trace_event!()` rather
  than call `trace_event_begin!()` and `trace_event_end!()` individually.

The categories that are currently supported by cros_tracing are:

- VirtioFs
- VirtioNet

### The trace_marker Backend

The `trace_marker` backend assumes that the host kernel has tracefs enabled and
`/sys/kernel/tracing/trace_marker` is writable by the host when the crosvm process starts. If the
file cannot be accessed, tracing will not work.

### Usage

First, we want to build crosvm with trace_marker enabled:

```sh
cargo build --features trace_marker
```

To verify that tracing is working, first start a trace capture on the host. You can use something
like [trace-cmd](https://man7.org/linux/man-pages/man1/trace-cmd.1.html) or manually enable tracing
in the system from the terminal:

```sh
sudo echo 1 > /sys/kernel/tracing/tracing_on
```

We can check that virtiofs tracing is working by launching crosvm with a virtiofs filesystem:

```sh
sudo crosvm run --disable-sandbox --shared-dir ${MOUNTPOINT}:mtdroot:type=fs -p "rootfstype=virtiofs root=mtdroot rw init=/bin/bash" ${KERNEL}
```

Where `${MOUNTPOINT}` is your virtiofs filesystem and `${KERNEL}` is your linux kernel.

In another terminal, open a `cat` stream on the `/sys/kernel/tracing/trace_pipe` file to view the
tracing events in real time:

```sh
sudo cat /sys/kernel/tracing/trace_pipe
```

As you issue virtiofs requests, you should see events showing up like:

```
<...>-3802142 [011] ..... 2179601.746212: tracing_mark_write: fuse server: handle_message: in_header=InHeader { len: 64, opcode: 18, unique: 814, nodeid: 42, uid: 0, gid: 0, pid: 0, padding: 0 }
<...>-3802142 [011] ..... 2179601.746226: tracing_mark_write: 503 VirtioFs Enter: release - (self.tag: "mtdroot")(inode: 42)(handle: 35)
<...>-3802142 [011] ..... 2179601.746244: tracing_mark_write: 503 VirtioFs Exit: release
```

### Adding Trace Points

You can add you own trace points by changing the code and recompiling.

If you just need to add a simple one-off trace point, you can use `trace_simple_print!()` like this
(taken from `devices/src/virtio/fs/worker.rs`):

```rust
pub fn process_fs_queue<I: SignalableInterrupt, F: FileSystem + Sync>(
    mem: &GuestMemory,
    interrupt: &I,
    queue: &mut Queue,
    server: &Arc<fuse::Server<F>>,
    tube: &Arc<Mutex<Tube>>,
    slot: u32,
) -> Result<()> {
    // Added simple print here
    cros_tracing::trace_simple_print!("Hello world.");
    let mapper = Mapper::new(Arc::clone(tube), slot);
    while let Some(avail_desc) = queue.pop(mem) {
        let reader =
            Reader::new(mem.clone(), avail_desc.clone()).map_err(Error::InvalidDescriptorChain)?;
        let writer =
            Writer::new(mem.clone(), avail_desc.clone()).map_err(Error::InvalidDescriptorChain)?;

        let total = server.handle_message(reader, writer, &mapper)?;

        queue.add_used(mem, avail_desc.index, total as u32);
        queue.trigger_interrupt(mem, &*interrupt);
    }
```

Recompile and you will see your message show up like:

```
<...>-3803691 [006] ..... 2180094.296405: tracing_mark_write: Hello world.
```

So far so good, but to get the most out of it you might want to record how long the function takes
to run and some extra parameters. In that case you want to use `trace_event!()` instead:

```rust
pub fn process_fs_queue<I: SignalableInterrupt, F: FileSystem + Sync>(
    mem: &GuestMemory,
    interrupt: &I,
    queue: &mut Queue,
    server: &Arc<fuse::Server<F>>,
    tube: &Arc<Mutex<Tube>>,
    slot: u32,
) -> Result<()> {
    // Added trace event with slot
    let _trace = cros_tracing::trace_event!(VirtioFs, "process_fs_queue", slot);
    let mapper = Mapper::new(Arc::clone(tube), slot);
    while let Some(avail_desc) = queue.pop(mem) {
        let reader =
            Reader::new(mem.clone(), avail_desc.clone()).map_err(Error::InvalidDescriptorChain)?;
        let writer =
            Writer::new(mem.clone(), avail_desc.clone()).map_err(Error::InvalidDescriptorChain)?;

        let total = server.handle_message(reader, writer, &mapper)?;

        queue.add_used(mem, avail_desc.index, total as u32);
        queue.trigger_interrupt(mem, &*interrupt);
    }
```

Recompile and this will show up:

```
<...>-3805264 [017] ..... 2180567.774540: tracing_mark_write: 512 VirtioFs Enter: process_fs_queue - (slot: 0)
<...>-3805264 [017] ..... 2180567.774551: tracing_mark_write: 512 VirtioFs Exit: process_fs_queue
```

The number `512` in the log corresponds to a unique identifier for that event so it's easier to
trace which `Enter` corresponds to which `Exit`. Note how the value of `slot` also has been
recorded. To be able to output the state, the data type needs to support the `fmt::Debug` trait.

NOTE: The unique identifier for each event is unique only per-process. If the crosvm process forks
(like spawning new devices) then it is possible for two events from different processes to have the
same ID, in which case it's important to look at the recorded PID that emitted each event in the
trace.

The numbers like `2180567.774540` and `2180567.774551` in the example above are the timestamps for
that event, in `<sec>.<usec>` format. We can see that the `process_fs_queue` call took 11usec to
execute.

In this last example we used the `VirtioFs` category tag. If you want to add a new category tag to
`trace_marker`, it can be done by adding it to the the `setup_trace_marker!()` call in
`cros_tracing/src/trace_marker.rs`:

```rust
// List of categories that can be enabled.
setup_trace_marker!((VirtioFs, true), (NewCategory, true));
```

If the value is `false` then the events will not be traced. This can be useful when you just want to
trace a specific category and don't care about the rest, you can disable them in the code and
recompile crosvm.

NOTE: Trace events are compile-time to reduce runtime overhead in non-tracing builds so a lot of
changes require recompiling and re-deploying crosvm.
