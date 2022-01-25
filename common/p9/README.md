# p9 - Server implementation of the [9p] file system protocol

This directory contains the protocol definition and a server implementation of the [9p] file system
protocol.

- [wire_format_derive] - A [procedural macro] that derives the serialization and de-serialization
  implementation for a struct into the [9p] wire format.
- [src/protocol] - Defines all the messages used in the [9p] protocol. Also implements serialization
  and de-serialization for some base types (integers, strings, vectors) that form the foundation of
  all [9p] messages. Wire format implementations for all other messages are derived using the
  `wire_format_derive` macro.
- [src/server.rs] - Implements a full [9p] server, carrying out file system requests on behalf of
  clients.

[9p]: http://man.cat-v.org/plan_9/5/intro
[procedural macro]: https://doc.rust-lang.org/proc_macro/index.html
[src/protocol]: src/protocol/
[src/server.rs]: src/server.rs
[wire_format_derive]: wire_format_derive/
