This is a small baremetal x86_64 application that can be booted with crosvm. You can simply do
`cargo run` and it'll build it and use crosvm from `PATH` to launch it. Alternatively you can build
it with `cargo build` and run with
`crosvm run --disable-sandbox path/to/target/x86_64-naked/debug/baremetal`

The application does nothing but output `Hello World!` log line over serial port and go into
infinite loop. This is expected and you'll need to kill crosvm to stop it.
