# Style guide for platform specific code

## Code organization

The crosvm code can heavily interleave platform specific code into platform agnostic code using
`#[cfg(target_os = "")]`. This is difficult to maintain as

- It reduces readability.
- Difficult to write/maintain unit tests.
- Difficult to maintain downstream, proprietary code

To address the above mentioned issue, the style guide provides a way to standardize platform
specific code layout.

Consider a following example where we have platform independent code, `PrintInner`, which is used by
platform specific code, `WinPrinter` and `UnixPrinter` to tweak the behavior according to the
underlying platform. The users of this module, `sys`, get to use an aliased struct called `Printer`
which exports similar interfaces on both the platforms.

In this scheme `print.rs` contains platform agnostic logic, structures and traits. Different
platforms, in `unix.rs` and `windows.rs`, implement traits defined in `print.rs`. Finally `sys.rs`
exports interfaces implemented by platform specific code.

In a more complex library, we may need another layer, `print.rs`, that uses traits and structures
exported by platform specific code, `unix/print.rs` and `windows/print.rs`, and adds some more
common logic to it. Following example illustrates the scheme discussed above. Here,
`Printer.print()` is supposed to print a value of `u32` and print the target os name.

The files that contain platform specific code **only** should live in a directory named `sys/` and
those files should be conditionally imported in `sys.rs` file. In such a setup, the directory
structure would look like,

```bash
$  tree
.
├── print.rs
├── sys
│   ├── unix
│   │   └── print.rs
│   ├── unix.rs
│   ├── windows
│   │   └── print.rs
│   └── windows.rs
└── sys.rs
```

File: `print.rs`

```rust
pub struct PrintInner {
    pub value: u32,
}

impl PrintInner {
    pub fn new(value: u32) -> Self {
        Self { value }
    }

    pub fn print(&self) {
        print!("My value:{} ", self.value);
    }
}

// This is useful if you want to
// * Enforce interface consistency or
// * Have more than one compiled-in struct to provide the same api.
//   Say a generic gpu driver and high performance proprietary driver
//   to coexist in the same namespace.
pub trait Print {
    fn print(&self);
}
```

File: `sys/windows/print.rs`

```rust
use crate::print::{Print, PrintInner};

pub struct WinPrinter {
    inner: PrintInner,
}

impl WinPrinter {
    pub fn new(value: u32) -> Self {
        Self {
            inner: PrintInner::new(value),
        }
    }
}

impl Print for WinPrinter {
    fn print(&self) {
        self.inner.print();
        println!("from win");
    }
}
```

File: `sys/unix/print.rs`

```rust
use crate::print::{Print, PrintInner};

pub struct UnixPrinter {
    inner: PrintInner,
}

impl UnixPrinter {
    pub fn new(value: u32) -> Self {
        Self {
            inner: PrintInner::new(value),
        }
    }
}

impl Print for UnixPrinter {
    fn print(&self) {
        self.inner.print();
        println!("from unix");
    }
}
```

File: `sys.rs`

```rust
cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        pub use platform_print::UnixPrinter as Printer;
    } else if #[cfg(windows)] {
        mod windows;
        pub use platform_print::WinPrinter as Printer;
    }
}
```

## Imports

When conditionally importing and using modules, use `cfg(unix)` and `cfg(windows)` for describing
the platform. Order imports such that common comes first followed by unix and windows dependencies.

```rust
// All other imports

#[cfg(unix)]
use {
  std::x::y,
  base::a::b::{Foo, Bar},
  etc::Etc,
};

#[cfg(windows)]
use {
  std::d::b,
  base::f::{Foo, Bar},
  etc::{WinEtc as Etc},
};
```

## Structure

It is OK to have a few platform specific fields inlined with cfgs. When inlining

- Ensure that all the fields of a particular platform are next to each other.
- Organize common fields first and then platform specific fields ordered by the target os name i.e.
  "unix" first and "windows" later.

If the structure has a large set of fields that are platform specific, it is more readable to split
it into different platform specific structures and have their implementations separate. If
necessary, consider defining a crate in platform independent and have the platform specific files
implement parts of those traits.

## Enum

When enums need to have platform specific variants

- Create a new platform specific enum and move all platform specific variants under the new enum
- Introduce a new variant, which takes a platform specific enum as member, to platform independent
  enum.

### Do

File: `sys/unix/base.rs`

```rust
enum MyEnumSys {
  Unix1,
}

fn handle_my_enum_impl(e: MyEnumSys) {
  match e {
    Unix1 => {..},
  };
}
```

File: `sys/windows/base.rs`

```rust
enum MyEnumSys {
  Windows1,
}

fn handle_my_enum_impl(e: MyEnumSys) {
  match e {
    Windows1 => {..},
  };
}
```

File: `base.rs`

```rust
use sys::MyEnumSys;
enum MyEnum {
  Common1,
  Common2,
  SysVariants(MyEnumSys),
}

fn handle_my_enum(e: MyEnum) {
  match e {
    Common1 => {..},
    Common2 => {..},
    SysVariants(v) => handle_my_enum_impl(v),
  };
}
```

### Don't

File: `base.rs`

```rust
enum MyEnum {
  Common1,
  Common2,
  #[cfg(target_os = "windows")]
  Windows1, // We shouldn't have platform-specific variants in a platform-independent enum.
  #[cfg(target_os = "unix")]
  Unix1, // We shouldn't have platform-specific variants in a platform-independent enum.
}

fn handle_my_enum(e: MyEnum) {
  match e {
    Common1 => {..},
    Common2 => {..},
    #[cfg(target_os = "windows")]
    Windows1 => {..}, // We shouldn't have platform-specific match arms in a platform-independent code.
    #[cfg(target_os = "unix")]
    Unix1 => {..}, // We shouldn't have platform-specific match arms in a platform-independent code.
  };
}
```

## Code blocks and functions

If a code block or a function has little platform independent code and the bulk of the code is
platform specific then carve out platform specific code into a function. If the carved out function
does most of what the original function was doing and there is no better name for the new function
then the new function can be named by appending `_impl` to the functions name.

### Do

File: `base.rs`

```rust
fn my_func() {
  print!("Hello ");
  my_func_impl();
}
```

File: `sys/unix/base.rs`

```rust
fn my_func_impl() {
  println!("unix");
}
```

File: `sys/windows/base.rs`

```rust
fn my_func_impl() {
  println!("windows");
}
```

### Don't

File: `base.rs`

```rust
fn my_func() {
  print!("Hello ");

  #[cfg(target_os = "unix")] {
    println!("unix"); // We shouldn't have platform-specific code in a platform-independent code block.
  }

  #[cfg(target_os = "windows")] {
    println!("windows"); // We shouldn't have platform-specific code in a platform-independent code block.
  }
}
```

## match

With an exception to matching enums, see [enum](#enum), matching for platform specific values can be
done in the wildcard patter(`_`) arm of the match statement.

### Do

File: `parse.rs`

```rust
fn parse_args(arg: &str) -> Result<()>{
  match arg {
    "path" => {
      <multiple lines of logic>;
      Ok(())
    },
    _ => parse_args_impl(arg),
  }
}
```

File: `sys/unix/parse.rs`

```rust
fn parse_args_impl(arg: &str) -> Result<()>{
  match arg {
    "fd" => {
      <multiple lines of logic>;
      Ok(())
    },
    _ => Err(ParseError),
  }
}
```

File: `sys/windows/parse.rs`

```rust
fn parse_args_impl(arg: &str) -> Result<()>{
  match arg {
    "handle" => {
      <multiple lines of logic>;
      Ok(())
    },
    _ => Err(ParseError),
  }
}
```

### Don't

File: `parse.rs`

```rust
fn parse_args(arg: &str) -> Result<()>{
  match arg {
    "path" => Ok(()),
    #[cfg(target_os = "unix")]
    "fd" => { // We shouldn't have platform-specific match arms in a platform-independent code.
      <multiple lines of logic>;
      Ok(())
    },
    #[cfg(target_os = "windows")]
    "handle" => { // We shouldn't have platform-specific match arms in a platform-independent code.
      <multiple lines of logic>;
      Ok(())
    },
    _ => Err(ParseError),
  }
}
```

## Errors

Inlining all platform specific error values is ok. This is an exception to the [enum](#enum) to keep
error handling simple. Organize platform independent errors first and then platform specific errors
ordered by the target os name i.e. "unix" first and "windows" later.

## Platform specific symbols

If a platform exports symbols that are specific to the platform only and are not exported by all
other platforms then those symbols should be made public through a namespace that reflects the name
of the platform.

File: `sys.rs`

```rust
cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub mod unix;
        use unix as platform;
    } else if #[cfg(windows)] {
        pub mod windows;
        use windows as platform;
    }
}

pub use platform::print;
```

File: `unix.rs`

```rust
fn print() {
  println!("Hello unix");
}

fn print_u8(val: u8) {
  println!("Unix u8:{}", val);

}
```

File: `windows.rs`

```rust
fn print() {
  println!("Hello windows");
}

fn print_u16(val: u16) {
  println!("Windows u16:{}", val);

}
```

The user of the library, say mylib, now has to do something like below which makes it explicit that
the functions `print_u8` and `print_u16` are platform specific.

```rust
use mylib::sys::print;

fn my_print() {
  print();

  #[cfg(unix)]
  mylib::sys::unix::print_u8(1);

  #[cfg(windows)]
  mylib::sys::windows::print_u16(1);
}

```
