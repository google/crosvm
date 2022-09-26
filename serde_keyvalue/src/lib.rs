// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A lightweight serde deserializer for strings containing key-value pairs separated by commas, as
//! commonly found in command-line parameters.
//!
//! Say your program takes a command-line option of the form:
//!
//! ```text
//! --foo type=bar,active,nb_threads=8
//! ```
//!
//! This crate provides a [from_key_values] function that deserializes these key-values into a
//! configuration structure. Since it uses serde, the same configuration structure can also be
//! created from any other supported source (such as a TOML or YAML configuration file) that uses
//! the same keys.
//!
//! Integration with the [argh](https://github.com/google/argh) command-line parser is also
//! provided via the `argh_derive` feature.
//!
//! The deserializer supports parsing signed and unsigned integers, booleans, strings (quoted or
//! not), paths, and enums inside a top-level struct. The order in which the fields appear in the
//! string is not important.
//!
//! Simple example:
//!
//! ```
//! use serde_keyvalue::from_key_values;
//! use serde::Deserialize;
//!
//! #[derive(Debug, PartialEq, Deserialize)]
//! struct Config {
//!     path: String,
//!     threads: u8,
//!     active: bool,
//! }
//!
//! let config: Config = from_key_values("path=/some/path,threads=16,active=true").unwrap();
//! assert_eq!(config, Config { path: "/some/path".into(), threads: 16, active: true });
//!
//! let config: Config = from_key_values("threads=16,active=true,path=/some/path").unwrap();
//! assert_eq!(config, Config { path: "/some/path".into(), threads: 16, active: true });
//! ```
//!
//! As a convenience the name of the first field of a struct can be omitted:
//!
//! ```
//! # use serde_keyvalue::from_key_values;
//! # use serde::Deserialize;
//! #[derive(Debug, PartialEq, Deserialize)]
//! struct Config {
//!     path: String,
//!     threads: u8,
//!     active: bool,
//! }
//!
//! let config: Config = from_key_values("/some/path,threads=16,active=true").unwrap();
//! assert_eq!(config, Config { path: "/some/path".into(), threads: 16, active: true });
//! ```
//!
//! Fields that are behind an `Option` can be omitted, in which case they will be `None`.
//!
//! ```
//! # use serde_keyvalue::from_key_values;
//! # use serde::Deserialize;
//! #[derive(Debug, PartialEq, Deserialize)]
//! struct Config {
//!     path: Option<String>,
//!     threads: u8,
//!     active: bool,
//! }
//!
//! let config: Config = from_key_values("path=/some/path,threads=16,active=true").unwrap();
//! assert_eq!(config, Config { path: Some("/some/path".into()), threads: 16, active: true });
//!
//! let config: Config = from_key_values("threads=16,active=true").unwrap();
//! assert_eq!(config, Config { path: None, threads: 16, active: true });
//! ```
//!
//! Alternatively, the serde `default` attribute can be used on select fields or on the whole
//! struct to make unspecified fields be assigned their default value. In the following example only
//! the `path` parameter must be specified.
//!
//! ```
//! # use serde_keyvalue::from_key_values;
//! # use serde::Deserialize;
//! #[derive(Debug, PartialEq, Deserialize)]
//! struct Config {
//!     path: String,
//!     #[serde(default)]
//!     threads: u8,
//!     #[serde(default)]
//!     active: bool,
//! }
//!
//! let config: Config = from_key_values("path=/some/path").unwrap();
//! assert_eq!(config, Config { path: "/some/path".into(), threads: 0, active: false });
//! ```
//!
//! A function providing a default value can also be specified, see the [serde documentation for
//! field attributes](https://serde.rs/field-attrs.html) for details.
//!
//! Booleans can be `true` or `false`, or take no value at all, in which case they will be `true`.
//! Combined with default values this allows to implement flags very easily:
//!
//! ```
//! # use serde_keyvalue::from_key_values;
//! # use serde::Deserialize;
//! #[derive(Debug, Default, PartialEq, Deserialize)]
//! #[serde(default)]
//! struct Config {
//!     active: bool,
//!     delayed: bool,
//!     pooled: bool,
//! }
//!
//! let config: Config = from_key_values("active=true,delayed=false,pooled=true").unwrap();
//! assert_eq!(config, Config { active: true, delayed: false, pooled: true });
//!
//! let config: Config = from_key_values("active,pooled").unwrap();
//! assert_eq!(config, Config { active: true, delayed: false, pooled: true });
//! ```
//!
//! Strings can be quoted, which is useful if they e.g. need to include a comma. Quoted strings can
//! also contain escaped characters, where any character after a `\` is repeated as-is:
//!
//! ```
//! # use serde_keyvalue::from_key_values;
//! # use serde::Deserialize;
//! #[derive(Debug, PartialEq, Deserialize)]
//! struct Config {
//!     path: String,
//! }
//!
//! let config: Config = from_key_values(r#"path="/some/\"strange\"/pa,th""#).unwrap();
//! assert_eq!(config, Config { path: r#"/some/"strange"/pa,th"#.into() });
//! ```
//!
//! Enums can be directly specified by name. It is recommended to use the `rename_all` serde
//! container attribute to make them parseable using snake or kebab case representation. Serde's
//! `rename` and `alias` field attributes can also be used to provide shorter values:
//!
//! ```
//! # use serde_keyvalue::from_key_values;
//! # use serde::Deserialize;
//! #[derive(Debug, PartialEq, Deserialize)]
//! #[serde(rename_all="kebab-case")]
//! enum Mode {
//!     Slow,
//!     Fast,
//!     #[serde(rename="ludicrous")]
//!     LudicrousSpeed,
//! }
//!
//! #[derive(Deserialize, PartialEq, Debug)]
//! struct Config {
//!     mode: Mode,
//! }
//!
//! let config: Config = from_key_values("mode=slow").unwrap();
//! assert_eq!(config, Config { mode: Mode::Slow });
//!
//! let config: Config = from_key_values("mode=ludicrous").unwrap();
//! assert_eq!(config, Config { mode: Mode::LudicrousSpeed });
//! ```
//!
//! Enums taking a single value should use the `flatten` field attribute in order to be inferred
//! from their variant key directly:
//!
//! ```
//! # use serde_keyvalue::from_key_values;
//! # use serde::Deserialize;
//! #[derive(Debug, PartialEq, Deserialize)]
//! #[serde(rename_all="kebab-case")]
//! enum Mode {
//!     // Work with a local file.
//!     File(String),
//!     // Work with a remote URL.
//!     Url(String),
//! }
//!
//! #[derive(Deserialize, PartialEq, Debug)]
//! struct Config {
//!     #[serde(flatten)]
//!     mode: Mode,
//! }
//!
//! let config: Config = from_key_values("file=/some/path").unwrap();
//! assert_eq!(config, Config { mode: Mode::File("/some/path".into()) });
//!
//! let config: Config = from_key_values("url=https://www.google.com").unwrap();
//! assert_eq!(config, Config { mode: Mode::Url("https://www.google.com".into()) });
//! ```
//!
//! The `flatten` attribute can also be used to embed one struct within another one and parse both
//! from the same string:
//!
//! ```
//! # use serde_keyvalue::from_key_values;
//! # use serde::Deserialize;
//! #[derive(Debug, PartialEq, Deserialize)]
//! struct BaseConfig {
//!     enabled: bool,
//!     num_threads: u8,
//! }
//!
//! #[derive(Debug, PartialEq, Deserialize)]
//! struct Config {
//!     #[serde(flatten)]
//!     base: BaseConfig,
//!     path: String,
//! }
//!
//! let config: Config = from_key_values("path=/some/path,enabled,num_threads=16").unwrap();
//! assert_eq!(
//!     config,
//!     Config {
//!         path: "/some/path".into(),
//!         base: BaseConfig {
//!             num_threads: 16,
//!             enabled: true,
//!         }
//!     }
//! );
//! ```
//!
//! If an enum's variants are made of structs, it should take the `untagged` container attribute so
//! it can be inferred directly from the fields of the embedded structs:
//!
//! ```
//! # use serde_keyvalue::from_key_values;
//! # use serde::Deserialize;
//! #[derive(Debug, PartialEq, Deserialize)]
//! #[serde(untagged)]
//! enum Mode {
//!     // Work with a local file.
//!     File {
//!         path: String,
//!         #[serde(default)]
//!         read_only: bool,
//!     },
//!     // Work with a remote URL.
//!     Remote {
//!         server: String,
//!         port: u16,
//!     }
//! }
//!
//! #[derive(Debug, PartialEq, Deserialize)]
//! struct Config {
//!     #[serde(flatten)]
//!     mode: Mode,
//! }
//!
//! let config: Config = from_key_values("path=/some/path").unwrap();
//! assert_eq!(config, Config { mode: Mode::File { path: "/some/path".into(), read_only: false } });
//!
//! let config: Config = from_key_values("server=google.com,port=80").unwrap();
//! assert_eq!(config, Config { mode: Mode::Remote { server: "google.com".into(), port: 80 } });
//! ```
//!
//! Using this crate, parsing errors and invalid or missing fields are precisely reported:
//!
//! ```
//! # use serde_keyvalue::from_key_values;
//! # use serde::Deserialize;
//! #[derive(Debug, PartialEq, Deserialize)]
//! struct Config {
//!     path: String,
//!     threads: u8,
//!     active: bool,
//! }
//!
//! let config = from_key_values::<Config>("path=/some/path,active=true").unwrap_err();
//! assert_eq!(format!("{}", config), "missing field `threads`");
//! ```
//!
//! Most of the serde [container](https://serde.rs/container-attrs.html) and
//! [field](https://serde.rs/field-attrs.html) attributes can be applied to your configuration
//! struct. Most useful ones include
//! [`deny_unknown_fields`](https://serde.rs/container-attrs.html#deny_unknown_fields) to report an
//! error if an unknown field is met in the input, and
//! [`deserialize_with`](https://serde.rs/field-attrs.html#deserialize_with) to use a custom
//! deserialization function for a specific field.
//!
//! Be aware that the use of `flatten` comes with some severe limitations. Because type information
//! is not available to the deserializer, it will try to determine the type of fields using the
//! input as its sole hint. For instance, any number will be returned as an integer type, and if the
//! parsed structure was actually expecting a number as a string, then an error will occur.
//!
//! For this reason it is discouraged to use `flatten` except when neither the embedding not the
//! flattened structs has a member of string type.
//!
//! Most of the time, similar functionality can be obtained by implementing a custom deserializer
//! that parses the embedding struct's member and then the flattened struct in a specific order
//! using the [`key_values::KeyValueDeserializer`] interface directly.
//!
//! Another limitation of using `flatten` that is inherent to serde is that it won't allow
//! `deny_unknown_fields` to be used in either the embedding or the flattened struct.
#![deny(missing_docs)]

mod key_values;

#[cfg(feature = "argh_derive")]
pub use argh;
pub use key_values::from_key_values;
pub use key_values::ErrorKind;
pub use key_values::KeyValueDeserializer;
pub use key_values::ParseError;
#[cfg(feature = "argh_derive")]
pub use serde_keyvalue_derive::FromKeyValues;
