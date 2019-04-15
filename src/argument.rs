// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles argument parsing.
//!
//! # Example
//!
//! ```
//! const ARGUMENTS: &'static [Argument] = &[
//!     Argument::positional("FILES", "files to operate on"),
//!     Argument::short_value('p', "program", "PROGRAM", "Program to apply to each file"),
//!     Argument::short_value('c', "cpus", "N", "Number of CPUs to use. (default: 1)"),
//!     Argument::flag("unmount", "Unmount the root"),
//!     Argument::short_flag('h', "help", "Print help message."),
//! ];
//!
//! let match_res = set_arguments(args, ARGUMENTS, |name, value| {
//!     match name {
//!         "" => println!("positional arg! {}", value.unwrap()),
//!         "program" => println!("gonna use program {}", value.unwrap()),
//!         "cpus" => {
//!             let v: u32 = value.unwrap().parse().map_err(|_| {
//!                 Error::InvalidValue {
//!                     value: value.unwrap().to_owned(),
//!                     expected: "this value for `cpus` needs to be integer",
//!                 }
//!             })?;
//!         }
//!         "unmount" => println!("gonna unmount"),
//!         "help" => return Err(Error::PrintHelp),
//!         _ => unreachable!(),
//!     }
//! }
//!
//! match match_res {
//!     Ok(_) => println!("running with settings"),
//!     Err(Error::PrintHelp) => print_help("best_program", "FILES", ARGUMENTS),
//!     Err(e) => println!("{}", e),
//! }
//! ```

use std::fmt::{self, Display};
use std::result;

/// An error with argument parsing.
#[derive(Debug)]
pub enum Error {
    /// There was a syntax error with the argument.
    Syntax(String),
    /// The argumen's name is unused.
    UnknownArgument(String),
    /// The argument was required.
    ExpectedArgument(String),
    /// The argument's given value is invalid.
    InvalidValue {
        value: String,
        expected: &'static str,
    },
    /// The argument was already given and none more are expected.
    TooManyArguments(String),
    /// The argument expects a value.
    ExpectedValue(String),
    /// The help information was requested
    PrintHelp,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            Syntax(s) => write!(f, "syntax error: {}", s),
            UnknownArgument(s) => write!(f, "unknown argument: {}", s),
            ExpectedArgument(s) => write!(f, "expected argument: {}", s),
            InvalidValue { value, expected } => {
                write!(f, "invalid value {:?}: {}", value, expected)
            }
            TooManyArguments(s) => write!(f, "too many arguments: {}", s),
            ExpectedValue(s) => write!(f, "expected parameter value: {}", s),
            PrintHelp => write!(f, "help was requested"),
        }
    }
}

/// Result of a argument parsing.
pub type Result<T> = result::Result<T, Error>;

/// Information about an argument expected from the command line.
///
/// # Examples
///
/// To indicate a flag style argument:
///
/// ```
/// Argument::short_flag('f', "flag", "enable awesome mode")
/// ```
///
/// To indicate a parameter style argument that expects a value:
///
/// ```
/// // "VALUE" and "NETMASK" are placeholder values displayed in the help message for these
/// // arguments.
/// Argument::short_value('v', "val", "VALUE", "how much do you value this usage information")
/// Argument::value("netmask", "NETMASK", "hides your netface")
/// ```
///
/// To indicate an argument with no short version:
///
/// ```
/// Argument::flag("verbose", "this option is hard to type quickly")
/// ```
///
/// To indicate a positional argument:
///
/// ```
/// Argument::positional("VALUES", "these are positional arguments")
/// ```
#[derive(Default)]
pub struct Argument {
    /// The name of the value to display in the usage information. Use None to indicate that there
    /// is no value expected for this argument.
    pub value: Option<&'static str>,
    /// Optional single character shortened argument name.
    pub short: Option<char>,
    /// The long name of this argument.
    pub long: &'static str,
    /// Helpfuly usage information for this argument to display to the user.
    pub help: &'static str,
}

impl Argument {
    pub fn positional(value: &'static str, help: &'static str) -> Argument {
        Argument {
            value: Some(value),
            long: "",
            help,
            ..Default::default()
        }
    }

    pub fn value(long: &'static str, value: &'static str, help: &'static str) -> Argument {
        Argument {
            value: Some(value),
            long,
            help,
            ..Default::default()
        }
    }

    pub fn short_value(
        short: char,
        long: &'static str,
        value: &'static str,
        help: &'static str,
    ) -> Argument {
        Argument {
            value: Some(value),
            short: Some(short),
            long,
            help,
        }
    }

    pub fn flag(long: &'static str, help: &'static str) -> Argument {
        Argument {
            long,
            help,
            ..Default::default()
        }
    }

    pub fn short_flag(short: char, long: &'static str, help: &'static str) -> Argument {
        Argument {
            short: Some(short),
            long,
            help,
            ..Default::default()
        }
    }
}

fn parse_arguments<I, R, F>(args: I, mut f: F) -> Result<()>
where
    I: Iterator<Item = R>,
    R: AsRef<str>,
    F: FnMut(&str, Option<&str>) -> Result<()>,
{
    enum State {
        // Initial state at the start and after finishing a single argument/value.
        Top,
        // The remaining arguments are all positional.
        Positional,
        // The next string is the value for the argument `name`.
        Value { name: String },
    }
    let mut s = State::Top;
    for arg in args {
        let arg = arg.as_ref();
        s = match s {
            State::Top => {
                if arg == "--" {
                    State::Positional
                } else if arg.starts_with("--") {
                    let param = arg.trim_start_matches('-');
                    if param.contains('=') {
                        let mut iter = param.splitn(2, '=');
                        let name = iter.next().unwrap();
                        let value = iter.next().unwrap();
                        if name.is_empty() {
                            return Err(Error::Syntax(
                                "expected parameter name before `=`".to_owned(),
                            ));
                        }
                        if value.is_empty() {
                            return Err(Error::Syntax(
                                "expected parameter value after `=`".to_owned(),
                            ));
                        }
                        f(name, Some(value))?;
                        State::Top
                    } else if let Err(e) = f(param, None) {
                        if let Error::ExpectedValue(_) = e {
                            State::Value {
                                name: param.to_owned(),
                            }
                        } else {
                            return Err(e);
                        }
                    } else {
                        State::Top
                    }
                } else if arg.starts_with('-') {
                    if arg.len() == 1 {
                        return Err(Error::Syntax(
                            "expected argument short name after `-`".to_owned(),
                        ));
                    }
                    let name = &arg[1..2];
                    let value = if arg.len() > 2 { Some(&arg[2..]) } else { None };
                    if let Err(e) = f(name, value) {
                        if let Error::ExpectedValue(_) = e {
                            State::Value {
                                name: name.to_owned(),
                            }
                        } else {
                            return Err(e);
                        }
                    } else {
                        State::Top
                    }
                } else {
                    f("", Some(&arg))?;
                    State::Positional
                }
            }
            State::Positional => {
                f("", Some(&arg))?;
                State::Positional
            }
            State::Value { name } => {
                f(&name, Some(&arg))?;
                State::Top
            }
        };
    }
    Ok(())
}

/// Parses the given `args` against the list of know arguments `arg_list` and calls `f` with each
/// present argument and value if required.
///
/// This function guarantees that only valid long argument names from `arg_list` are sent to the
/// callback `f`. It is also guaranteed that if an arg requires a value (i.e.
/// `arg.value.is_some()`), the value will be `Some` in the callbacks arguments. If the callback
/// returns `Err`, this function will end parsing and return that `Err`.
///
/// See the [module level](index.html) example for a usage example.
pub fn set_arguments<I, R, F>(args: I, arg_list: &[Argument], mut f: F) -> Result<()>
where
    I: Iterator<Item = R>,
    R: AsRef<str>,
    F: FnMut(&str, Option<&str>) -> Result<()>,
{
    parse_arguments(args, |name, value| {
        let mut matches = None;
        for arg in arg_list {
            if let Some(short) = arg.short {
                if name.len() == 1 && name.starts_with(short) {
                    if value.is_some() != arg.value.is_some() {
                        return Err(Error::ExpectedValue(short.to_string()));
                    }
                    matches = Some(arg.long);
                }
            }
            if matches.is_none() && arg.long == name {
                if value.is_some() != arg.value.is_some() {
                    return Err(Error::ExpectedValue(arg.long.to_owned()));
                }
                matches = Some(arg.long);
            }
        }
        match matches {
            Some(long) => f(long, value),
            None => Err(Error::UnknownArgument(name.to_owned())),
        }
    })
}

/// Prints command line usage information to stdout.
///
/// Usage information is printed according to the help fields in `args` with a leading usage line.
/// The usage line is of the format "`program_name` [ARGUMENTS] `required_arg`".
pub fn print_help(program_name: &str, required_arg: &str, args: &[Argument]) {
    println!(
        "Usage: {} {}{}\n",
        program_name,
        if args.is_empty() { "" } else { "[ARGUMENTS] " },
        required_arg
    );
    if args.is_empty() {
        return;
    }
    println!("Argument{}:", if args.len() > 1 { "s" } else { "" });
    for arg in args {
        match arg.short {
            Some(s) => print!(" -{}, ", s),
            None => print!("     "),
        }
        if arg.long.is_empty() {
            print!("  ");
        } else {
            print!("--");
        }
        print!("{:<12}", arg.long);
        if let Some(v) = arg.value {
            if arg.long.is_empty() {
                print!(" ");
            } else {
                print!("=");
            }
            print!("{:<10}", v);
        } else {
            print!("{:<11}", "");
        }
        println!("{}", arg.help);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_help() {
        let arguments = [Argument::short_flag('h', "help", "Print help message.")];

        let match_res = set_arguments(["-h"].iter(), &arguments[..], |name, _| {
            match name {
                "help" => return Err(Error::PrintHelp),
                _ => unreachable!(),
            };
        });
        match match_res {
            Err(Error::PrintHelp) => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn mixed_args() {
        let arguments = [
            Argument::positional("FILES", "files to operate on"),
            Argument::short_value('p', "program", "PROGRAM", "Program to apply to each file"),
            Argument::short_value('c', "cpus", "N", "Number of CPUs to use. (default: 1)"),
            Argument::flag("unmount", "Unmount the root"),
            Argument::short_flag('h', "help", "Print help message."),
        ];

        let mut unmount = false;
        let match_res = set_arguments(
            ["--cpus", "3", "--program", "hello", "--unmount", "file"].iter(),
            &arguments[..],
            |name, value| {
                match name {
                    "" => assert_eq!(value.unwrap(), "file"),
                    "program" => assert_eq!(value.unwrap(), "hello"),
                    "cpus" => {
                        let c: u32 = value.unwrap().parse().map_err(|_| Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: "this value for `cpus` needs to be integer",
                        })?;
                        assert_eq!(c, 3);
                    }
                    "unmount" => unmount = true,
                    "help" => return Err(Error::PrintHelp),
                    _ => unreachable!(),
                };
                Ok(())
            },
        );
        assert!(match_res.is_ok());
        assert!(unmount);
    }

    #[test]
    fn name_value_pair() {
        let arguments = [Argument::short_value(
            'c',
            "cpus",
            "N",
            "Number of CPUs to use. (default: 1)",
        )];
        let match_res = set_arguments(
            ["-c", "5", "--cpus", "5", "-c5", "--cpus=5"].iter(),
            &arguments[..],
            |name, value| {
                assert_eq!(name, "cpus");
                assert_eq!(value, Some("5"));
                Ok(())
            },
        );
        assert!(match_res.is_ok());
    }
}
