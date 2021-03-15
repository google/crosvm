// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles argument parsing.
//!
//! # Example
//!
//! ```
//! # use crosvm::argument::{Argument, Error, print_help, set_arguments};
//! # let args: std::slice::Iter<String> = [].iter();
//! let arguments = &[
//!     Argument::positional("FILES", "files to operate on"),
//!     Argument::short_value('p', "program", "PROGRAM", "Program to apply to each file"),
//!     Argument::short_value('c', "cpus", "N", "Number of CPUs to use. (default: 1)"),
//!     Argument::flag("unmount", "Unmount the root"),
//!     Argument::short_flag('h', "help", "Print help message."),
//! ];
//!
//! let match_res = set_arguments(args, arguments, |name, value| {
//!     match name {
//!         "" => println!("positional arg! {}", value.unwrap()),
//!         "program" => println!("gonna use program {}", value.unwrap()),
//!         "cpus" => {
//!             let v: u32 = value.unwrap().parse().map_err(|_| {
//!                 Error::InvalidValue {
//!                     value: value.unwrap().to_owned(),
//!                     expected: String::from("this value for `cpus` needs to be integer"),
//!                 }
//!             })?;
//!         }
//!         "unmount" => println!("gonna unmount"),
//!         "help" => return Err(Error::PrintHelp),
//!         _ => unreachable!(),
//!     }
//!     unreachable!();
//! });
//!
//! match match_res {
//!     Ok(_) => println!("running with settings"),
//!     Err(Error::PrintHelp) => print_help("best_program", "FILES", arguments),
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
    /// The argument's name is unused.
    UnknownArgument(String),
    /// The argument was required.
    ExpectedArgument(String),
    /// The argument's given value is invalid.
    InvalidValue { value: String, expected: String },
    /// The argument was already given and none more are expected.
    TooManyArguments(String),
    /// The argument expects a value.
    ExpectedValue(String),
    /// The argument does not expect a value.
    UnexpectedValue(String),
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
            UnexpectedValue(s) => write!(f, "unexpected parameter value: {}", s),
            PrintHelp => write!(f, "help was requested"),
        }
    }
}

/// Result of a argument parsing.
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum ArgumentValueMode {
    /// Specifies that an argument requires a value and that an error should be generated if
    /// no value is provided during parsing.
    Required,

    /// Specifies that an argument does not allow a value and that an error should be returned
    /// if a value is provided during parsing.
    Disallowed,

    /// Specifies that an argument may have a value during parsing but is not required to.
    Optional,
}

/// Information about an argument expected from the command line.
///
/// # Examples
///
/// To indicate a flag style argument:
///
/// ```
/// # use crosvm::argument::Argument;
/// Argument::short_flag('f', "flag", "enable awesome mode");
/// ```
///
/// To indicate a parameter style argument that expects a value:
///
/// ```
/// # use crosvm::argument::Argument;
/// // "VALUE" and "NETMASK" are placeholder values displayed in the help message for these
/// // arguments.
/// Argument::short_value('v', "val", "VALUE", "how much do you value this usage information");
/// Argument::value("netmask", "NETMASK", "hides your netface");
/// ```
///
/// To indicate an argument with no short version:
///
/// ```
/// # use crosvm::argument::Argument;
/// Argument::flag("verbose", "this option is hard to type quickly");
/// ```
///
/// To indicate a positional argument:
///
/// ```
/// # use crosvm::argument::Argument;
/// Argument::positional("VALUES", "these are positional arguments");
/// ```
pub struct Argument {
    /// The name of the value to display in the usage information.
    pub value: Option<&'static str>,
    /// Specifies how values should be handled for this this argument.
    pub value_mode: ArgumentValueMode,
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
            value_mode: ArgumentValueMode::Required,
            short: None,
            long: "",
            help,
        }
    }

    pub fn value(long: &'static str, value: &'static str, help: &'static str) -> Argument {
        Argument {
            value: Some(value),
            value_mode: ArgumentValueMode::Required,
            short: None,
            long,
            help,
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
            value_mode: ArgumentValueMode::Required,
            short: Some(short),
            long,
            help,
        }
    }

    pub fn flag(long: &'static str, help: &'static str) -> Argument {
        Argument {
            value: None,
            value_mode: ArgumentValueMode::Disallowed,
            short: None,
            long,
            help,
        }
    }

    pub fn short_flag(short: char, long: &'static str, help: &'static str) -> Argument {
        Argument {
            value: None,
            value_mode: ArgumentValueMode::Disallowed,
            short: Some(short),
            long,
            help,
        }
    }

    pub fn flag_or_value(long: &'static str, value: &'static str, help: &'static str) -> Argument {
        Argument {
            value: Some(value),
            value_mode: ArgumentValueMode::Optional,
            short: None,
            long,
            help,
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
        loop {
            let mut arg_consumed = true;
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
                        } else {
                            State::Value {
                                name: param.to_owned(),
                            }
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
                    if arg.starts_with('-') {
                        arg_consumed = false;
                        f(&name, None)?;
                    } else if let Err(e) = f(&name, Some(&arg)) {
                        arg_consumed = false;
                        f(&name, None).map_err(|_| e)?;
                    }
                    State::Top
                }
            };

            if arg_consumed {
                break;
            }
        }
    }

    // If we ran out of arguments while parsing the last parameter, which may be either a
    // value parameter or a flag, try to parse it as a flag. This will produce "missing value"
    // error if the parameter is in fact a value parameter, which is the desired outcome.
    match s {
        State::Value { name } => f(&name, None),
        _ => Ok(()),
    }
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
                if value.is_none() && arg.value_mode == ArgumentValueMode::Required {
                    return Err(Error::ExpectedValue(arg.long.to_owned()));
                }
                if value.is_some() && arg.value_mode == ArgumentValueMode::Disallowed {
                    return Err(Error::UnexpectedValue(arg.long.to_owned()));
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
/// The usage line is of the format "`program_name` \[ARGUMENTS\] `required_arg`".
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
                            expected: String::from("this value for `cpus` needs to be integer"),
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
        let not_match_res = set_arguments(
            ["-c", "5", "--cpus"].iter(),
            &arguments[..],
            |name, value| {
                assert_eq!(name, "cpus");
                assert_eq!(value, Some("5"));
                Ok(())
            },
        );
        assert!(not_match_res.is_err());
    }

    #[test]
    fn flag_or_value() {
        let run_case = |args| -> Option<String> {
            let arguments = [
                Argument::positional("FILES", "files to operate on"),
                Argument::flag_or_value("gpu", "[2D|3D]", "Enable or configure gpu"),
                Argument::flag("foo", "Enable foo."),
                Argument::value("bar", "stuff", "Configure bar."),
            ];

            let mut gpu_value: Option<String> = None;
            let match_res =
                set_arguments(args, &arguments[..], |name: &str, value: Option<&str>| {
                    match name {
                        "" => assert_eq!(value.unwrap(), "file1"),
                        "foo" => assert!(value.is_none()),
                        "bar" => assert_eq!(value.unwrap(), "stuff"),
                        "gpu" => match value {
                            Some(v) => match v {
                                "2D" | "3D" => {
                                    gpu_value = Some(v.to_string());
                                }
                                _ => {
                                    return Err(Error::InvalidValue {
                                        value: v.to_string(),
                                        expected: String::from("2D or 3D"),
                                    })
                                }
                            },
                            None => {
                                gpu_value = None;
                            }
                        },
                        _ => unreachable!(),
                    };
                    Ok(())
                });

            assert!(match_res.is_ok());
            gpu_value
        };

        // Used as flag and followed by positional
        assert_eq!(run_case(["--gpu", "file1"].iter()), None);
        // Used as flag and followed by flag
        assert_eq!(run_case(["--gpu", "--foo", "file1",].iter()), None);
        // Used as flag and followed by value
        assert_eq!(run_case(["--gpu", "--bar=stuff", "file1"].iter()), None);

        // Used as value and followed by positional
        assert_eq!(run_case(["--gpu=2D", "file1"].iter()).unwrap(), "2D");
        // Used as value and followed by flag
        assert_eq!(run_case(["--gpu=2D", "--foo"].iter()).unwrap(), "2D");
        // Used as value and followed by value
        assert_eq!(
            run_case(["--gpu=2D", "--bar=stuff", "file1"].iter()).unwrap(),
            "2D"
        );
    }
}
