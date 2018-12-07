// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Runs a [9P] server.
///
/// [9P]: http://man.cat-v.org/plan_9/5/0intro
extern crate assertions;
extern crate getopts;
extern crate libc;
extern crate p9;
#[macro_use]
extern crate sys_util;

mod vsock;

use std::fmt;
use std::io::{self, BufReader, BufWriter};
use std::net;
use std::num::ParseIntError;
use std::os::raw::c_uint;
use std::result;
use std::str::FromStr;
use std::string;
use std::sync::Arc;
use std::thread;

use sys_util::syslog;

use vsock::*;

const DEFAULT_BUFFER_SIZE: usize = 8192;

// Address family identifiers.
const VSOCK: &'static str = "vsock:";
const UNIX: &'static str = "unix:";

// Usage for this program.
const USAGE: &'static str = "9s [options] {vsock:<port>|unix:<path>|<ip>:<port>}";

enum ListenAddress {
    Net(net::SocketAddr),
    Unix(String),
    Vsock(c_uint),
}

#[derive(Debug)]
enum ParseAddressError {
    MissingUnixPath,
    MissingVsockPort,
    Net(net::AddrParseError),
    Unix(string::ParseError),
    Vsock(ParseIntError),
}

impl fmt::Display for ParseAddressError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &ParseAddressError::MissingUnixPath => write!(f, "missing unix path"),
            &ParseAddressError::MissingVsockPort => write!(f, "missing vsock port number"),
            &ParseAddressError::Net(ref e) => e.fmt(f),
            &ParseAddressError::Unix(ref e) => write!(f, "invalid unix path: {}", e),
            &ParseAddressError::Vsock(ref e) => write!(f, "invalid vsock port number: {}", e),
        }
    }
}

impl FromStr for ListenAddress {
    type Err = ParseAddressError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        if s.starts_with(VSOCK) {
            if s.len() > VSOCK.len() {
                Ok(ListenAddress::Vsock(
                    s[VSOCK.len()..].parse().map_err(ParseAddressError::Vsock)?,
                ))
            } else {
                Err(ParseAddressError::MissingVsockPort)
            }
        } else if s.starts_with(UNIX) {
            if s.len() > UNIX.len() {
                Ok(ListenAddress::Unix(
                    s[UNIX.len()..].parse().map_err(ParseAddressError::Unix)?,
                ))
            } else {
                Err(ParseAddressError::MissingUnixPath)
            }
        } else {
            Ok(ListenAddress::Net(
                s.parse().map_err(ParseAddressError::Net)?,
            ))
        }
    }
}

#[derive(Debug)]
enum Error {
    Address(ParseAddressError),
    Argument(getopts::Fail),
    Cid(ParseIntError),
    IO(io::Error),
    MissingAcceptCid,
    Syslog(syslog::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Address(ref e) => e.fmt(f),
            &Error::Argument(ref e) => e.fmt(f),
            &Error::Cid(ref e) => write!(f, "invalid cid value: {}", e),
            &Error::IO(ref e) => e.fmt(f),
            &Error::MissingAcceptCid => write!(f, "`accept_cid` is required for vsock servers"),
            &Error::Syslog(ref e) => write!(f, "failed to initialize syslog: {:?}", e),
        }
    }
}

type Result<T> = result::Result<T, Error>;

fn handle_client<R: io::Read, W: io::Write>(
    root: Arc<str>,
    mut reader: R,
    mut writer: W,
) -> io::Result<()> {
    let mut server = p9::Server::new(&*root);

    loop {
        server.handle_message(&mut reader, &mut writer)?;
    }
}

fn run_vsock_server(root: Arc<str>, port: c_uint, accept_cid: c_uint) -> io::Result<()> {
    let listener = VsockListener::bind(port)?;

    loop {
        let (stream, peer) = listener.accept()?;

        if accept_cid != peer.cid {
            warn!("ignoring connection from {}:{}", peer.cid, peer.port);
            continue;
        }

        info!("accepted connection from {}:{}", peer.cid, peer.port);
        let reader = BufReader::with_capacity(DEFAULT_BUFFER_SIZE, stream.try_clone()?);
        let writer = BufWriter::with_capacity(DEFAULT_BUFFER_SIZE, stream);
        let server_root = root.clone();
        thread::spawn(move || {
            if let Err(e) = handle_client(server_root, reader, writer) {
                error!(
                    "error while handling client {}:{}: {}",
                    peer.cid, peer.port, e
                );
            }
        });
    }
}

fn main() -> Result<()> {
    let mut opts = getopts::Options::new();
    opts.optopt(
        "",
        "accept_cid",
        "only accept connections from this vsock context id",
        "CID",
    );
    opts.optopt(
        "r",
        "root",
        "root directory for clients (default is \"/\")",
        "PATH",
    );
    opts.optflag("h", "help", "print this help menu");

    let matches = opts
        .parse(std::env::args_os().skip(1))
        .map_err(Error::Argument)?;

    if matches.opt_present("h") || matches.free.len() == 0 {
        print!("{}", opts.usage(USAGE));
        return Ok(());
    }

    syslog::init().map_err(Error::Syslog)?;

    let root: Arc<str> = Arc::from(matches.opt_str("r").unwrap_or_else(|| "/".into()));

    // We already checked that |matches.free| has at least one item.
    match matches.free[0]
        .parse::<ListenAddress>()
        .map_err(Error::Address)?
    {
        ListenAddress::Vsock(port) => {
            let accept_cid = if let Some(cid) = matches.opt_str("accept_cid") {
                cid.parse::<c_uint>().map_err(Error::Cid)
            } else {
                Err(Error::MissingAcceptCid)
            }?;
            run_vsock_server(root, port, accept_cid).map_err(Error::IO)?;
        }
        ListenAddress::Net(_) => {
            error!("Network server unimplemented");
        }
        ListenAddress::Unix(_) => {
            error!("Unix server unimplemented");
        }
    }

    Ok(())
}
