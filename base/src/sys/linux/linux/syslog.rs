// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of the Syslog trait for Linux.

use std::fs::File;
use std::io::Write;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixDatagram;
use std::ptr::null;

use libc::closelog;
use libc::fcntl;
use libc::localtime_r;
use libc::openlog;
use libc::time;
use libc::time_t;
use libc::tm;
use libc::F_GETFD;
use libc::LOG_NDELAY;
use libc::LOG_PERROR;
use libc::LOG_PID;
use libc::LOG_USER;
use once_cell::sync::OnceCell;

use super::super::getpid;
use crate::syslog::Error;
use crate::syslog::Facility;
use crate::syslog::Priority;
use crate::syslog::Syslog;
use crate::RawDescriptor;

/// Global syslog socket derived from the fd opened by `openlog()`.
/// This is initialized in `PlatformSyslog::new()`.
static SYSLOG_SOCKET: OnceCell<UnixDatagram> = OnceCell::new();

pub struct PlatformSyslog {}

struct SyslogSocket {}

impl Write for SyslogSocket {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(socket) = SYSLOG_SOCKET.get() {
            // If `send()` fails, there is nothing we can do about it, so just ignore the result.
            let _ = socket.send(buf);
        }

        // Abandon all hope but this is fine
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Syslog for PlatformSyslog {
    fn new(
        proc_name: String,
        facility: Facility,
    ) -> Result<(Option<Box<dyn log::Log + Send>>, Option<RawDescriptor>), Error> {
        // Calling openlog_and_get_socket() more than once will cause the previous syslogger FD to
        // be closed, invalidating the log::Log object in an unsafe manner. The OnceCell
        // get_or_try_init() ensures we only call it once.
        //
        // b/238923791 is tracking fixing this problem.
        let socket = SYSLOG_SOCKET.get_or_try_init(openlog_and_get_socket)?;
        let mut builder = env_logger::Builder::new();

        // Everything is filtered layer above
        builder.filter_level(log::LevelFilter::Trace);

        let fd = socket.as_raw_fd();
        builder.target(env_logger::Target::Pipe(Box::new(SyslogSocket {})));
        builder.format(move |buf, record| {
            const MONTHS: [&str; 12] = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ];

            let tm = get_localtime();
            let pri: Priority = record.level().into();
            let prifac = (pri as u8) | (facility as u8);
            write!(
                buf,
                "<{}>{} {:02} {:02}:{:02}:{:02} {}[{}]: ",
                prifac,
                MONTHS[tm.tm_mon as usize],
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec,
                &proc_name,
                getpid()
            )?;
            if let Some(path) = record.file() {
                write!(buf, " [{}", path)?;
                if let Some(line) = record.line() {
                    write!(buf, ":{}", line)?;
                }
                write!(buf, "] ")?;
            }
            writeln!(buf, "{}", record.args())
        });
        // https://github.com/env-logger-rs/env_logger/issues/208
        builder.is_test(true);
        Ok((Some(Box::new(builder.build())), Some(fd)))
    }
}

// Uses libc's openlog function to get a socket to the syslogger. By getting the socket this way, as
// opposed to connecting to the syslogger directly, libc's internal state gets initialized for other
// libraries (e.g. minijail) that make use of libc's syslog function. Note that this function
// depends on no other threads or signal handlers being active in this process because they might
// create FDs.
//
// TODO(zachr): Once https://android-review.googlesource.com/470998 lands, there won't be any
// libraries in use that hard depend on libc's syslogger. Remove this and go back to making the
// connection directly once minjail is ready.
fn openlog_and_get_socket() -> Result<UnixDatagram, Error> {
    // SAFETY:
    // closelog first in case there was already a file descriptor open.  Safe because it takes no
    // arguments and just closes an open file descriptor.  Does nothing if the file descriptor
    // was not already open.
    unsafe {
        closelog();
    }

    // Ordinarily libc's FD for the syslog connection can't be accessed, but we can guess that the
    // FD that openlog will be getting is the lowest unused FD. To guarantee that an FD is opened in
    // this function we use the LOG_NDELAY to tell openlog to connect to the syslog now. To get the
    // lowest unused FD, we open a dummy file (which the manual says will always return the lowest
    // fd), and then close that fd. Voilà, we now know the lowest numbered FD. The call to openlog
    // will make use of that FD, and then we just wrap a `UnixDatagram` around it for ease of use.
    let fd = File::open("/dev/null")
        .map_err(Error::GetLowestFd)?
        .as_raw_fd();

    // SAFETY: See comments for each unsafe line in the block.
    unsafe {
        // Safe because openlog accesses no pointers because `ident` is null, only valid flags are
        // used, and it returns no error.
        openlog(null(), LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);
        // For safety, ensure the fd we guessed is valid. The `fcntl` call itself only reads the
        // file descriptor table of the current process, which is trivially safe.
        if fcntl(fd, F_GETFD) >= 0 {
            Ok(UnixDatagram::from_raw_fd(fd))
        } else {
            Err(Error::InvalidFd)
        }
    }
}

fn get_localtime() -> tm {
    // SAFETY: See comments for each unsafe line in the block.
    unsafe {
        // Safe because tm is just a struct of plain data.
        let mut tm: tm = mem::zeroed();
        let mut now: time_t = 0;
        // Safe because we give time a valid pointer and can never fail.
        time(&mut now as *mut _);
        // Safe because we give localtime_r valid pointers and can never fail.
        localtime_r(&now, &mut tm as *mut _);
        tm
    }
}
