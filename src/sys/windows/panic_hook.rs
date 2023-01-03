// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::panic;
use std::process::abort;

/// The intent of our panic hook is to get panic info and a stacktrace into the syslog, even for
/// jailed subprocesses. It will always abort on panic to ensure a minidump is generated.
///
/// Note that jailed processes will usually have a stacktrace of <unknown> because the backtrace
/// routines attempt to open this binary and are unable to do so in a jail.
pub fn set_panic_hook() {
    let default_panic = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        // Ensure all in-flight metrics are fully flushed
        metrics::get_destructor().cleanup();
        // TODO(b/144724919): should update log_panic_info for this "cleanly exit crosvm" bug
        // log_panic_info(default_panic.as_ref(), info);
        default_panic(info);
        // Abort to trigger the crash reporter so that a minidump is generated.
        abort();
    }));
}
