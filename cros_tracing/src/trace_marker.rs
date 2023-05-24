// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Mutex;

use base::error;
use base::RawDescriptor;
use once_cell::sync::OnceCell;

static TRACE_MARKER_FILE: OnceCell<Mutex<File>> = OnceCell::new();

#[macro_export]
/// This macro is used as a placeholder to let us iterate over the compile-time
/// allocated vector of categories when we statically initialize it.
/// This macro should only be used internally to this crate.
macro_rules! zero_internal {
    ($x:ident) => {
        0
    };
}

#[macro_export]
/// This macro expands an expression with its value for easier printing.
/// `expand_fmt_internal!(my_var)` becomes `"(my_var: {:?})"`.
macro_rules! expand_fmt_internal {
    ($x:expr) => {
        std::concat!("(", std::stringify!($x), ": {:?})")
    };
}

#[macro_export]
/// Macro used to handle fd permanency across jailed devices.
/// If we run crosvm without `--disable-sandbox`, we need to add the `trace_marker`
/// file descriptor to the list of file descriptors allowed to be accessed by the
/// sandboxed process. We call this macro to add the file descriptor to the list
/// of `keep_rds` that the process is allowed to access every time we jail.
macro_rules! push_descriptors {
    ($fd_vec:expr) => {
        $crate::push_descriptors_internal($fd_vec);
    };
}

#[macro_export]
/// Prints a single non-scoped message without creating a trace context.
/// The tagged variant lets us enable or disable individual categories.
macro_rules! trace_simple_print {
    ($category: ident, $($t:tt)*) => {{
        if($crate::ENABLED_CATEGORIES[$crate::TracedCategories::$category as usize].load(std::sync::atomic::Ordering::Relaxed)) {
            $crate::trace_simple_print!($($t)*);
        }
    }};
    ($($t:tt)*) => {{
        $crate::trace_simple_print_internal(std::format!($($t)*));
    }};
}

/// Platform-specific implementation of the `push_descriptors!` macro. If the
/// `trace_marker` file has been initialized properly, it adds its file descriptor
/// to the list of file descriptors that are allowed to be accessed when the process
/// is jailed in the sandbox.
///
/// # Arguments
///
/// * `keep_rds` - List of file descriptors that will be accessible after jailing
pub fn push_descriptors_internal(keep_rds: &mut Vec<RawDescriptor>) {
    if let Some(file) = TRACE_MARKER_FILE.get() {
        let fd = file.lock().unwrap().as_raw_fd();
        if !keep_rds.contains(&fd) {
            keep_rds.push(fd);
        }
    }
}

#[macro_export]
/// Macro used to set up the trace environment categories. It takes a variable
/// number of arguments in pairs of category, boolean value on whether or not the
/// tracing category is enabled at compile time.
///
/// # Example usage
///
/// ```ignore
/// setup_trace_marker!(
///     (Category1, true),
///     (Category2, false)
/// );
/// ```
///
/// Categories that are enabled will have their events traced at runtime via
/// `trace_event_begin!()`, `trace_event_end!()`, or `trace_event!()` scoped tracing.
/// The categories that are marked as false will have their events skipped.
///
macro_rules! setup_trace_marker {
 ($(($cat:ident, $enabled:literal)),+) => {
     #[allow(non_camel_case_types, missing_docs)]
     /// The tracing categories that the trace_marker backend supports.
     pub enum TracedCategories {
         $($cat,)+
         /// Hacky way to get the count of how many tracing categories we have in total.
         CATEGORY_COUNT,
     }

     /// Vector counting how many tracing event contexts are running for each category.
     pub static CATEGORY_COUNTER: [std::sync::atomic::AtomicI64; TracedCategories::CATEGORY_COUNT as usize] = [
         $(
             // Note, we pass $cat to the zero_internal! macro here, which always just returns
             // 0, because it's impossible to iterate over $cat unless $cat is used.
             std::sync::atomic::AtomicI64::new(zero_internal!($cat)),
         )+
     ];

     /// Vector used to test if a category is enabled or not for tracing.
     pub static ENABLED_CATEGORIES: [std::sync::atomic::AtomicBool; TracedCategories::CATEGORY_COUNT as usize] = [
         $(
             std::sync::atomic::AtomicBool::new($enabled),
         )+
     ];

     /// Sequential identifier for scoped trace events. This unique identifier is incremented
     /// for each new `trace_event()` call.
     pub static EVENT_COUNTER: std::sync::atomic::AtomicU64 =
         std::sync::atomic::AtomicU64::new(0);
 }
}

#[macro_export]
/// Returns a Trace object with a new name and index and traces its enter state, if the
/// given category identifier is enabled. Extra args can be provided for easier debugging.
/// Upon exiting its scope, it is automatically collected and its exit gets traced.
///
/// If the category identifier is not enabled for this event, nothing happens and the trace
/// event is skipped.
///
/// # Example usage
///
/// ```ignore
/// {
///    let _trace = trace_event!(Category, "exec", param1, param2);
///
///    // ... Rest of code ...
///
///    // End of `_trace`'s lifetime so `trace_event_end` is called.
/// }
/// ```
///
/// This will output in `trace_marker`:
///
///   - `$uid: $category Enter: exec - (param1: ...)(param2: ...)`
///
/// and when _trace runs out of scope, it will output:
///
///   - `$uid: Exit: exec`
///
/// where `$uid` will be the same unique value across those two events.
///
macro_rules! trace_event {
    ($category:ident, $name:expr, $($arg:expr),+) => {{
        if($crate::ENABLED_CATEGORIES[$crate::TracedCategories::$category as usize].load(std::sync::atomic::Ordering::Relaxed)) {
            $crate::trace_event_begin!($category);
            let index = $crate::EVENT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            $crate::trace_simple_print!($category,
                                        "{} {} Enter: {} - {}",
                                        index,
                                        std::stringify!($category),
                                        $name,
                                        // Creates a formatted list for each argument and their
                                        // values.
                                        std::format_args!(std::concat!($($crate::expand_fmt_internal!($arg),)*), $($arg),*));
            Some($crate::Trace::new(index, $name, std::stringify!($category), $crate::TracedCategories::$category as usize))
        } else {
            None
        }
    }};
    ($category:ident, $name:expr) => {{
        if($crate::ENABLED_CATEGORIES[$crate::TracedCategories::$category as usize].load(std::sync::atomic::Ordering::Relaxed)) {
            $crate::trace_event_begin!($category);
            let index = $crate::EVENT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            $crate::trace_simple_print!($category,
                                        "{} {} Enter: {}", index, std::stringify!($category), $name);
            Some($crate::Trace::new(index, $name, std::stringify!($category), $crate::TracedCategories::$category as usize))
        } else {
            None
        }
    }};
}

#[macro_export]
/// Begins a tracing event context in the given category, it increases the counter
/// of the currently traced events for that category by one.
///
/// # Arguments
///
/// * `category` - Identifier name of the category.
macro_rules! trace_event_begin {
    ($category:ident) => {
        $crate::CATEGORY_COUNTER[$crate::TracedCategories::$category as usize]
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    };
}

#[macro_export]
/// Ends a tracing event context in the given category, it decreases the counter
/// of the currently traced events for that category by one.
///
/// # Arguments
///
/// * `category` - Identifier name of the category.
macro_rules! trace_event_end {
    ($category:ident) => {
        if ($crate::ENABLED_CATEGORIES[$crate::TracedCategories::$category as usize]
            .load(std::sync::atomic::Ordering::Relaxed))
        {
            $crate::CATEGORY_COUNTER[$crate::TracedCategories::$category as usize]
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    };
    ($category_id:expr) => {
        if ($crate::ENABLED_CATEGORIES[$category_id as usize]
            .load(std::sync::atomic::Ordering::Relaxed))
        {
            $crate::CATEGORY_COUNTER[$category_id as usize]
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    };
}

// List of categories that can be enabled.
// If a category is marked as disabled here, no events will be processed for it.
setup_trace_marker!((VirtioFs, true));

/// Platform-specific implementation of the `trace_simple_print!` macro. If tracing
/// is enabled on the system, it writes the given message to the `trace_marker` file.
///
/// # Arguments
///
/// * `message` - The message to be written
pub fn trace_simple_print_internal(message: String) {
    // In case tracing is not working or the trace marker file is None we can
    // just ignore this. We don't need to handle the error here.
    if let Some(file) = TRACE_MARKER_FILE.get() {
        // We ignore the error here in case write!() fails, because the trace
        // marker file would be normally closed by the system unless we are
        // actively tracing the runtime. It is not an error.
        write!(file.lock().unwrap(), "{}", message).ok();
    };
}

/// Initializes the trace_marker backend. It attepts to open the `trace_marker`
/// file and keep a reference that can be shared throughout the lifetime of the
/// crosvm process.
///
/// If tracefs is not available on the system or the file cannot be opened,
/// tracing will not work but the crosvm process will still continue execution
/// without tracing.
pub fn init() {
    let path = Path::new("/sys/kernel/tracing/trace_marker");
    let file = match OpenOptions::new().read(false).write(true).open(path) {
        Ok(f) => f,
        Err(e) => {
            error!(
                "Failed to open {}: {}. Tracing will not work.",
                path.display(),
                e
            );
            return;
        }
    };

    if TRACE_MARKER_FILE.set(Mutex::new(file)).is_err() {
        error!("Failed to create mutex. Tracing will not work.");
    }
}

/// A trace context obtained from a `trace_event!()` call.
pub struct Trace {
    /// Unique identifier for the specific event.
    identifier: u64,
    /// Name of the trace event.
    name: String,
    /// Category name to which the event belongs.
    category: String,
    /// Category ID to which the event belongs.
    category_id: usize,
}

impl Trace {
    /// Returns a Trace object with the given name, id, and category
    pub fn new(identifier: u64, name: &str, category: &str, category_id: usize) -> Self {
        Trace {
            identifier,
            name: name.to_string(),
            category: category.to_string(),
            category_id,
        }
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        trace_simple_print!("{} {} Exit: {}", self.identifier, self.category, self.name);
        trace_event_end!(self.category_id);
    }
}
