// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::fmt::Write as _;
use std::mem;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use base::error;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::Event;
use base::EventToken;
use base::FromRawDescriptor;
use base::SafeDescriptor;
use base::WaitContext;
use chrono::DateTime;
use chrono::Local;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FILETIME;
use winapi::um::processthreadsapi::GetProcessTimes;
use winapi::um::processthreadsapi::GetSystemTimes;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::GetProcessMemoryInfo;
use winapi::um::psapi::PROCESS_MEMORY_COUNTERS;
use winapi::um::psapi::PROCESS_MEMORY_COUNTERS_EX;
use winapi::um::winbase::GetProcessIoCounters;
use winapi::um::winnt::IO_COUNTERS;
use winapi::um::winnt::LARGE_INTEGER;
use winapi::um::winnt::LONGLONG;
use winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION;
use winapi::um::winnt::PROCESS_VM_READ;
use winapi::um::winnt::SYNCHRONIZE;

use crate::log_metric;
use crate::windows::Error;
use crate::windows::Result;
use crate::windows::METRIC_UPLOAD_INTERVAL_SECONDS;
use crate::MetricEventType;

const BYTES_PER_MB: usize = 1024 * 1024;
const WORKER_REPORT_INTERVAL: Duration = Duration::from_secs(1);

type SysResult<T> = std::result::Result<T, SysError>;

/// A worker job which periodically logs system metrics.
struct Worker {
    exit_evt: Event,
    io: Arc<Mutex<Option<ProcessIoRecord>>>,
    measurements: Arc<Mutex<Option<Measurements>>>,
    memory: Arc<Mutex<ProcessMemory>>,
    memory_acc: Arc<Mutex<Option<ProcessMemoryAccumulated>>>,
    metrics_string: Arc<Mutex<String>>,
}

impl Worker {
    fn run(&mut self) {
        #[derive(EventToken)]
        enum Token {
            Exit,
        }
        let event_ctx: WaitContext<Token> =
            match WaitContext::build_with(&[(&self.exit_evt, Token::Exit)]) {
                Ok(event_ctx) => event_ctx,
                Err(e) => {
                    error!("failed creating WaitContext: {}", e);
                    return;
                }
            };
        let mut last_metric_upload_time = Local::now();
        'poll: loop {
            let events = match event_ctx.wait_timeout(WORKER_REPORT_INTERVAL) {
                Ok(events) => events,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    return;
                }
            };
            if events.is_empty() {
                self.collect_metrics();
                // Time budget for UI thread is very limited.
                // We make the metric string for displaying in UI in the
                // worker thread for best performance.
                self.make_metrics_string();

                self.upload_metrics(&mut last_metric_upload_time);
            }

            if events.into_iter().any(|e| e.is_readable) {
                break 'poll;
            }
        }
    }

    fn make_metrics_string(&mut self) {
        let mut metrics_string = self.metrics_string.lock().unwrap();
        *metrics_string = format!(
            "{}\n{}",
            self.cpu_metrics_string(),
            self.mem_metrics_string()
        );
    }

    fn upload_metrics(&self, last_metric_upload_time: &mut DateTime<Local>) {
        let time_elapsed = (Local::now() - *last_metric_upload_time).num_seconds();
        if time_elapsed >= METRIC_UPLOAD_INTERVAL_SECONDS {
            let mut memory_acc = self.memory_acc.lock().unwrap();
            if let Some(acc) = &*memory_acc {
                let mem = acc.accumulated.physical / acc.accumulated_count / BYTES_PER_MB;
                // The i64 cast will not cause overflow because the mem is at most 10TB for
                // Windows 10.
                log_metric(MetricEventType::MemoryUsage, mem as i64);
            }
            *memory_acc = None;

            let mut cpu_measurements = self.measurements.lock().unwrap();
            if let Some(measurements) = &*cpu_measurements {
                let sys_time = measurements.current.sys_time;
                let process_time = measurements.current.process_time;
                let prev_sys_time = measurements.last_upload.sys_time;
                let prev_process_time = measurements.last_upload.process_time;

                let diff_systime_kernel =
                    compute_filetime_subtraction(sys_time.kernel, prev_sys_time.kernel);
                let diff_systime_user =
                    compute_filetime_subtraction(sys_time.user, prev_sys_time.user);

                let diff_processtime_kernel =
                    compute_filetime_subtraction(process_time.kernel, prev_process_time.kernel);
                let diff_processtime_user =
                    compute_filetime_subtraction(process_time.user, prev_process_time.user);

                let total_systime = diff_systime_kernel + diff_systime_user;
                let total_processtime = diff_processtime_kernel + diff_processtime_user;

                if total_systime > 0 {
                    let cpu_usage = 100 * total_processtime / total_systime;
                    // The i64 cast will not cause overflow because the usage is at most 100.
                    log_metric(MetricEventType::CpuUsage, cpu_usage as i64);
                }
            }
            *cpu_measurements = None;

            let mut io = self.io.lock().unwrap();
            if let Some(io_record) = &*io {
                let new_io_read_bytes =
                    io_record.current.read_bytes - io_record.last_upload.read_bytes;
                let new_io_write_bytes =
                    io_record.current.write_bytes - io_record.last_upload.write_bytes;

                let ms_elapsed =
                    (io_record.current_time - io_record.last_upload_time).num_milliseconds();
                if ms_elapsed > 0 {
                    let io_read_bytes_per_sec =
                        (new_io_read_bytes as f32) / (ms_elapsed as f32) * 1000.0;
                    let io_write_bytes_per_sec =
                        (new_io_write_bytes as f32) / (ms_elapsed as f32) * 1000.0;
                    log_metric(MetricEventType::ReadIo, io_read_bytes_per_sec as i64);
                    log_metric(MetricEventType::WriteIo, io_write_bytes_per_sec as i64);
                }
            }
            *io = None;
            *last_metric_upload_time = Local::now();
        }
    }

    fn collect_metrics(&mut self) {
        match self.get_cpu_metrics() {
            Ok(new_measurement) => {
                let mut measurements = self.measurements.lock().unwrap();
                let next_measurements = match *measurements {
                    Some(Measurements {
                        current,
                        last_upload,
                        ..
                    }) => Measurements {
                        current: new_measurement,
                        previous: current,
                        last_upload,
                    },
                    None => Measurements {
                        current: new_measurement,
                        previous: new_measurement,
                        last_upload: new_measurement,
                    },
                };
                *measurements = Some(next_measurements);
            }
            Err(e) => {
                // Do not panic because of cpu query related failures.
                error!("Get cpu measurement failed: {}", e);
            }
        }

        match self.get_mem_metrics() {
            Ok(mem) => {
                // Keep running sum and count to calculate averages.
                let mut memory_acc = self.memory_acc.lock().unwrap();
                let updated_memory_acc = match *memory_acc {
                    Some(acc) => accumulate_process_memory(acc, mem),
                    None => ProcessMemoryAccumulated {
                        accumulated: mem,
                        accumulated_count: 1,
                    },
                };
                *memory_acc = Some(updated_memory_acc);
                *self.memory.lock().unwrap() = mem
            }
            Err(e) => {
                // Do not panic because of memory query failures.
                error!("Get cpu measurement failed: {}", e);
            }
        }

        match self.get_io_metrics() {
            Ok(new_io) => {
                let mut io_record = self.io.lock().unwrap();
                let updated_io = match *io_record {
                    Some(io) => ProcessIoRecord {
                        current: new_io,
                        current_time: Local::now(),
                        last_upload: io.last_upload,
                        last_upload_time: io.last_upload_time,
                    },
                    None => ProcessIoRecord {
                        current: new_io,
                        current_time: Local::now(),
                        last_upload: new_io,
                        last_upload_time: Local::now(),
                    },
                };
                *io_record = Some(updated_io);
            }
            Err(e) => {
                // Do not panic because of io query failures.
                error!("Get io measurement failed: {}", e);
            }
        }
    }

    fn get_mem_metrics(&self) -> SysResult<ProcessMemory> {
        let process_handle = CoreWinMetrics::get_process_handle()?;

        let mut counters = PROCESS_MEMORY_COUNTERS_EX::default();

        // Safe because we own the process handle and all memory was allocated.
        let result = unsafe {
            GetProcessMemoryInfo(
                process_handle.as_raw_descriptor(),
                // Converting is necessary because the `winapi`' GetProcessMemoryInfo
                // does NOT support `PROCESS_MEMORY_COUNTERS_EX`, but only
                // 'PROCESS_MEMORY_COUNTERS'. The casting is safe because the underlining
                // Windows api does `PROCESS_MEMORY_COUNTERS_EX`.
                &mut counters as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
                mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as DWORD,
            )
        };
        if result == 0 {
            return Err(SysError::last());
        }

        Ok(ProcessMemory {
            page_fault_count: counters.PageFaultCount,
            working_set_size: counters.WorkingSetSize,
            working_set_peak: counters.PeakWorkingSetSize,
            page_file_usage: counters.PagefileUsage,
            page_file_peak: counters.PeakPagefileUsage,
            physical: counters.PrivateUsage,
        })
    }

    fn get_cpu_metrics(&self) -> SysResult<Measurement> {
        let mut sys_time: SystemCpuTime = Default::default();
        let mut process_time: ProcessCpuTime = Default::default();
        let sys_time_success: i32;

        // Safe because memory is allocated for sys_time before the windows call.
        // And the value were initilized to 0s.
        unsafe {
            // First get kernel cpu time.
            sys_time_success =
                GetSystemTimes(&mut sys_time.idle, &mut sys_time.kernel, &mut sys_time.user);
        }
        if sys_time_success == 0 {
            error!("Systime collection failed.\n");
            return Err(SysError::last());
        } else {
            // Query current process cpu time.
            let process_handle = CoreWinMetrics::get_process_handle()?;
            let process_time_success: i32;
            // Safe because memory is allocated for process_time before the windows call.
            // And the value were initilized to 0s.
            unsafe {
                process_time_success = GetProcessTimes(
                    process_handle.as_raw_descriptor(),
                    &mut process_time.create,
                    &mut process_time.exit,
                    &mut process_time.kernel,
                    &mut process_time.user,
                );
            }
            if process_time_success == 0 {
                error!("Systime collection failed.\n");
                return Err(SysError::last());
            }
        }
        Ok(Measurement {
            sys_time: SystemCpuTime {
                idle: sys_time.idle,
                kernel: sys_time.kernel,
                user: sys_time.user,
            },
            process_time: ProcessCpuTime {
                create: process_time.create,
                exit: process_time.exit,
                kernel: process_time.kernel,
                user: process_time.user,
            },
        })
    }

    fn get_io_metrics(&self) -> SysResult<ProcessIo> {
        let process_handle = CoreWinMetrics::get_process_handle()?;
        let mut io_counters = IO_COUNTERS::default();
        // Safe because we own the process handle and all memory was allocated.
        let result = unsafe {
            GetProcessIoCounters(
                process_handle.as_raw_descriptor(),
                &mut io_counters as *mut IO_COUNTERS,
            )
        };
        if result == 0 {
            return Err(SysError::last());
        }
        Ok(ProcessIo {
            read_bytes: io_counters.ReadTransferCount,
            write_bytes: io_counters.WriteTransferCount,
        })
    }

    fn mem_metrics_string(&self) -> String {
        let guard = self.memory.lock().unwrap();
        let memory: ProcessMemory = *guard;
        let mut buf = format!(
            "Physical memory used: {} mb.\n",
            memory.physical / BYTES_PER_MB
        );
        let _ = writeln!(
            buf,
            "Total working memory: {} mb.",
            memory.working_set_size / BYTES_PER_MB
        );
        let _ = writeln!(
            buf,
            "Peak working memory: {} mb.",
            memory.working_set_peak / BYTES_PER_MB
        );
        let _ = writeln!(buf, "Page fault count: {}.", memory.page_fault_count);
        let _ = writeln!(
            buf,
            "Page file used: {} mb.",
            memory.page_file_usage / BYTES_PER_MB
        );
        let _ = writeln!(
            buf,
            "Peak page file used: {} mb.",
            memory.page_file_peak / BYTES_PER_MB
        );
        buf
    }

    fn cpu_metrics_string(&self) -> String {
        let guard = self.measurements.lock().unwrap();
        let mut buf = String::new();

        // Now we use current and last cpu measurment data to calculate cpu usage
        // as a percentage.
        if let Some(measurements) = &*guard {
            let sys_time = measurements.current.sys_time;
            let process_time = measurements.current.process_time;
            let prev_sys_time = measurements.previous.sys_time;
            let prev_process_time = measurements.previous.process_time;

            let diff_systime_kernel =
                compute_filetime_subtraction(sys_time.kernel, prev_sys_time.kernel);
            let diff_systime_user = compute_filetime_subtraction(sys_time.user, prev_sys_time.user);

            let diff_processtime_kernel =
                compute_filetime_subtraction(process_time.kernel, prev_process_time.kernel);
            let diff_processtime_user =
                compute_filetime_subtraction(process_time.user, prev_process_time.user);

            let total_systime = diff_systime_kernel + diff_systime_user;
            let total_processtime = diff_processtime_kernel + diff_processtime_user;

            let mut process_cpu = String::from("still calculating...");
            if total_systime > 0 {
                process_cpu = format!("{}%", (100 * total_processtime / total_systime));
            }
            let _ = writeln!(buf, "Process cpu usage is: {}", process_cpu);

            #[cfg(debug_assertions)]
            {
                // Show data supporting our cpu usage calculation.
                // Output system cpu time.
                let _ = writeln!(
                    buf,
                    "Systime Idle: low {} / high {}",
                    sys_time.idle.dwLowDateTime, sys_time.idle.dwHighDateTime
                );
                let _ = writeln!(
                    buf,
                    "Systime User: low {} / high {}",
                    sys_time.user.dwLowDateTime, sys_time.user.dwHighDateTime
                );
                let _ = writeln!(
                    buf,
                    "Systime kernel: low {} / high {}",
                    sys_time.kernel.dwLowDateTime, sys_time.kernel.dwHighDateTime
                );
                // Output process cpu time.
                let _ = writeln!(
                    buf,
                    "Process Create: low {} / high {}",
                    process_time.create.dwLowDateTime, process_time.create.dwHighDateTime
                );
                let _ = writeln!(
                    buf,
                    "Process Exit: low {} / high {}",
                    process_time.exit.dwLowDateTime, process_time.exit.dwHighDateTime
                );
                let _ = writeln!(
                    buf,
                    "Process kernel: low {} / high {}",
                    process_time.kernel.dwLowDateTime, process_time.kernel.dwHighDateTime
                );
                let _ = writeln!(
                    buf,
                    "Process user: low {} / high {}",
                    process_time.user.dwLowDateTime, process_time.user.dwHighDateTime
                );
            }
        } else {
            let _ = write!(buf, "Calculating cpu usage...");
        }
        buf
    }
}

fn compute_filetime_subtraction(fta: FILETIME, ftb: FILETIME) -> LONGLONG {
    // safe because we are initializing the struct to 0s.
    unsafe {
        let mut a: LARGE_INTEGER = mem::zeroed::<LARGE_INTEGER>();
        a.u_mut().LowPart = fta.dwLowDateTime;
        a.u_mut().HighPart = fta.dwHighDateTime as i32;
        let mut b: LARGE_INTEGER = mem::zeroed::<LARGE_INTEGER>();
        b.u_mut().LowPart = ftb.dwLowDateTime;
        b.u_mut().HighPart = ftb.dwHighDateTime as i32;
        a.QuadPart() - b.QuadPart()
    }
}

// Adds to a running total of memory metrics over the course of a collection period.
// Can divide these sums to calculate averages.
fn accumulate_process_memory(
    acc: ProcessMemoryAccumulated,
    mem: ProcessMemory,
) -> ProcessMemoryAccumulated {
    ProcessMemoryAccumulated {
        accumulated: ProcessMemory {
            page_fault_count: mem.page_fault_count,
            working_set_size: acc.accumulated.working_set_size + mem.working_set_size,
            working_set_peak: mem.working_set_peak,
            page_file_usage: acc.accumulated.page_file_usage + mem.page_file_usage,
            page_file_peak: mem.page_file_peak,
            physical: acc.accumulated.physical + mem.physical,
        },
        accumulated_count: acc.accumulated_count + 1,
    }
}

#[derive(Copy, Clone, Default)]
struct SystemCpuTime {
    idle: FILETIME,
    kernel: FILETIME,
    user: FILETIME,
}

#[derive(Copy, Clone, Default)]
struct ProcessCpuTime {
    create: FILETIME,
    exit: FILETIME,
    kernel: FILETIME,
    user: FILETIME,
}

#[derive(Copy, Clone, Default)]
struct ProcessMemory {
    page_fault_count: u32,
    working_set_size: usize,
    working_set_peak: usize,
    page_file_usage: usize,
    page_file_peak: usize,
    physical: usize,
}

#[derive(Copy, Clone)]
struct ProcessMemoryAccumulated {
    accumulated: ProcessMemory,
    accumulated_count: usize,
}

#[derive(Copy, Clone, Default)]
struct ProcessIo {
    read_bytes: u64,
    write_bytes: u64,
}

#[derive(Copy, Clone)]
struct ProcessIoRecord {
    current: ProcessIo,
    current_time: DateTime<Local>,
    last_upload: ProcessIo,
    last_upload_time: DateTime<Local>,
}

#[derive(Copy, Clone)]
struct Measurement {
    sys_time: SystemCpuTime,
    process_time: ProcessCpuTime,
}

struct Measurements {
    current: Measurement,
    previous: Measurement,
    last_upload: Measurement,
}

/// A managing struct for a job which defines regular logging of core Windows system metrics.
pub(crate) struct CoreWinMetrics {
    metrics_string: Weak<Mutex<String>>,
    exit_evt: Event,
    worker_thread: Option<JoinHandle<()>>,
}

impl CoreWinMetrics {
    pub fn new() -> Result<Self> {
        let exit_evt = match Event::new() {
            Ok(evt) => evt,
            Err(_e) => return Err(Error::CannotInstantiateEvent),
        };

        let metrics_string = String::new();
        let arc_metrics_memory = Arc::new(Mutex::new(metrics_string));
        let weak_metrics_memory = Arc::downgrade(&arc_metrics_memory);

        let mut me = Self {
            metrics_string: weak_metrics_memory,
            exit_evt,
            worker_thread: None,
        };
        let exit_evt_clone = match me.exit_evt.try_clone() {
            Ok(evt) => evt,
            Err(_) => return Err(Error::CannotCloneEvent),
        };
        me.worker_thread.replace(thread::spawn(|| {
            Worker {
                exit_evt: exit_evt_clone,
                io: Arc::new(Mutex::new(None)),
                measurements: Arc::new(Mutex::new(None)),
                memory: Arc::new(Mutex::new(Default::default())),
                memory_acc: Arc::new(Mutex::new(None)),
                metrics_string: arc_metrics_memory,
            }
            .run();
        }));
        Ok(me)
    }

    fn get_process_handle() -> SysResult<SafeDescriptor> {
        // Safe because we own the current process.
        let process_handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,
                0,
                std::process::id(),
            )
        };
        if process_handle.is_null() {
            return Err(SysError::last());
        }
        // Safe as the SafeDescriptor is the only thing with access to the handle after this.
        Ok(unsafe { SafeDescriptor::from_raw_descriptor(process_handle) })
    }
}

impl Drop for CoreWinMetrics {
    fn drop(&mut self) {
        if let Some(join_handle) = self.worker_thread.take() {
            let _ = self.exit_evt.signal();
            join_handle
                .join()
                .expect("fail to join the worker thread of a win core metrics collector.");
        }
    }
}

impl fmt::Display for CoreWinMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.metrics_string.upgrade() {
            Some(metrics_string) => write!(f, "{}", *metrics_string.lock().unwrap()),
            None => write!(f, ""),
        }
    }
}
