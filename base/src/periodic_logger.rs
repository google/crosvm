// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/318439696): Remove once it is used
#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use thiserror::Error as ThisError;

use crate::EventToken;
use crate::Timer;
use crate::TimerTrait;
use crate::WaitContext;
use crate::WorkerThread;

/// Utility class that helps count and log high frequency events periodically.
pub struct PeriodicLogger {
    // Name that is printed out to differentiate between other `PeriodicLogger`s
    name: String,
    // Interval to log
    interval: Duration,
    // Map of event counters that are periodically logged
    counters: Arc<RwLock<HashMap<String, AtomicU32>>>,
    // The periodic logger thread
    worker_thread: Option<WorkerThread<Result<(), PeriodicLoggerError>>>,
}

impl PeriodicLogger {
    pub fn new(name: String, interval: Duration) -> Self {
        PeriodicLogger {
            name,
            interval,
            counters: Arc::new(RwLock::new(HashMap::new())),
            worker_thread: None,
        }
    }

    /// Add a new event item to be counted.
    pub fn add_counter_item(&self, name: String) -> Result<(), PeriodicLoggerError> {
        // This write lock will likely be acquired infrequently.
        let mut counters_write_lock = self
            .counters
            .write()
            .map_err(|e| PeriodicLoggerError::WriteLockError(e.to_string()))?;

        if counters_write_lock.contains_key(&name) {
            return Err(PeriodicLoggerError::CounterAlreadyExist(name));
        }

        counters_write_lock.insert(name, AtomicU32::new(0));
        Ok(())
    }

    /// Increment event counter by an `amount`
    pub fn increment_counter(&self, name: String, amount: u32) -> Result<(), PeriodicLoggerError> {
        match self.counters.read() {
            Ok(counters_map) => {
                if let Some(atomic_counter) = counters_map.get(&name) {
                    atomic_counter.fetch_add(amount, Ordering::Relaxed);
                    Ok(())
                } else {
                    Err(PeriodicLoggerError::CounterDoesNotExist(name))
                }
            }
            Err(e) => Err(PeriodicLoggerError::ReadLockError(e.to_string())),
        }
    }

    /// Starts a thread that will log the count of events within a `self.interval` time period.
    /// All counters will be reset to 0 after logging.
    pub fn start_logging_thread(&mut self) -> Result<(), PeriodicLoggerError> {
        if self.worker_thread.is_some() {
            return Err(PeriodicLoggerError::ThreadAlreadyStarted);
        }

        #[derive(EventToken)]
        enum Token {
            Exit,
            PeriodicLog,
        }

        let cloned_counter = self.counters.clone();
        let interval_copy = self.interval;
        let name_copy = self.name.clone();
        self.worker_thread = Some(WorkerThread::start(
            format!("PeriodicLogger_{}", self.name),
            move |kill_evt| {
                let mut timer = Timer::new().map_err(PeriodicLoggerError::TimerNewError)?;
                timer
                    .reset(interval_copy, Some(interval_copy))
                    .map_err(PeriodicLoggerError::TimerResetError)?;

                let wait_ctx = WaitContext::build_with(&[
                    (&kill_evt, Token::Exit),
                    (&timer, Token::PeriodicLog),
                ])
                .map_err(PeriodicLoggerError::WaitContextBuildError)?;

                'outer: loop {
                    let events = wait_ctx.wait().expect("wait failed");
                    for event in events.iter().filter(|e| e.is_readable) {
                        match event.token {
                            Token::Exit => {
                                break 'outer;
                            }
                            Token::PeriodicLog => {
                                let counter_map = cloned_counter.read().map_err(|e| {
                                    PeriodicLoggerError::ReadLockError(e.to_string())
                                })?;

                                let mut logged_string =
                                    format!("{} {:?}:", name_copy, interval_copy);
                                for (counter_name, counter_value) in counter_map.iter() {
                                    let value = counter_value.swap(0, Ordering::Relaxed);
                                    let _ =
                                        write!(logged_string, "\n    {}: {}", counter_name, value);
                                }

                                // Log all counters
                                crate::info!("{}", logged_string);
                            }
                        }
                    }
                }
                Ok(())
            },
        ));

        Ok(())
    }
}

#[derive(Debug, ThisError, PartialEq)]
pub enum PeriodicLoggerError {
    #[error("Periodic logger thread already started.")]
    ThreadAlreadyStarted,
    #[error("Failed to acquire write lock: {0}")]
    WriteLockError(String),
    #[error("Failed to acquire read lock: {0}")]
    ReadLockError(String),
    #[error("Counter already exists: {0}")]
    CounterAlreadyExist(String),
    #[error("Counter does not exist: {0}")]
    CounterDoesNotExist(String),
    #[error("Failed to build WaitContext: {0}")]
    WaitContextBuildError(crate::Error),
    #[error("Failed to wait on WaitContext: {0}")]
    WaitContextWaitError(crate::Error),
    #[error("Failed to reset Timer: {0}")]
    TimerResetError(crate::Error),
    #[error("Failed initialize Timer: {0}")]
    TimerNewError(crate::Error),
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn periodic_add() {
        let periodic_logger = PeriodicLogger::new("test".to_string(), Duration::from_secs(3));
        periodic_logger
            .add_counter_item("counter_1".to_string())
            .unwrap();
        periodic_logger
            .increment_counter("counter_1".to_string(), 2)
            .unwrap();
        periodic_logger
            .increment_counter("counter_1".to_string(), 5)
            .unwrap();

        assert_eq!(periodic_logger.counters.read().unwrap().len(), 1);
        assert_eq!(
            periodic_logger
                .counters
                .read()
                .unwrap()
                .get("counter_1")
                .unwrap()
                .load(Ordering::Relaxed),
            7
        );
    }

    #[test]
    fn worker_thread_cannot_start_twice() {
        let mut periodic_logger = PeriodicLogger::new("test".to_string(), Duration::from_secs(3));
        assert!(periodic_logger.start_logging_thread().is_ok());
        assert!(periodic_logger.start_logging_thread().is_err());
    }

    #[test]
    fn add_same_counter_item_twice_return_err() {
        let periodic_logger = PeriodicLogger::new("test".to_string(), Duration::from_secs(3));
        assert!(periodic_logger
            .add_counter_item("counter_1".to_string())
            .is_ok());
        assert_eq!(
            periodic_logger.add_counter_item("counter_1".to_string()),
            Err(PeriodicLoggerError::CounterAlreadyExist(
                "counter_1".to_string()
            ))
        );
    }

    /// Ignored because this is intended to be ran locally
    #[ignore]
    #[test]
    fn periodic_logger_smoke_test() {
        let mut periodic_logger = PeriodicLogger::new("test".to_string(), Duration::from_secs(3));
        periodic_logger
            .add_counter_item("counter_1".to_string())
            .unwrap();

        periodic_logger.start_logging_thread().unwrap();
        periodic_logger
            .increment_counter("counter_1".to_string(), 5)
            .unwrap();

        thread::sleep(Duration::from_secs(5));
    }
}
