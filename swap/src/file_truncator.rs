// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use base::Descriptor;
use base::Event;
use base::EventToken;
use base::Timer;
use base::TimerTrait;
use base::WaitContext;
use base::WorkerThread;

/// Truncates a file to length 0, in the background when possible.
///
/// Truncating a large file can result in a significant amount of IO when
/// updating filesystem metadata. When possible, [FileTruncator] truncates a
/// given file gradually over time to avoid competing with higher prioirty IO.
pub struct FileTruncator {
    worker: Option<WorkerThread<Result<File>>>,
}

// The particular values here are relatively arbitrary values that
// result in a "slow-enough" background truncation.
const TRUNCATE_STEP_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB
const TRUNCATE_INITIAL_WAIT: Duration = Duration::from_secs(30);
const TRUNCATE_INTERVAL: Duration = Duration::from_secs(5);

fn truncate_worker(
    mut timer: Box<dyn TimerTrait>,
    mut file: File,
    kill_evt: Event,
) -> Result<File> {
    #[derive(EventToken)]
    enum Token {
        Alarm,
        Kill,
    }

    let mut len = file
        .seek(SeekFrom::End(0))
        .context("Failed to determine size")?;

    let descriptor = Descriptor(timer.as_raw_descriptor());
    let wait_ctx: WaitContext<Token> =
        WaitContext::build_with(&[(&descriptor, Token::Alarm), (&kill_evt, Token::Kill)])
            .context("worker context failed")?;

    while len > 0 {
        let events = wait_ctx.wait().context("wait failed")?;
        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::Alarm => {
                    let _ = timer.mark_waited().context("failed to reset timer")?;
                    len = len.saturating_sub(TRUNCATE_STEP_BYTES);
                    file.set_len(len).context("failed to truncate file")?;
                }
                Token::Kill => {
                    file.set_len(0).context("failed to clear file")?;
                    return Ok(file);
                }
            }
        }
    }
    Ok(file)
}

impl FileTruncator {
    /// Creates an new [FileTruncator] to truncate the given file.
    ///
    /// # Arguments
    ///
    /// * `file` - The file to truncate.
    pub fn new(file: File) -> Result<Self> {
        let timer = Timer::new().context("failed to create truncate timer")?;
        Self::new_inner(Box::new(timer), file)
    }

    fn new_inner(mut timer: Box<dyn TimerTrait>, file: File) -> Result<Self> {
        timer
            .reset(TRUNCATE_INITIAL_WAIT, Some(TRUNCATE_INTERVAL))
            .context("failed to arm timer")?;
        Ok(Self {
            worker: Some(WorkerThread::start(
                "truncate_worker",
                move |kill_evt| -> Result<File> { truncate_worker(timer, file, kill_evt) },
            )),
        })
    }

    /// Retrieves the underlying file, which is guaranteed to be truncated.
    ///
    /// If this function is called while the background worker thread has not
    /// finished, it may block briefly while stopping the background worker.
    pub fn take_file(mut self) -> Result<File> {
        let file = self
            .worker
            .take()
            .context("missing worker")?
            .stop()
            .context("worker failure")?;
        Ok(file)
    }
}

impl Drop for FileTruncator {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use base::FakeClock;
    use base::FakeTimer;
    use sync::Mutex;

    use super::*;

    fn wait_for_target_length(file: &mut File, len: u64) {
        let mut count = 0;
        while file.seek(SeekFrom::End(0)).unwrap() != len && count < 100 {
            std::thread::sleep(Duration::from_millis(1));
            count += 1;
        }
        assert_eq!(file.seek(SeekFrom::End(0)).unwrap(), len);
    }

    #[test]
    fn test_full_truncate() {
        let mut file = tempfile::tempfile().unwrap();
        let clock = Arc::new(Mutex::new(FakeClock::new()));
        let timer = Box::new(FakeTimer::new(clock.clone()));

        file.set_len(2 * TRUNCATE_STEP_BYTES).unwrap();

        let worker = FileTruncator::new_inner(timer, file.try_clone().unwrap()).unwrap();
        clock.lock().add_ns(TRUNCATE_INITIAL_WAIT.as_nanos() as u64);
        wait_for_target_length(&mut file, TRUNCATE_STEP_BYTES);
        clock.lock().add_ns(TRUNCATE_INTERVAL.as_nanos() as u64);
        wait_for_target_length(&mut file, 0);

        let _ = worker.take_file().unwrap();
    }

    #[test]
    fn test_early_exit() {
        let mut file = tempfile::tempfile().unwrap();
        let clock = Arc::new(Mutex::new(FakeClock::new()));
        let timer = Box::new(FakeTimer::new(clock));

        file.set_len(2 * TRUNCATE_STEP_BYTES).unwrap();

        let worker = FileTruncator::new_inner(timer, file.try_clone().unwrap()).unwrap();

        let _ = worker.take_file().unwrap();
        assert_eq!(file.seek(SeekFrom::End(0)).unwrap(), 0);
    }
}
