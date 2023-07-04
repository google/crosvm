// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::TimerTrait;

use crate::AsyncResult;
use crate::IntoAsync;
use crate::TimerAsync;

impl<T: TimerTrait + IntoAsync> TimerAsync<T> {
    pub async fn wait_sys(&self) -> AsyncResult<()> {
        self.io_source.wait_for_handle().await
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;
    use std::time::Instant;

    use super::*;
    use crate::Executor;

    #[test]
    fn timer() {
        async fn this_test(ex: &Executor) {
            // On Windows, SetWaitableTimer, the underlying timer API, is not
            // guaranteed to sleep for *at least* the supplied duration, so here
            // we permit early wakeups.
            let dur = Duration::from_millis(200);
            let min_duration = Duration::from_millis(150);

            let now = Instant::now();
            TimerAsync::sleep(ex, dur).await.expect("unable to sleep");
            let actual_sleep_duration = now.elapsed();
            assert!(actual_sleep_duration >= min_duration);
        }

        let ex = Executor::new().expect("creating an executor failed");
        ex.run_until(this_test(&ex)).unwrap();
    }
}
