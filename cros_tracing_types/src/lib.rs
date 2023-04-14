// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use anyhow::bail;

pub mod static_strings;

/// Sets the duration for a trace.
pub enum TraceDuration {
    AlwaysOn,
    StopIn(Duration),
}

impl TryFrom<TraceDuration> for Duration {
    type Error = anyhow::Error;

    fn try_from(duration: TraceDuration) -> anyhow::Result<Self> {
        match duration {
            TraceDuration::AlwaysOn => Ok(Duration::from_millis(0)),
            TraceDuration::StopIn(d) if !d.is_zero() => Ok(d),
            TraceDuration::StopIn(_) => {
                bail!("zero duration not permitted; did you mean TraceDuration::AlwaysOn?")
            }
        }
    }
}
