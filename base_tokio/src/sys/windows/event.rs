// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// An async version of `base::Event`.
pub struct EventTokio(base::Event);

impl EventTokio {
    /// Must be a manual-reset event (i.e. created by `base::Event::new()`).
    ///
    /// TODO: Add support for auto-reset events.
    pub fn new(event: base::Event) -> anyhow::Result<Self> {
        Ok(Self(event))
    }

    /// Blocks until the event is signaled and clears the signal.
    ///
    /// It is undefined behavior to wait on an event from multiple threads or processes
    /// simultaneously.
    pub async fn wait(&self) -> std::io::Result<()> {
        base::sys::windows::async_wait_for_single_object(&self.0).await?;
        self.0.reset()?;
        Ok(())
    }
}
