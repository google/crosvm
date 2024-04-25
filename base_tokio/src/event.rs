// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(test)]
mod tests {
    use base::Event;

    use crate::EventTokio;

    #[tokio::test]
    async fn already_signaled() {
        let event = Event::new().unwrap();
        let async_event = EventTokio::new(event.try_clone().unwrap()).unwrap();

        event.signal().unwrap();
        async_event.wait().await.unwrap();
    }

    #[tokio::test]
    async fn signaled_after_delay() {
        let event = Event::new().unwrap();
        let async_event = EventTokio::new(event.try_clone().unwrap()).unwrap();

        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            event.signal().unwrap();
        });
        async_event.wait().await.unwrap();
    }
}
