// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(test)]
mod tests {
    use base::Tube;

    use crate::TubeTokio;

    #[tokio::test]
    async fn recv_send() {
        let (a, b) = Tube::pair().unwrap();
        let mut b = TubeTokio::new(b).unwrap();

        let blocking_task = tokio::task::spawn_blocking(move || {
            a.send(&5u8).unwrap();
            a.recv::<u8>().unwrap()
        });

        assert_eq!(b.recv::<u8>().await.unwrap(), 5u8);
        b.send(&16u8).await.unwrap();
        assert_eq!(blocking_task.await.unwrap(), 16u8);
    }
}
