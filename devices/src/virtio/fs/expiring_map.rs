// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

pub struct ExpiringMap<K, V> {
    limit: Duration,
    map: BTreeMap<K, (V, Instant)>,
    dq: VecDeque<(K, Instant)>,
}

impl<K, V> ExpiringMap<K, V>
where
    K: Clone + Ord,
{
    pub fn new(limit: Duration) -> Self {
        Self {
            limit,
            map: Default::default(),
            dq: Default::default(),
        }
    }

    fn cleanup(&mut self, now: &Instant) {
        while let Some((k, prev)) = self.dq.front() {
            if now.duration_since(*prev) < self.limit {
                return;
            }
            self.map.remove(k);
            self.dq.pop_front();
        }
    }

    #[cfg(test)]
    pub fn get(&mut self, key: &K) -> Option<&V> {
        let now = Instant::now();
        self.cleanup(&now);
        self.map.get(key).map(|(v, _)| v)
    }

    pub fn get_or_insert_with<F: FnOnce() -> std::result::Result<V, E>, E>(
        &mut self,
        key: &K,
        f: F,
    ) -> std::result::Result<&V, E> {
        let now = Instant::now();
        self.cleanup(&now);

        if self.map.get(key).is_some() {
            Ok(self.map.get(key).map(|(v, _)| v).expect("must exist"))
        } else {
            self.dq.push_back((key.clone(), now));
            self.map.insert(key.clone(), (f()?, now));
            Ok(self.map.get(key).map(|(v, _)| v).expect("must exist"))
        }
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let now = Instant::now();
        self.cleanup(&now);
        self.map.get_mut(key).map(|(v, _)| v)
    }

    pub fn remove(&mut self, key: &K) {
        self.map.remove(key);
        self.dq.retain(|(k, _)| k != key);
    }
}
