// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub use super::wait::*;
use super::RawDescriptor;
use crate::descriptor::AsRawDescriptor;
use crate::EventToken;

/// Represents descriptor-token pairs which represent an event which can be triggered in the
/// EventContext
#[derive(PartialEq)]
pub struct EventTrigger<T: EventToken> {
    pub(crate) token: T,
    pub(crate) event: RawDescriptor,
}

impl<T: EventToken> EventTrigger<T> {
    pub fn from(descriptor: &dyn AsRawDescriptor, token: T) -> Self {
        EventTrigger {
            token,
            event: descriptor.as_raw_descriptor(),
        }
    }
}

impl<T: EventToken> Clone for EventTrigger<T> {
    fn clone(&self) -> Self {
        EventTrigger {
            token: T::from_raw_token(self.token.as_raw_token()),
            event: self.event,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::PlatformEvent;
    use super::*;

    #[test]
    fn event_context() {
        let evt1 = PlatformEvent::new().unwrap();
        let evt2 = PlatformEvent::new().unwrap();
        evt1.write(1).unwrap();
        evt2.write(1).unwrap();
        let ctx: EventContext<u32> =
            EventContext::build_with(&[EventTrigger::from(&evt1, 1), EventTrigger::from(&evt2, 2)])
                .unwrap();

        let mut evt_count = 0;
        while evt_count < 2 {
            for event in ctx.wait().unwrap().iter() {
                evt_count += 1;
                match event.token {
                    1 => {
                        evt1.read().unwrap();
                        ctx.delete(&evt1).unwrap();
                    }
                    2 => {
                        evt2.read().unwrap();
                        ctx.delete(&evt2).unwrap();
                    }
                    _ => panic!("unexpected token"),
                };
            }
        }
        assert_eq!(evt_count, 2);
    }

    // TODO(145170451) rizhang: This test will be needed to be implemented when the round robn
    // implementation is complete
    // #[test]
    // fn poll_context_overflow() {
    //     const EVT_COUNT: usize = MAXIMUM_WAIT_OBJECTS * 2 + 1;
    //     let ctx: EventContext<usize> = EventContext::new().unwrap();
    //     let mut evts = Vec::with_capacity(EVT_COUNT);
    //     for i in 0..EVT_COUNT {
    //         let evt = PlatformEvent::new().unwrap();
    //         evt.write(1).unwrap();
    //         ctx.add(&evt, i).unwrap();
    //         evts.push(evt);
    //     }
    //     let mut evt_count = 0;
    //     while evt_count < EVT_COUNT {
    //         for event in ctx.wait().unwrap().iter_readable() {
    //             evts[event.token()].read().unwrap();
    //             evt_count += 1;
    //         }
    //     }
    // }

    #[test]
    fn poll_context_timeout() {
        let ctx: EventContext<u32> = EventContext::new().unwrap();
        let evt = PlatformEvent::new().unwrap();
        ctx.add(EventTrigger::from(&evt, 1))
            .expect("Failed to add event.");
        let dur = Duration::from_millis(100);
        let events = ctx.wait_timeout(dur).unwrap();
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn wait_returns_mulitple_signal_events() {
        let evt1 = PlatformEvent::new().unwrap();
        let evt2 = PlatformEvent::new().unwrap();
        let evt3 = PlatformEvent::new().unwrap();
        evt1.write(1).expect("Failed to write to event.");
        evt2.write(1).expect("Failed to write to event.");
        evt3.write(1).expect("Failed to write to event.");
        let ctx: EventContext<u32> = EventContext::build_with(&[
            EventTrigger::from(&evt1, 1),
            EventTrigger::from(&evt2, 2),
            EventTrigger::from(&evt3, 3),
        ])
        .unwrap();
        let events = ctx.wait().unwrap();

        let tokens: Vec<u32> = events.iter().map(|e| e.token).collect();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens, [1, 2, 3]);
    }

    #[test]
    fn wait_returns_mulitple_signal_and_unsignaled_events() {
        let evt1 = PlatformEvent::new().unwrap();
        let evt2 = PlatformEvent::new().unwrap();
        let evt3 = PlatformEvent::new().unwrap();
        let evt4 = PlatformEvent::new().unwrap();
        let evt5 = PlatformEvent::new().unwrap();
        let evt6 = PlatformEvent::new().unwrap();
        let evt7 = PlatformEvent::new().unwrap();
        evt1.write(1).unwrap();
        evt2.write(1).unwrap();
        evt4.write(1).unwrap();
        evt7.write(1).unwrap();
        let ctx: EventContext<u32> = EventContext::build_with(&[
            EventTrigger::from(&evt1, 1),
            EventTrigger::from(&evt2, 2),
            EventTrigger::from(&evt3, 3),
            EventTrigger::from(&evt4, 4),
            EventTrigger::from(&evt5, 5),
            EventTrigger::from(&evt6, 6),
            EventTrigger::from(&evt7, 7),
        ])
        .unwrap();
        let events = ctx.wait().unwrap();

        let tokens: Vec<u32> = events.iter().map(|e| e.token).collect();
        assert_eq!(tokens.len(), 4);
        assert_eq!(tokens, [1, 2, 4, 7]);
    }
}
