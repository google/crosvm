// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[macro_export]
macro_rules! generate_scoped_event {
    ($event:ident) => {
        /// An `Event` wrapper which triggers when it goes out of scope.
        ///
        /// If the underlying `Event` fails to trigger during drop, a panic is triggered instead.
        pub struct ScopedEvent($event);

        impl ScopedEvent {
            /// Creates a new `ScopedEvent` which triggers when it goes out of scope.
            pub fn new() -> Result<ScopedEvent> {
                Ok($event::new()?.into())
            }
        }

        impl From<$event> for ScopedEvent {
            fn from(e: $event) -> Self {
                Self(e)
            }
        }

        impl From<ScopedEvent> for $event {
            fn from(scoped_event: ScopedEvent) -> Self {
                // Rust doesn't allow moving out of types with a Drop implementation, so we have to
                // use something that copies instead of moves. This is safe because we prevent the
                // drop of `scoped_event` using `mem::forget`, so the underlying `Event` will not
                // experience a double-drop.
                let evt = unsafe { ptr::read(&scoped_event.0) };
                mem::forget(scoped_event);
                evt
            }
        }

        impl Deref for ScopedEvent {
            type Target = $event;

            fn deref(&self) -> &$event {
                &self.0
            }
        }

        impl Drop for ScopedEvent {
            fn drop(&mut self) {
                self.write(1).expect("failed to trigger scoped event");
            }
        }
    };
}
