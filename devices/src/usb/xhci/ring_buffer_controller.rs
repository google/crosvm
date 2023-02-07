// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::fmt::Display;
use std::sync::Arc;
use std::sync::MutexGuard;

use anyhow::Context;
use base::error;
use base::Error as SysError;
use base::Event;
use base::EventType;
use remain::sorted;
use sync::Mutex;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use super::ring_buffer::RingBuffer;
use super::ring_buffer_stop_cb::RingBufferStopCallback;
use super::xhci_abi::*;
use crate::utils;
use crate::utils::EventHandler;
use crate::utils::EventLoop;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to add event to event loop: {0}")]
    AddEvent(utils::Error),
    #[error("failed to create event: {0}")]
    CreateEvent(SysError),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(PartialEq, Copy, Clone, Eq)]
enum RingBufferState {
    /// Running: RingBuffer is running, consuming transfer descriptor.
    Running,
    /// Stopping: Some thread requested RingBuffer stop. It will stop when current descriptor is
    /// handled.
    Stopping,
    /// Stopped: RingBuffer already stopped.
    Stopped,
}

/// TransferDescriptorHandler handles transfer descriptor. User should implement this trait and
/// build a ring buffer controller with the struct.
pub trait TransferDescriptorHandler {
    /// Process descriptor asynchronously, write complete_event when done.
    fn handle_transfer_descriptor(
        &self,
        descriptor: TransferDescriptor,
        complete_event: Event,
    ) -> anyhow::Result<()>;

    /// Stop is called when trying to stop ring buffer controller. Returns true when stop must be
    /// performed asynchronously. This happens because the handler is handling some descriptor
    /// asynchronously, the stop callback of ring buffer controller must be called after the
    /// `async` part is handled or canceled. If the TransferDescriptorHandler decide it could stop
    /// immediately, it could return false.
    /// For example, if a handler submitted a transfer but the transfer has not yet finished. Then
    /// guest kernel requests to stop the ring buffer controller. Transfer descriptor handler will
    /// return true, thus RingBufferController would transfer to Stopping state. It will be stopped
    /// when all pending transfer completed.
    /// On the other hand, if hander does not have any pending transfers, it would return false.
    fn stop(&self) -> bool {
        true
    }
}

/// RingBufferController owns a ring buffer. It lives on a event_loop. It will pop out transfer
/// descriptor and let TransferDescriptorHandler handle it.
pub struct RingBufferController<T: 'static + TransferDescriptorHandler> {
    name: String,
    state: Mutex<RingBufferState>,
    stop_callback: Mutex<Vec<RingBufferStopCallback>>,
    ring_buffer: Mutex<RingBuffer>,
    handler: Mutex<T>,
    event_loop: Arc<EventLoop>,
    event: Event,
}

impl<T: 'static + TransferDescriptorHandler> Display for RingBufferController<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RingBufferController `{}`", self.name)
    }
}

impl<T: Send> RingBufferController<T>
where
    T: 'static + TransferDescriptorHandler,
{
    /// Create a ring buffer controller and add it to event loop.
    pub fn new_with_handler(
        name: String,
        mem: GuestMemory,
        event_loop: Arc<EventLoop>,
        handler: T,
    ) -> Result<Arc<RingBufferController<T>>> {
        let evt = Event::new().map_err(Error::CreateEvent)?;
        let controller = Arc::new(RingBufferController {
            name: name.clone(),
            state: Mutex::new(RingBufferState::Stopped),
            stop_callback: Mutex::new(Vec::new()),
            ring_buffer: Mutex::new(RingBuffer::new(name, mem)),
            handler: Mutex::new(handler),
            event_loop: event_loop.clone(),
            event: evt,
        });
        let event_handler: Arc<dyn EventHandler> = controller.clone();
        event_loop
            .add_event(
                &controller.event,
                EventType::Read,
                Arc::downgrade(&event_handler),
            )
            .map_err(Error::AddEvent)?;
        Ok(controller)
    }

    fn lock_ring_buffer(&self) -> MutexGuard<RingBuffer> {
        self.ring_buffer.lock()
    }

    /// Set dequeue pointer of the internal ring buffer.
    pub fn set_dequeue_pointer(&self, ptr: GuestAddress) {
        usb_debug!("{}: set dequeue pointer: {:x}", self.name, ptr.0);
        // Fast because this should only happen during xhci setup.
        self.lock_ring_buffer().set_dequeue_pointer(ptr);
    }

    /// Set consumer cycle state.
    pub fn set_consumer_cycle_state(&self, state: bool) {
        usb_debug!("{}: set consumer cycle state: {}", self.name, state);
        // Fast because this should only happen during xhci setup.
        self.lock_ring_buffer().set_consumer_cycle_state(state);
    }

    /// Start the ring buffer.
    pub fn start(&self) {
        usb_debug!("{} started", self.name);
        let mut state = self.state.lock();
        if *state != RingBufferState::Running {
            *state = RingBufferState::Running;
            if let Err(e) = self.event.signal() {
                error!("cannot start event ring: {}", e);
            }
        }
    }

    /// Stop the ring buffer asynchronously.
    pub fn stop(&self, callback: RingBufferStopCallback) {
        usb_debug!("{} being stopped", self.name);
        let mut state = self.state.lock();
        if *state == RingBufferState::Stopped {
            usb_debug!("{} is already stopped", self.name);
            return;
        }
        if self.handler.lock().stop() {
            *state = RingBufferState::Stopping;
            self.stop_callback.lock().push(callback);
        } else {
            *state = RingBufferState::Stopped;
        }
    }
}

impl<T> Drop for RingBufferController<T>
where
    T: 'static + TransferDescriptorHandler,
{
    fn drop(&mut self) {
        // Remove self from the event loop.
        if let Err(e) = self.event_loop.remove_event_for_descriptor(&self.event) {
            error!(
                "cannot remove ring buffer controller from event loop: {}",
                e
            );
        }
    }
}

impl<T> EventHandler for RingBufferController<T>
where
    T: 'static + TransferDescriptorHandler + Send,
{
    fn on_event(&self) -> anyhow::Result<()> {
        // `self.event` triggers ring buffer controller to run.
        self.event.wait().context("cannot read from event")?;
        let mut state = self.state.lock();

        match *state {
            RingBufferState::Stopped => return Ok(()),
            RingBufferState::Stopping => {
                usb_debug!("{}: stopping ring buffer controller", self.name);
                *state = RingBufferState::Stopped;
                self.stop_callback.lock().clear();
                return Ok(());
            }
            RingBufferState::Running => {}
        }

        let transfer_descriptor = self
            .lock_ring_buffer()
            .dequeue_transfer_descriptor()
            .context("cannot dequeue transfer descriptor")?;

        let transfer_descriptor = match transfer_descriptor {
            Some(t) => t,
            None => {
                *state = RingBufferState::Stopped;
                self.stop_callback.lock().clear();
                return Ok(());
            }
        };

        let event = self.event.try_clone().context("cannot clone event")?;
        self.handler
            .lock()
            .handle_transfer_descriptor(transfer_descriptor, event)
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;
    use std::sync::mpsc::channel;
    use std::sync::mpsc::Sender;

    use super::*;

    struct TestHandler {
        sender: Sender<i32>,
    }

    impl TransferDescriptorHandler for TestHandler {
        fn handle_transfer_descriptor(
            &self,
            descriptor: TransferDescriptor,
            complete_event: Event,
        ) -> anyhow::Result<()> {
            for atrb in descriptor {
                assert_eq!(atrb.trb.get_trb_type().unwrap(), TrbType::Normal);
                self.sender.send(atrb.trb.get_parameter() as i32).unwrap();
            }
            complete_event.signal().unwrap();
            Ok(())
        }
    }

    fn setup_mem() -> GuestMemory {
        let trb_size = size_of::<Trb>() as u64;
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Structure of ring buffer:
        //  0x100  --> 0x200  --> 0x300
        //  trb 1  |   trb 3  |   trb 5
        //  trb 2  |   trb 4  |   trb 6
        //  l trb  -   l trb  -   l trb to 0x100
        let mut trb = NormalTrb::new();
        trb.set_trb_type(TrbType::Normal);
        trb.set_data_buffer(1);
        trb.set_chain(true);
        gm.write_obj_at_addr(trb, GuestAddress(0x100)).unwrap();

        trb.set_data_buffer(2);
        gm.write_obj_at_addr(trb, GuestAddress(0x100 + trb_size))
            .unwrap();

        let mut ltrb = LinkTrb::new();
        ltrb.set_trb_type(TrbType::Link);
        ltrb.set_ring_segment_pointer(0x200);
        gm.write_obj_at_addr(ltrb, GuestAddress(0x100 + 2 * trb_size))
            .unwrap();

        trb.set_data_buffer(3);
        gm.write_obj_at_addr(trb, GuestAddress(0x200)).unwrap();

        // Chain bit is false.
        trb.set_data_buffer(4);
        trb.set_chain(false);
        gm.write_obj_at_addr(trb, GuestAddress(0x200 + 1 * trb_size))
            .unwrap();

        ltrb.set_ring_segment_pointer(0x300);
        gm.write_obj_at_addr(ltrb, GuestAddress(0x200 + 2 * trb_size))
            .unwrap();

        trb.set_data_buffer(5);
        trb.set_chain(true);
        gm.write_obj_at_addr(trb, GuestAddress(0x300)).unwrap();

        // Chain bit is false.
        trb.set_data_buffer(6);
        trb.set_chain(false);
        gm.write_obj_at_addr(trb, GuestAddress(0x300 + 1 * trb_size))
            .unwrap();

        ltrb.set_ring_segment_pointer(0x100);
        gm.write_obj_at_addr(ltrb, GuestAddress(0x300 + 2 * trb_size))
            .unwrap();
        gm
    }

    #[test]
    fn test_ring_buffer_controller() {
        let (tx, rx) = channel();
        let mem = setup_mem();
        let (l, j) = EventLoop::start("test".to_string(), None).unwrap();
        let l = Arc::new(l);
        let controller = RingBufferController::new_with_handler(
            "".to_string(),
            mem,
            l.clone(),
            TestHandler { sender: tx },
        )
        .unwrap();
        controller.set_dequeue_pointer(GuestAddress(0x100));
        controller.set_consumer_cycle_state(false);
        controller.start();
        assert_eq!(rx.recv().unwrap(), 1);
        assert_eq!(rx.recv().unwrap(), 2);
        assert_eq!(rx.recv().unwrap(), 3);
        assert_eq!(rx.recv().unwrap(), 4);
        assert_eq!(rx.recv().unwrap(), 5);
        assert_eq!(rx.recv().unwrap(), 6);
        l.stop();
        j.join().unwrap();
    }
}
