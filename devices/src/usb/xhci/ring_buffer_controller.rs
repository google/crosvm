// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::ring_buffer_stop_cb::RingBufferStopCallback;
use super::xhci_abi::*;
use crate::utils::{self, EventHandler, EventLoop};
use std::fmt::{self, Display};
use std::sync::{Arc, MutexGuard};
use sync::Mutex;

use sys_util::{error, Error as SysError, EventFd, GuestAddress, GuestMemory, WatchingEvents};

use super::ring_buffer::RingBuffer;

#[derive(Debug)]
pub enum Error {
    AddEvent(utils::Error),
    CreateEventFd(SysError),
}

type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            AddEvent(e) => write!(f, "failed to add event to event loop: {}", e),
            CreateEventFd(e) => write!(f, "failed to create event fd: {}", e),
        }
    }
}

#[derive(PartialEq, Copy, Clone)]
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
        complete_event: EventFd,
    ) -> std::result::Result<(), ()>;
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
    event: EventFd,
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
        let evt = EventFd::new().map_err(Error::CreateEventFd)?;
        let controller = Arc::new(RingBufferController {
            name: name.clone(),
            state: Mutex::new(RingBufferState::Stopped),
            stop_callback: Mutex::new(Vec::new()),
            ring_buffer: Mutex::new(RingBuffer::new(name.clone(), mem)),
            handler: Mutex::new(handler),
            event_loop: event_loop.clone(),
            event: evt,
        });
        let event_handler: Arc<dyn EventHandler> = controller.clone();
        event_loop
            .add_event(
                &controller.event,
                WatchingEvents::empty().set_read(),
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
            if let Err(e) = self.event.write(1) {
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
        if let Err(e) = self.event_loop.remove_event_for_fd(&self.event) {
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
    fn on_event(&self) -> std::result::Result<(), ()> {
        // `self.event` triggers ring buffer controller to run, the value read is not important.
        match self.event.read() {
            Ok(_) => {}
            Err(e) => {
                error!("cannot read from event fd: {}", e);
                return Err(());
            }
        }
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

        let transfer_descriptor = match self.lock_ring_buffer().dequeue_transfer_descriptor() {
            Ok(t) => t,
            Err(e) => {
                error!("cannot dequeue transfer descriptor: {}", e);
                return Err(());
            }
        };

        let transfer_descriptor = match transfer_descriptor {
            Some(t) => t,
            None => {
                *state = RingBufferState::Stopped;
                self.stop_callback.lock().clear();
                return Ok(());
            }
        };

        let event = match self.event.try_clone() {
            Ok(evt) => evt,
            Err(e) => {
                error!("cannot clone event fd: {}", e);
                return Err(());
            }
        };
        self.handler
            .lock()
            .handle_transfer_descriptor(transfer_descriptor, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;
    use std::sync::mpsc::{channel, Sender};

    struct TestHandler {
        sender: Sender<i32>,
    }

    impl TransferDescriptorHandler for TestHandler {
        fn handle_transfer_descriptor(
            &self,
            descriptor: TransferDescriptor,
            complete_event: EventFd,
        ) -> std::result::Result<(), ()> {
            for atrb in descriptor {
                assert_eq!(atrb.trb.get_trb_type().unwrap(), TrbType::Normal);
                self.sender.send(atrb.trb.get_parameter() as i32).unwrap();
            }
            complete_event.write(1).unwrap();
            Ok(())
        }
    }

    fn setup_mem() -> GuestMemory {
        let trb_size = size_of::<Trb>() as u64;
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();

        // Structure of ring buffer:
        //  0x100  --> 0x200  --> 0x300
        //  trb 1  |   trb 3  |   trb 5
        //  trb 2  |   trb 4  |   trb 6
        //  l trb  -   l trb  -   l trb to 0x100
        let mut trb = NormalTrb::new();
        trb.set_trb_type(TrbType::Normal);
        trb.set_data_buffer(1);
        trb.set_chain(true);
        gm.write_obj_at_addr(trb.clone(), GuestAddress(0x100))
            .unwrap();

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
