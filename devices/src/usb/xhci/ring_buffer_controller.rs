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
use super::xhci_abi::TransferDescriptor;
use crate::usb::xhci::xhci_abi::AddressedTrb;
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
    /// Stopped: RingBuffer already stopped.
    Stopped,
}

/// TransferDescriptorHandler handles transfer descriptor. User should implement this trait and
/// build a ring buffer controller with the struct.
pub trait TransferDescriptorHandler {
    /// Process descriptor asynchronously, signal trigger_event when ready to proceed.
    fn handle_transfer_descriptor(
        &self,
        descriptor: TransferDescriptor,
        trigger_event: Event,
    ) -> anyhow::Result<()>;

    /// Cancel transfers. This is used to stop the ring activity as soon as possible when we
    /// process a Stop Endpoint command.
    /// xHCI spec 4.6.9 states we need to stop the USB activity for the pipe before sending the
    /// completion event. Use the callback to ensure that all the in-flight transfers are gone
    /// before sending the event, if the backend cannot immediately cancel them.
    fn cancel_transfers(&self, _callback: RingBufferStopCallback) {}
}

/// RingBufferController owns a ring buffer. It lives on a event_loop. It will pop out transfer
/// descriptor and let TransferDescriptorHandler handle it.
pub struct RingBufferController<T: 'static + TransferDescriptorHandler> {
    name: String,
    state: Mutex<RingBufferState>,
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

    /// Get dequeue pointer and consumer cycle state of the ring buffer when it is stopped.
    // This function should only be called when stopping an endpoint, since it synchronizes the
    // internal dequeue pointers and the consumer cycle states.
    pub fn get_stopped_dequeue_state(&self) -> (GuestAddress, bool) {
        let mut locked = self.lock_ring_buffer();
        locked.synchronize_with_hardware();
        (
            locked.get_dequeue_pointer(),
            locked.get_consumer_cycle_state(),
        )
    }

    /// Set dequeue pointer of the internal ring buffer.
    pub fn set_dequeue_pointer(&self, ptr: GuestAddress) {
        xhci_trace!("{}: set_dequeue_pointer({:x})", self.name, ptr.0);
        // Fast because this should only happen during xhci setup.
        self.lock_ring_buffer().set_dequeue_pointer(ptr);
    }

    /// Set consumer cycle state.
    pub fn set_consumer_cycle_state(&self, state: bool) {
        xhci_trace!("{}: set consumer cycle state: {}", self.name, state);
        // Fast because this should only happen during xhci setup.
        self.lock_ring_buffer().set_consumer_cycle_state(state);
    }

    /// Start the ring buffer.
    pub fn start(&self) {
        xhci_trace!("start {}", self.name);
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
        xhci_trace!("stop {}", self.name);
        let mut state = self.state.lock();
        // Always issue the cancel, because the ring can also be Stopped when it has submitted all
        // the transfer requests in the ring but it hasn't reaped them yet.
        self.handler.lock().cancel_transfers(callback);
        *state = RingBufferState::Stopped;
    }

    /// Report completion of TRB to the ring buffer.
    pub fn report_completed_trb(&self, trb: &AddressedTrb) {
        self.lock_ring_buffer().complete(trb);
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

    use base::pagesize;

    use super::super::xhci_abi::LinkTrb;
    use super::super::xhci_abi::NormalTrb;
    use super::super::xhci_abi::Trb;
    use super::super::xhci_abi::TrbType;
    use super::*;

    struct TestHandler {
        sender: Sender<i32>,
    }

    impl TransferDescriptorHandler for TestHandler {
        fn handle_transfer_descriptor(
            &self,
            descriptor: TransferDescriptor,
            trigger_event: Event,
        ) -> anyhow::Result<()> {
            for atrb in &descriptor {
                assert_eq!(atrb.trb.get_trb_type().unwrap(), TrbType::Normal);
                self.sender.send(atrb.trb.get_parameter() as i32).unwrap();
            }
            trigger_event.signal().unwrap();
            Ok(())
        }
    }

    struct TestLazyHandler {
        sender: Sender<u64>,
        processing: Mutex<Vec<u64>>,
    }

    impl TransferDescriptorHandler for TestLazyHandler {
        fn handle_transfer_descriptor(
            &self,
            descriptor: TransferDescriptor,
            trigger_event: Event,
        ) -> anyhow::Result<()> {
            let mut locked = self.processing.lock();
            for a in locked.iter() {
                self.sender.send(*a).unwrap();
            }
            trigger_event.signal().unwrap();
            *locked = descriptor.iter().map(|atrb| atrb.gpa).collect();
            Ok(())
        }

        fn cancel_transfers(&self, _callback: RingBufferStopCallback) {}
    }

    fn setup_mem() -> GuestMemory {
        let trb_size = size_of::<Trb>() as u64;
        let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();

        // Structure of ring buffer:
        //  0x100  --> 0x200  --> 0x300
        //  trb 1  |   trb 3  |   trb 5
        //  trb 2  |   trb 4  |   trb 6
        //  l trb  -   l trb  -   l trb to 0x100
        let mut trb = NormalTrb::new();
        trb.set_trb_type(TrbType::Normal);
        trb.set_data_buffer_pointer(1);
        trb.set_chain(true);
        gm.write_obj_at_addr(trb, GuestAddress(0x100)).unwrap();

        trb.set_data_buffer_pointer(2);
        gm.write_obj_at_addr(trb, GuestAddress(0x100 + trb_size))
            .unwrap();

        let mut ltrb = LinkTrb::new();
        ltrb.set_trb_type(TrbType::Link);
        ltrb.set_ring_segment_pointer(0x200);
        gm.write_obj_at_addr(ltrb, GuestAddress(0x100 + 2 * trb_size))
            .unwrap();

        trb.set_data_buffer_pointer(3);
        gm.write_obj_at_addr(trb, GuestAddress(0x200)).unwrap();

        // Chain bit is false.
        trb.set_data_buffer_pointer(4);
        trb.set_chain(false);
        gm.write_obj_at_addr(trb, GuestAddress(0x200 + 1 * trb_size))
            .unwrap();

        ltrb.set_ring_segment_pointer(0x300);
        gm.write_obj_at_addr(ltrb, GuestAddress(0x200 + 2 * trb_size))
            .unwrap();

        trb.set_data_buffer_pointer(5);
        trb.set_chain(true);
        gm.write_obj_at_addr(trb, GuestAddress(0x300)).unwrap();

        // Chain bit is false.
        trb.set_data_buffer_pointer(6);
        trb.set_chain(false);
        gm.write_obj_at_addr(trb, GuestAddress(0x300 + 1 * trb_size))
            .unwrap();

        ltrb.set_ring_segment_pointer(0x100);
        ltrb.set_toggle_cycle(true);
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

    #[test]
    fn synchronize_dequeue_pointer() {
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
        for i in 1..=6 {
            assert_eq!(rx.recv().unwrap(), i);
        }

        let mut trb = Trb::new();
        trb.set_cycle(false);
        let atrb = AddressedTrb { trb, gpa: 0x210 };
        let null_callback = RingBufferStopCallback::new(move || {});
        controller.stop(null_callback);
        controller.report_completed_trb(&atrb);
        let (dq, cycle) = controller.get_stopped_dequeue_state();
        assert_eq!(dq.offset(), 0x220);
        assert_eq!(cycle, false); // We haven't crossed the LinkTRB at 0x320 yet.
        l.stop();
        j.join().unwrap();
    }

    #[test]
    fn synchronize_dequeue_pointer_across_link_trb() {
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

        // Wait for the software to read all 6 TRBs.
        // During this process, it reads the Link TRB at 0x320 which has Toggle Cycle = true.
        // Therefore, the software's internal consumer_cycle_state becomes TRUE.
        for i in 1..=6 {
            assert_eq!(rx.recv().unwrap(), i);
        }

        // We report completion of TRB 5 at 0x300.
        // The hardware pointer will advance to 0x310.
        // It has NOT crossed the Link TRB at 0x320 yet, so the hardware state is still FALSE.
        let mut trb = Trb::new();
        trb.set_cycle(false);
        let atrb = AddressedTrb { trb, gpa: 0x300 };
        let null_callback = RingBufferStopCallback::new(move || {});
        controller.stop(null_callback);
        controller.report_completed_trb(&atrb);
        let (dq, cycle) = controller.get_stopped_dequeue_state();
        assert_eq!(dq.offset(), 0x310);
        assert_eq!(cycle, false);
        l.stop();
        j.join().unwrap();
    }

    #[test]
    fn synchronize_dequeue_pointer_for_lazy_handler() {
        let (tx, rx) = channel();
        let mem = setup_mem();
        let (l, j) = EventLoop::start("test".to_string(), None).unwrap();
        let l = Arc::new(l);
        let controller = RingBufferController::new_with_handler(
            "".to_string(),
            mem,
            l.clone(),
            TestLazyHandler {
                sender: tx,
                processing: Mutex::new(Vec::new()),
            },
        )
        .unwrap();
        controller.set_dequeue_pointer(GuestAddress(0x100));
        controller.set_consumer_cycle_state(false);
        controller.start();
        assert_eq!(rx.recv().unwrap(), 0x100);
        assert_eq!(rx.recv().unwrap(), 0x110);
        assert_eq!(rx.recv().unwrap(), 0x200);
        assert_eq!(rx.recv().unwrap(), 0x210);
        assert!(rx.try_recv().is_err());

        let null_callback = RingBufferStopCallback::new(move || {});
        controller.stop(null_callback);
        // Since we didn't call report_completed_trb(), the hw dequeue pointer should still point
        // to the very first TRB.
        let (dq, cycle) = controller.get_stopped_dequeue_state();
        assert_eq!(dq.offset(), 0x100);
        assert_eq!(cycle, false);
        l.stop();
        j.join().unwrap();
    }
}
