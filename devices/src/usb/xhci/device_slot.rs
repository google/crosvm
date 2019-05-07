// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::interrupter::Interrupter;
use super::transfer_ring_controller::{TransferRingController, TransferRingControllerError};
use super::usb_hub::{self, UsbHub};
use super::xhci_abi::{
    AddressDeviceCommandTrb, ConfigureEndpointCommandTrb, DequeuePtr, DeviceContext,
    DeviceSlotState, EndpointContext, EndpointState, EvaluateContextCommandTrb,
    InputControlContext, SlotContext, TrbCompletionCode, DEVICE_CONTEXT_ENTRY_SIZE,
};
use super::xhci_regs::{valid_slot_id, MAX_PORTS, MAX_SLOTS};
use crate::register_space::Register;
use crate::usb::xhci::ring_buffer_stop_cb::{fallible_closure, RingBufferStopCallback};
use crate::utils::{EventLoop, FailHandle};
use bit_field::Error as BitFieldError;
use std::fmt::{self, Display};
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use sync::Mutex;
use sys_util::{error, GuestAddress, GuestMemory, GuestMemoryError};

#[derive(Debug)]
pub enum Error {
    BadPortId(u8),
    ReadGuestMemory(GuestMemoryError),
    WriteGuestMemory(GuestMemoryError),
    WeakReferenceUpgrade,
    CallbackFailed,
    GetSlotContextState(BitFieldError),
    GetEndpointState(BitFieldError),
    GetPort(u8),
    GetTrc(u8),
    BadInputContextAddr(GuestAddress),
    BadDeviceContextAddr(GuestAddress),
    CreateTransferController(TransferRingControllerError),
}

type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            BadPortId(id) => write!(f, "device slot get a bad port id: {}", id),
            ReadGuestMemory(e) => write!(f, "failed to read guest memory: {}", e),
            WriteGuestMemory(e) => write!(f, "failed to write guest memory: {}", e),
            WeakReferenceUpgrade => write!(f, "failed to upgrade weak reference"),
            CallbackFailed => write!(f, "callback failed"),
            GetSlotContextState(e) => write!(f, "failed to get slot context state: {}", e),
            GetEndpointState(e) => write!(f, "failed to get endpoint state: {}", e),
            GetPort(v) => write!(f, "failed to get port: {}", v),
            GetTrc(v) => write!(f, "failed to get trc: {}", v),
            BadInputContextAddr(addr) => write!(f, "bad input context address: {}", addr),
            BadDeviceContextAddr(addr) => write!(f, "bad device context: {}", addr),
            CreateTransferController(e) => write!(f, "failed to create transfer controller: {}", e),
        }
    }
}

/// See spec 4.5.1 for dci.
/// index 0: Control endpoint. Device Context Index: 1.
/// index 1: Endpoint 1 out. Device Context Index: 2
/// index 2: Endpoint 1 in. Device Context Index: 3.
/// index 3: Endpoint 2 out. Device Context Index: 4
/// ...
/// index 30: Endpoint 15 in. Device Context Index: 31
pub const TRANSFER_RING_CONTROLLERS_INDEX_END: usize = 31;
/// End of device context index.
pub const DCI_INDEX_END: u8 = (TRANSFER_RING_CONTROLLERS_INDEX_END + 1) as u8;
/// Device context index of first transfer endpoint.
pub const FIRST_TRANSFER_ENDPOINT_DCI: u8 = 2;

fn valid_endpoint_id(endpoint_id: u8) -> bool {
    endpoint_id < DCI_INDEX_END && endpoint_id > 0
}

#[derive(Clone)]
pub struct DeviceSlots {
    fail_handle: Arc<dyn FailHandle>,
    hub: Arc<UsbHub>,
    slots: Vec<Arc<DeviceSlot>>,
}

impl DeviceSlots {
    pub fn new(
        fail_handle: Arc<dyn FailHandle>,
        dcbaap: Register<u64>,
        hub: Arc<UsbHub>,
        interrupter: Arc<Mutex<Interrupter>>,
        event_loop: Arc<EventLoop>,
        mem: GuestMemory,
    ) -> DeviceSlots {
        let mut slots = Vec::new();
        for slot_id in 1..=MAX_SLOTS {
            slots.push(Arc::new(DeviceSlot::new(
                slot_id,
                dcbaap.clone(),
                hub.clone(),
                interrupter.clone(),
                event_loop.clone(),
                mem.clone(),
            )));
        }
        DeviceSlots {
            fail_handle,
            hub,
            slots,
        }
    }

    /// Note that slot id starts from 1. Slot index start from 0.
    pub fn slot(&self, slot_id: u8) -> Option<Arc<DeviceSlot>> {
        if valid_slot_id(slot_id) {
            Some(self.slots[slot_id as usize - 1].clone())
        } else {
            error!(
                "trying to index a wrong slot id {}, max slot = {}",
                slot_id, MAX_SLOTS
            );
            None
        }
    }

    /// Reset the device connected to a specific port.
    pub fn reset_port(&self, port_id: u8) -> std::result::Result<(), ()> {
        if let Some(port) = self.hub.get_port(port_id) {
            if let Some(backend_device) = port.get_backend_device().as_mut() {
                backend_device.reset()?;
            }
        }

        // No device on port, so nothing to reset.
        Ok(())
    }

    /// Stop all device slots and reset them.
    pub fn stop_all_and_reset<C: FnMut() + 'static + Send>(&self, mut callback: C) {
        usb_debug!("stopping all device slots and resetting host hub");
        let slots = self.slots.clone();
        let hub = self.hub.clone();
        let auto_callback = RingBufferStopCallback::new(fallible_closure(
            self.fail_handle.clone(),
            move || -> std::result::Result<(), usb_hub::Error> {
                for slot in &slots {
                    slot.reset();
                }
                hub.reset()?;
                callback();
                Ok(())
            },
        ));
        self.stop_all(auto_callback);
    }

    /// Stop all devices. The auto callback will be executed when all trc is stopped. It could
    /// happen asynchronously, if there are any pending transfers.
    pub fn stop_all(&self, auto_callback: RingBufferStopCallback) {
        for slot in &self.slots {
            slot.stop_all_trc(auto_callback.clone());
        }
    }

    /// Disable a slot. This might happen asynchronously, if there is any pending transfers. The
    /// callback will be invoked when slot is actually disabled.
    pub fn disable_slot<
        C: FnMut(TrbCompletionCode) -> std::result::Result<(), ()> + 'static + Send,
    >(
        &self,
        slot_id: u8,
        cb: C,
    ) -> Result<()> {
        usb_debug!("device slot {} is being disabled", slot_id);
        DeviceSlot::disable(
            self.fail_handle.clone(),
            &self.slots[slot_id as usize - 1],
            cb,
        )
    }

    /// Reset a slot. This is a shortcut call for DeviceSlot::reset_slot.
    pub fn reset_slot<
        C: FnMut(TrbCompletionCode) -> std::result::Result<(), ()> + 'static + Send,
    >(
        &self,
        slot_id: u8,
        cb: C,
    ) -> Result<()> {
        usb_debug!("device slot {} is resetting", slot_id);
        DeviceSlot::reset_slot(
            self.fail_handle.clone(),
            &self.slots[slot_id as usize - 1],
            cb,
        )
    }

    pub fn stop_endpoint<
        C: FnMut(TrbCompletionCode) -> std::result::Result<(), ()> + 'static + Send,
    >(
        &self,
        slot_id: u8,
        endpoint_id: u8,
        cb: C,
    ) -> Result<()> {
        self.slots[slot_id as usize - 1].stop_endpoint(self.fail_handle.clone(), endpoint_id, cb)
    }
}

// Usb port id. Valid ids starts from 1, to MAX_PORTS.
struct PortId(Mutex<u8>);

impl PortId {
    fn new() -> Self {
        PortId(Mutex::new(0))
    }

    fn set(&self, value: u8) -> Result<()> {
        if value < 1 || value > MAX_PORTS {
            return Err(Error::BadPortId(value));
        }
        *self.0.lock() = value;
        Ok(())
    }

    fn reset(&self) {
        *self.0.lock() = 0;
    }

    fn get(&self) -> Result<(u8)> {
        let val = *self.0.lock();
        if val == 0 {
            return Err(Error::BadPortId(val));
        }
        Ok(val)
    }
}

pub struct DeviceSlot {
    slot_id: u8,
    port_id: PortId, // Valid port id starts from 1, to MAX_PORTS.
    dcbaap: Register<u64>,
    hub: Arc<UsbHub>,
    interrupter: Arc<Mutex<Interrupter>>,
    event_loop: Arc<EventLoop>,
    mem: GuestMemory,
    enabled: AtomicBool,
    transfer_ring_controllers: Mutex<Vec<Option<Arc<TransferRingController>>>>,
}

impl DeviceSlot {
    /// Create a new device slot.
    pub fn new(
        slot_id: u8,
        dcbaap: Register<u64>,
        hub: Arc<UsbHub>,
        interrupter: Arc<Mutex<Interrupter>>,
        event_loop: Arc<EventLoop>,
        mem: GuestMemory,
    ) -> Self {
        let transfer_ring_controllers = vec![None; TRANSFER_RING_CONTROLLERS_INDEX_END];
        DeviceSlot {
            slot_id,
            port_id: PortId::new(),
            dcbaap,
            hub,
            interrupter,
            event_loop,
            mem,
            enabled: AtomicBool::new(false),
            transfer_ring_controllers: Mutex::new(transfer_ring_controllers),
        }
    }

    fn get_trc(&self, i: usize) -> Option<Arc<TransferRingController>> {
        let trcs = self.transfer_ring_controllers.lock();
        trcs[i].clone()
    }

    fn set_trc(&self, i: usize, trc: Option<Arc<TransferRingController>>) {
        let mut trcs = self.transfer_ring_controllers.lock();
        trcs[i] = trc;
    }

    fn trc_len(&self) -> usize {
        self.transfer_ring_controllers.lock().len()
    }

    /// The arguments are identical to the fields in each doorbell register. The
    /// target value:
    /// 1: Reserved
    /// 2: Control endpoint
    /// 3: Endpoint 1 out
    /// 4: Endpoint 1 in
    /// 5: Endpoint 2 out
    /// ...
    /// 32: Endpoint 15 in
    ///
    /// Steam ID will be useful when host controller support streams.
    /// The stream ID must be zero for endpoints that do not have streams
    /// configured.
    /// This function will return false if it fails to trigger transfer ring start.
    pub fn ring_doorbell(&self, target: u8, _stream_id: u16) -> Result<bool> {
        if !valid_endpoint_id(target) {
            error!(
                "device slot {}: Invalid target written to doorbell register. target: {}",
                self.slot_id, target
            );
            return Ok(false);
        }
        usb_debug!(
            "device slot {}: ding-dong. who is that? target = {}",
            self.slot_id,
            target
        );
        // See DCI in spec.
        let endpoint_index = (target - 1) as usize;
        let transfer_ring_controller = match self.get_trc(endpoint_index) {
            Some(tr) => tr,
            None => {
                error!("Device endpoint is not inited");
                return Ok(false);
            }
        };
        let context = self.get_device_context()?;
        if context.endpoint_context[endpoint_index]
            .get_endpoint_state()
            .map_err(Error::GetEndpointState)?
            == EndpointState::Running
        {
            usb_debug!("endpoint is started, start transfer ring");
            transfer_ring_controller.start();
        } else {
            error!("doorbell rung when endpoint is not started");
        }
        Ok(true)
    }

    /// Enable the slot. This function returns false if it's already enabled.
    pub fn enable(&self) -> bool {
        let was_already_enabled = self.enabled.swap(true, Ordering::SeqCst);
        if was_already_enabled {
            error!("device slot is already enabled");
        } else {
            usb_debug!("device slot {} enabled", self.slot_id);
        }
        !was_already_enabled
    }

    /// Disable this device slot. If the slot is not enabled, callback will be invoked immediately
    /// with error. Otherwise, callback will be invoked when all trc is stopped.
    pub fn disable<C: FnMut(TrbCompletionCode) -> std::result::Result<(), ()> + 'static + Send>(
        fail_handle: Arc<dyn FailHandle>,
        slot: &Arc<DeviceSlot>,
        mut callback: C,
    ) -> Result<()> {
        if slot.enabled.load(Ordering::SeqCst) {
            let slot_weak = Arc::downgrade(slot);
            let auto_callback =
                RingBufferStopCallback::new(fallible_closure(fail_handle, move || {
                    // Slot should still be alive when the callback is invoked. If it's not, there
                    // must be a bug somewhere.
                    let slot = slot_weak.upgrade().ok_or(Error::WeakReferenceUpgrade)?;
                    let mut device_context = slot.get_device_context()?;
                    device_context
                        .slot_context
                        .set_slot_state(DeviceSlotState::DisabledOrEnabled);
                    slot.set_device_context(device_context)?;
                    slot.reset();
                    usb_debug!(
                        "device slot {}: all trc disabled, sending trb",
                        slot.slot_id
                    );
                    callback(TrbCompletionCode::Success).map_err(|_| Error::CallbackFailed)
                }));
            slot.stop_all_trc(auto_callback);
            Ok(())
        } else {
            callback(TrbCompletionCode::SlotNotEnabledError).map_err(|_| Error::CallbackFailed)
        }
    }

    // Assigns the device address and initializes slot and endpoint 0 context.
    pub fn set_address(&self, trb: &AddressDeviceCommandTrb) -> Result<TrbCompletionCode> {
        if !self.enabled.load(Ordering::SeqCst) {
            error!(
                "trying to set address to a disabled device slot {}",
                self.slot_id
            );
            return Ok(TrbCompletionCode::SlotNotEnabledError);
        }
        let device_context = self.get_device_context()?;
        let state = device_context
            .slot_context
            .get_slot_state()
            .map_err(Error::GetSlotContextState)?;
        match state {
            DeviceSlotState::DisabledOrEnabled => {}
            DeviceSlotState::Default if !trb.get_block_set_address_request() => {}
            _ => {
                error!("slot {} has unexpected slot state", self.slot_id);
                return Ok(TrbCompletionCode::ContextStateError);
            }
        }

        // Copy all fields of the slot context and endpoint 0 context from the input context
        // to the output context.
        let input_context_ptr = GuestAddress(trb.get_input_context_pointer());
        // Copy slot context.
        self.copy_context(input_context_ptr, 0)?;
        // Copy control endpoint context.
        self.copy_context(input_context_ptr, 1)?;

        // Read back device context.
        let mut device_context = self.get_device_context()?;
        let port_id = device_context.slot_context.get_root_hub_port_number();
        self.port_id.set(port_id)?;
        usb_debug!(
            "port id {} is assigned to slot id {}",
            port_id,
            self.slot_id
        );

        // Initialize the control endpoint. Endpoint id = 1.
        self.set_trc(
            0,
            Some(
                TransferRingController::new(
                    self.mem.clone(),
                    self.hub.get_port(port_id).ok_or(Error::GetPort(port_id))?,
                    self.event_loop.clone(),
                    self.interrupter.clone(),
                    self.slot_id,
                    1,
                )
                .map_err(Error::CreateTransferController)?,
            ),
        );

        // Assign slot ID as device address if block_set_address_request is not set.
        if trb.get_block_set_address_request() {
            device_context
                .slot_context
                .set_slot_state(DeviceSlotState::Default);
        } else {
            let port = self.hub.get_port(port_id).ok_or(Error::GetPort(port_id))?;
            match port.get_backend_device().as_mut() {
                Some(backend) => {
                    backend.set_address(self.slot_id as u32);
                }
                None => {
                    return Ok(TrbCompletionCode::TransactionError);
                }
            }

            device_context
                .slot_context
                .set_usb_device_address(self.slot_id);
            device_context
                .slot_context
                .set_slot_state(DeviceSlotState::Addressed);
        }

        // TODO(jkwang) trc should always exists. Fix this.
        self.get_trc(0)
            .ok_or(Error::GetTrc(0))?
            .set_dequeue_pointer(
                device_context.endpoint_context[0]
                    .get_tr_dequeue_pointer()
                    .get_gpa(),
            );

        self.get_trc(0)
            .ok_or(Error::GetTrc(0))?
            .set_consumer_cycle_state(device_context.endpoint_context[0].get_dequeue_cycle_state());

        usb_debug!("Setting endpoint 0 to running");
        device_context.endpoint_context[0].set_endpoint_state(EndpointState::Running);
        self.set_device_context(device_context)?;
        Ok(TrbCompletionCode::Success)
    }

    // Adds or drops multiple endpoints in the device slot.
    pub fn configure_endpoint(
        &self,
        trb: &ConfigureEndpointCommandTrb,
    ) -> Result<TrbCompletionCode> {
        usb_debug!("configuring endpoint");
        let input_control_context = if trb.get_deconfigure() {
            // From section 4.6.6 of the xHCI spec:
            // Setting the deconfigure (DC) flag to '1' in the Configure Endpoint Command
            // TRB is equivalent to setting Input Context Drop Context flags 2-31 to '1'
            // and Add Context 2-31 flags to '0'.
            let mut c = InputControlContext::new();
            c.set_add_context_flags(0);
            c.set_drop_context_flags(0xfffffffc);
            c
        } else {
            self.mem
                .read_obj_from_addr(GuestAddress(trb.get_input_context_pointer()))
                .map_err(Error::ReadGuestMemory)?
        };

        for device_context_index in 1..DCI_INDEX_END {
            if input_control_context.drop_context_flag(device_context_index) {
                self.drop_one_endpoint(device_context_index)?;
            }
            if input_control_context.add_context_flag(device_context_index) {
                self.copy_context(
                    GuestAddress(trb.get_input_context_pointer()),
                    device_context_index,
                )?;
                self.add_one_endpoint(device_context_index)?;
            }
        }

        if trb.get_deconfigure() {
            self.set_state(DeviceSlotState::Addressed)?;
        } else {
            self.set_state(DeviceSlotState::Configured)?;
        }
        Ok(TrbCompletionCode::Success)
    }

    // Evaluates the device context by reading new values for certain fields of
    // the slot context and/or control endpoint context.
    pub fn evaluate_context(&self, trb: &EvaluateContextCommandTrb) -> Result<TrbCompletionCode> {
        if !self.enabled.load(Ordering::SeqCst) {
            return Ok(TrbCompletionCode::SlotNotEnabledError);
        }
        // TODO(jkwang) verify this
        // The spec has multiple contradictions about validating context parameters in sections
        // 4.6.7, 6.2.3.3. To keep things as simple as possible we do no further validation here.
        let input_control_context: InputControlContext = self
            .mem
            .read_obj_from_addr(GuestAddress(trb.get_input_context_pointer()))
            .map_err(Error::ReadGuestMemory)?;

        let mut device_context = self.get_device_context()?;
        if input_control_context.add_context_flag(0) {
            let input_slot_context: SlotContext = self
                .mem
                .read_obj_from_addr(GuestAddress(
                    trb.get_input_context_pointer() + DEVICE_CONTEXT_ENTRY_SIZE as u64,
                ))
                .map_err(Error::ReadGuestMemory)?;
            device_context
                .slot_context
                .set_interrupter_target(input_slot_context.get_interrupter_target());

            device_context
                .slot_context
                .set_max_exit_latency(input_slot_context.get_max_exit_latency());
        }

        // From 6.2.3.3: "Endpoint Contexts 2 throught 31 shall not be evaluated by the Evaluate
        // Context Command".
        if input_control_context.add_context_flag(1) {
            let ep0_context: EndpointContext = self
                .mem
                .read_obj_from_addr(GuestAddress(
                    trb.get_input_context_pointer() + 2 * DEVICE_CONTEXT_ENTRY_SIZE as u64,
                ))
                .map_err(Error::ReadGuestMemory)?;
            device_context.endpoint_context[0]
                .set_max_packet_size(ep0_context.get_max_packet_size());
        }
        self.set_device_context(device_context)?;
        Ok(TrbCompletionCode::Success)
    }

    /// Reset the device slot to default state and deconfigures all but the
    /// control endpoint.
    pub fn reset_slot<
        C: FnMut(TrbCompletionCode) -> std::result::Result<(), ()> + 'static + Send,
    >(
        fail_handle: Arc<dyn FailHandle>,
        slot: &Arc<DeviceSlot>,
        mut callback: C,
    ) -> Result<()> {
        let weak_s = Arc::downgrade(&slot);
        let auto_callback =
            RingBufferStopCallback::new(fallible_closure(fail_handle, move || -> Result<()> {
                let s = weak_s.upgrade().ok_or(Error::WeakReferenceUpgrade)?;
                for i in FIRST_TRANSFER_ENDPOINT_DCI..DCI_INDEX_END {
                    s.drop_one_endpoint(i)?;
                }
                let mut ctx = s.get_device_context()?;
                ctx.slot_context.set_slot_state(DeviceSlotState::Default);
                ctx.slot_context.set_context_entries(1);
                ctx.slot_context.set_root_hub_port_number(0);
                s.set_device_context(ctx)?;
                callback(TrbCompletionCode::Success).map_err(|_| Error::CallbackFailed)?;
                Ok(())
            }));
        slot.stop_all_trc(auto_callback);
        Ok(())
    }

    /// Stop all transfer ring controllers.
    pub fn stop_all_trc(&self, auto_callback: RingBufferStopCallback) {
        for i in 0..self.trc_len() {
            if let Some(trc) = self.get_trc(i) {
                trc.stop(auto_callback.clone());
            }
        }
    }

    /// Stop a endpoint.
    pub fn stop_endpoint<
        C: FnMut(TrbCompletionCode) -> std::result::Result<(), ()> + 'static + Send,
    >(
        &self,
        fail_handle: Arc<dyn FailHandle>,
        endpoint_id: u8,
        mut cb: C,
    ) -> Result<()> {
        if !valid_endpoint_id(endpoint_id) {
            error!("trb indexing wrong endpoint id");
            return cb(TrbCompletionCode::TrbError).map_err(|_| Error::CallbackFailed);
        }
        let index = endpoint_id - 1;
        match self.get_trc(index as usize) {
            Some(trc) => {
                usb_debug!("stopping endpoint");
                let auto_cb = RingBufferStopCallback::new(fallible_closure(
                    fail_handle,
                    move || -> Result<()> {
                        cb(TrbCompletionCode::Success).map_err(|_| Error::CallbackFailed)
                    },
                ));
                trc.stop(auto_cb);
            }
            None => {
                error!("endpoint at index {} is not started", index);
                cb(TrbCompletionCode::ContextStateError).map_err(|_| Error::CallbackFailed)?;
            }
        }
        Ok(())
    }

    /// Set transfer ring dequeue pointer.
    pub fn set_tr_dequeue_ptr(&self, endpoint_id: u8, ptr: u64) -> Result<TrbCompletionCode> {
        if !valid_endpoint_id(endpoint_id) {
            error!("trb indexing wrong endpoint id");
            return Ok(TrbCompletionCode::TrbError);
        }
        let index = (endpoint_id - 1) as usize;
        match self.get_trc(index) {
            Some(trc) => {
                trc.set_dequeue_pointer(GuestAddress(ptr));
                let mut ctx = self.get_device_context()?;
                ctx.endpoint_context[index]
                    .set_tr_dequeue_pointer(DequeuePtr::new(GuestAddress(ptr)));
                self.set_device_context(ctx)?;
                Ok(TrbCompletionCode::Success)
            }
            None => {
                error!("set tr dequeue ptr failed due to no trc started");
                Ok(TrbCompletionCode::ContextStateError)
            }
        }
    }

    // Reset and reset_slot are different.
    // Reset_slot handles command ring `reset slot` command. It will reset the slot state.
    // Reset handles xhci reset. It will destroy everything.
    fn reset(&self) {
        for i in 0..self.trc_len() {
            self.set_trc(i, None);
        }
        usb_debug!("reseting device slot {}!", self.slot_id);
        self.enabled.store(false, Ordering::SeqCst);
        self.port_id.reset();
    }

    fn add_one_endpoint(&self, device_context_index: u8) -> Result<()> {
        usb_debug!(
            "adding one endpoint, device context index {}",
            device_context_index
        );
        let mut device_context = self.get_device_context()?;
        let transfer_ring_index = (device_context_index - 1) as usize;
        let trc = TransferRingController::new(
            self.mem.clone(),
            self.hub
                .get_port(self.port_id.get()?)
                .ok_or(Error::GetPort(self.port_id.get()?))?,
            self.event_loop.clone(),
            self.interrupter.clone(),
            self.slot_id,
            device_context_index,
        )
        .map_err(Error::CreateTransferController)?;
        trc.set_dequeue_pointer(
            device_context.endpoint_context[transfer_ring_index]
                .get_tr_dequeue_pointer()
                .get_gpa(),
        );
        trc.set_consumer_cycle_state(
            device_context.endpoint_context[transfer_ring_index].get_dequeue_cycle_state(),
        );
        self.set_trc(transfer_ring_index, Some(trc));
        device_context.endpoint_context[transfer_ring_index]
            .set_endpoint_state(EndpointState::Running);
        self.set_device_context(device_context)
    }

    fn drop_one_endpoint(&self, device_context_index: u8) -> Result<()> {
        let endpoint_index = (device_context_index - 1) as usize;
        self.set_trc(endpoint_index, None);
        let mut ctx = self.get_device_context()?;
        ctx.endpoint_context[endpoint_index].set_endpoint_state(EndpointState::Disabled);
        self.set_device_context(ctx)
    }

    fn get_device_context(&self) -> Result<DeviceContext> {
        let ctx = self
            .mem
            .read_obj_from_addr(self.get_device_context_addr()?)
            .map_err(Error::ReadGuestMemory)?;
        usb_debug!("read device ctx: {:?}", ctx);
        Ok(ctx)
    }

    fn set_device_context(&self, device_context: DeviceContext) -> Result<()> {
        self.mem
            .write_obj_at_addr(device_context, self.get_device_context_addr()?)
            .map_err(Error::WriteGuestMemory)
    }

    fn copy_context(
        &self,
        input_context_ptr: GuestAddress,
        device_context_index: u8,
    ) -> Result<()> {
        // Note that it could be slot context or device context. They have the same size. Won't
        // make a difference here.
        let ctx: EndpointContext = self
            .mem
            .read_obj_from_addr(
                input_context_ptr
                    .checked_add(
                        (device_context_index as u64 + 1) * DEVICE_CONTEXT_ENTRY_SIZE as u64,
                    )
                    .ok_or(Error::BadInputContextAddr(input_context_ptr))?,
            )
            .map_err(Error::ReadGuestMemory)?;
        usb_debug!("context being copied {:?}", ctx);
        let device_context_ptr = self.get_device_context_addr()?;
        self.mem
            .write_obj_at_addr(
                ctx,
                device_context_ptr
                    .checked_add(device_context_index as u64 * DEVICE_CONTEXT_ENTRY_SIZE as u64)
                    .ok_or(Error::BadDeviceContextAddr(device_context_ptr))?,
            )
            .map_err(Error::WriteGuestMemory)
    }

    fn get_device_context_addr(&self) -> Result<GuestAddress> {
        let addr: u64 = self
            .mem
            .read_obj_from_addr(GuestAddress(
                self.dcbaap.get_value() + size_of::<u64>() as u64 * self.slot_id as u64,
            ))
            .map_err(Error::ReadGuestMemory)?;
        Ok(GuestAddress(addr))
    }

    fn set_state(&self, state: DeviceSlotState) -> Result<()> {
        let mut ctx = self.get_device_context()?;
        ctx.slot_context.set_slot_state(state);
        self.set_device_context(ctx)
    }
}
