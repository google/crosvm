// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles the main wait loop for IRQs.
//! Should be started on a background thread.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use arch::IrqChipArch;
use base::error;
use base::info;
use base::warn;
use base::Event;
use base::EventToken;
use base::ReadNotifier;
use base::Result;
use base::Tube;
use base::TubeError;
use base::WaitContext;
use base::MAXIMUM_WAIT_OBJECTS;
use devices::IrqEdgeEvent;
use devices::IrqEventIndex;
use devices::IrqEventSource;
use metrics::log_high_frequency_descriptor_event;
use metrics::MetricEventType;
use resources::SystemAllocator;
use sync::Mutex;
use vm_control::IrqHandlerRequest;
use vm_control::IrqHandlerResponse;
use vm_control::IrqSetup;
use vm_control::VmIrqRequest;

pub struct IrqWaitWorker {
    irq_handler_control: Tube,
    irq_chip: Box<dyn IrqChipArch>,
    irq_control_tubes: Vec<Tube>,
    sys_allocator: Arc<Mutex<SystemAllocator>>,
}

#[derive(EventToken)]
enum Token {
    VmControl { index: usize },
    IrqHandlerControl,
    DelayedIrqEvent,
}

impl IrqWaitWorker {
    pub fn start(
        irq_handler_control: Tube,
        irq_chip: Box<dyn IrqChipArch>,
        irq_control_tubes: Vec<Tube>,
        sys_allocator: Arc<Mutex<SystemAllocator>>,
    ) -> JoinHandle<anyhow::Result<()>> {
        let mut irq_worker = IrqWaitWorker {
            irq_handler_control,
            irq_chip,
            irq_control_tubes,
            sys_allocator,
        };
        thread::Builder::new()
            .name("irq_wait_loop".into())
            .spawn(move || irq_worker.run())
            .unwrap()
    }

    fn add_child(
        wait_ctx: &WaitContext<Token>,
        children: &mut Vec<JoinHandle<Result<()>>>,
        child_control_tubes: &mut Vec<Tube>,
        irq_chip: Box<dyn IrqChipArch>,
        irq_frequencies: Arc<Mutex<Vec<u64>>>,
    ) -> Result<Arc<WaitContext<ChildToken>>> {
        let (child_control_tube, child_control_tube_for_child) = Tube::pair().map_err(|e| {
            error!("failed to create IRQ child control tube: {:?}", e);
            base::Error::from(io::Error::new(io::ErrorKind::Other, e))
        })?;
        let (child_wait_ctx, child_join_handle) =
            IrqWaitWorkerChild::start(child_control_tube_for_child, irq_chip, irq_frequencies)?;
        children.push(child_join_handle);
        child_control_tubes.push(child_control_tube);
        Ok(child_wait_ctx)
    }

    fn run(&mut self) -> anyhow::Result<()> {
        let wait_ctx = WaitContext::new()?;

        let mut max_event_index: usize = 0;
        let mut vm_control_added_irq_events: Vec<Event> = Vec::new();
        let mut irq_event_sources: HashMap<IrqEventIndex, IrqEventSource> = HashMap::new();
        // TODO(b/190828888): Move irq logging into the irqchip impls.
        let irq_frequencies = Arc::new(Mutex::new(vec![0; max_event_index + 1]));
        let irq_events = self.irq_chip.irq_event_tokens()?;
        let mut children = vec![];
        let mut child_control_tubes = vec![];

        let mut child_wait_ctx = Self::add_child(
            &wait_ctx,
            &mut children,
            &mut child_control_tubes,
            self.irq_chip.try_box_clone()?,
            irq_frequencies.clone(),
        )
        .context("failed to create IRQ wait child")?;

        wait_ctx.add(
            self.irq_handler_control.get_read_notifier(),
            Token::IrqHandlerControl,
        )?;

        for (event_index, source, evt) in irq_events {
            child_wait_ctx.add(&evt, ChildToken::IrqEvent { event_index })?;
            max_event_index = std::cmp::max(max_event_index, event_index);
            irq_event_sources.insert(event_index, source);

            vm_control_added_irq_events.push(evt);
        }

        irq_frequencies.lock().resize(max_event_index + 1, 0);

        for (index, control_tube) in self.irq_control_tubes.iter().enumerate() {
            wait_ctx.add(control_tube.get_read_notifier(), Token::VmControl { index })?;
        }

        let mut _delayed_event_token: Option<Event> = None;
        if let Some(delayed_token) = self.irq_chip.irq_delayed_event_token()? {
            wait_ctx.add(&delayed_token, Token::DelayedIrqEvent)?;
            // store the token, so that it lasts outside this scope.
            // We must store the event as try_clone creates a new event. It won't keep
            // the current event valid that is waited on inside wait_ctx.
            _delayed_event_token = Some(delayed_token);
        }

        let mut intr_stat_sample_time = Instant::now();

        'poll: loop {
            let events = {
                match wait_ctx.wait() {
                    Ok(v) => v,
                    Err(e) => {
                        error!("failed to wait on irq thread: {}", e);
                        break 'poll;
                    }
                }
            };

            let mut token_count = events.len();
            let mut notify_control_on_iteration_end = false;
            let mut vm_control_indices_to_remove = Vec::new();
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::IrqHandlerControl => {
                        match self.irq_handler_control.recv::<IrqHandlerRequest>() {
                            Ok(request) => match request {
                                IrqHandlerRequest::Exit => {
                                    info!("irq event loop got exit request");
                                    break 'poll;
                                }
                                IrqHandlerRequest::AddIrqControlTubes(_tubes) => {
                                    panic!("CrosVM on Windows does not support adding devices on the fly yet.");
                                }
                                IrqHandlerRequest::WakeAndNotifyIteration => {
                                    for child_control_tube in child_control_tubes.iter() {
                                        child_control_tube
                                            .send(&IrqHandlerRequest::WakeAndNotifyIteration)
                                            .context("failed to send flush command to IRQ handler child thread")?;
                                        let resp = child_control_tube
                                            .recv()
                                            .context("failed to recv flush response from IRQ handler child thread")?;
                                        match resp {
                                            IrqHandlerResponse::HandlerIterationComplete(
                                                tokens_serviced,
                                            ) => {
                                                token_count += tokens_serviced;
                                            }
                                            unexpected_resp => panic!(
                                                "got unexpected response: {:?}",
                                                unexpected_resp
                                            ),
                                        }
                                    }
                                    notify_control_on_iteration_end = true;
                                }
                                IrqHandlerRequest::RefreshIrqEventTokens => {
                                    todo!("not implemented yet");
                                }
                            },
                            Err(e) => {
                                if let TubeError::Disconnected = e {
                                    panic!("irq handler control tube disconnected.");
                                } else {
                                    error!("failed to recv IrqHandlerRequest: {}", e);
                                }
                            }
                        }
                    }
                    Token::VmControl { index } => {
                        if let Some(tube) = self.irq_control_tubes.get(index) {
                            match tube.recv::<VmIrqRequest>() {
                                Ok(request) => {
                                    let response = {
                                        let irq_chip = &mut self.irq_chip;
                                        // TODO(b/229262201): Refactor the closure into a standalone function to reduce indentation.
                                        request.execute(
                                            |setup| match setup {
                                                IrqSetup::Event(
                                                    irq,
                                                    ev,
                                                    device_id,
                                                    queue_id,
                                                    device_name,
                                                ) => {
                                                    let irqevent = IrqEdgeEvent::from_event(
                                                        ev.try_clone()
                                                            .expect("Failed to clone irq event."),
                                                    );
                                                    let source = IrqEventSource {
                                                        device_id: device_id.try_into()?,
                                                        queue_id,
                                                        device_name,
                                                    };
                                                    let event_index = irq_chip
                                                        .register_edge_irq_event(
                                                            irq,
                                                            &irqevent,
                                                            source.clone(),
                                                        )?;
                                                    if let Some(event_index) = event_index {
                                                        max_event_index = std::cmp::max(
                                                            event_index,
                                                            irq as usize,
                                                        );
                                                        irq_frequencies
                                                            .lock()
                                                            .resize(max_event_index + 1, 0);
                                                        irq_event_sources
                                                            .insert(event_index, source);
                                                        // Make new thread if needed, including buffer space for any
                                                        // events we didn't explicitly add (exit/reset/etc)
                                                        if irq_event_sources.len()
                                                            % (MAXIMUM_WAIT_OBJECTS - 3)
                                                            == 0
                                                        {
                                                            // The child wait thread has reached max capacity, we
                                                            // need to add another.
                                                            child_wait_ctx = Self::add_child(
                                                                &wait_ctx, &mut children, &mut child_control_tubes,
                                                                irq_chip.try_box_clone()?, irq_frequencies.clone())?;

                                                        }
                                                        let irqevent =
                                                            irqevent.get_trigger().try_clone()?;
                                                        match child_wait_ctx.add(
                                                            &irqevent,
                                                            ChildToken::IrqEvent { event_index },
                                                        ) {
                                                            Err(e) => {
                                                                warn!("failed to add IrqEvent to synchronization context: {}", e);
                                                                Err(e)
                                                            },
                                                            Ok(_) => {
                                                                vm_control_added_irq_events
                                                                    .push(irqevent);
                                                                Ok(())
                                                            }
                                                        }
                                                    } else {
                                                        Ok(())
                                                    }
                                                }
                                                IrqSetup::Route(route) => irq_chip.route_irq(route),
                                                IrqSetup::UnRegister(irq, ev) => irq_chip
                                                    .unregister_edge_irq_event(
                                                        irq,
                                                        &IrqEdgeEvent::from_event(ev.try_clone()?),
                                                    ),
                                            },
                                            &mut self.sys_allocator.lock(),
                                        )
                                    };
                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmIrqResponse: {}", e);
                                    }
                                }
                                Err(e) => {
                                    if let TubeError::Disconnected = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmIrqRequest: {}", e);
                                    }
                                }
                            }
                        }
                    }
                    Token::DelayedIrqEvent => {
                        if let Err(e) = self.irq_chip.process_delayed_irq_events() {
                            warn!("can't deliver delayed irqs: {}", e);
                        }
                    }
                }
            }

            let now = Instant::now();
            let intr_stat_duration = now.duration_since(intr_stat_sample_time);

            // include interrupt stats every 10 seconds
            if intr_stat_duration > Duration::from_secs(10) {
                let mut event_indices: Vec<(&usize, &IrqEventSource)> =
                    irq_event_sources.iter().collect();
                // sort the devices by irq_frequency
                let mut locked_irq_frequencies = irq_frequencies.lock();
                event_indices
                    .sort_by_key(|(idx, _)| std::cmp::Reverse(locked_irq_frequencies[**idx]));
                let rates: Vec<String> = event_indices
                    .iter()
                    .filter(|(idx, _)| locked_irq_frequencies[**idx] > 0)
                    .map(|(idx, source)| {
                        let rate = locked_irq_frequencies[**idx] / intr_stat_duration.as_secs();
                        // As the descriptor, use a 64bit int containing two 32bit ids.
                        // low bits: queue_id, high bits: device_id
                        let descriptor_bytes: [u8; 8] = {
                            let mut bytes: [u8; 8] = [0; 8];
                            for (i, byte) in
                                (source.queue_id as u32).to_le_bytes().iter().enumerate()
                            {
                                bytes[i] = *byte
                            }
                            let device_id: u32 = source.device_id.into();
                            for (i, byte) in device_id.to_le_bytes().iter().enumerate() {
                                bytes[i + 4] = *byte
                            }
                            bytes
                        };
                        log_high_frequency_descriptor_event(
                            MetricEventType::Interrupts,
                            i64::from_le_bytes(descriptor_bytes),
                            rate as i64,
                        );
                        format!("{}({})->{}/s", source.device_name, source.queue_id, rate,)
                    })
                    .collect();

                info!("crosvm-interrupt-rates: {}", rates.join(", "));

                // reset sample time and counters
                intr_stat_sample_time = now;
                *locked_irq_frequencies = vec![0; max_event_index + 1];
            }

            vm_control_indices_to_remove.dedup();
            for index in vm_control_indices_to_remove {
                self.irq_control_tubes.swap_remove(index);
            }

            if notify_control_on_iteration_end {
                if let Err(e) =
                    // We want to send the number of IRQ events processed in
                    // this iteration. Token count is almost what we want,
                    // except it counts the IrqHandlerControl token, so we just
                    // subtract it off to get the desired value.
                    self.irq_handler_control.send(
                        &IrqHandlerResponse::HandlerIterationComplete(token_count - 1),
                    )
                {
                    error!(
                        "failed to notify on iteration completion (snapshotting may fail): {}",
                        e
                    );
                }
            }
        }

        // Ensure all children have exited.
        for child_control_tube in child_control_tubes.iter() {
            if let Err(e) = child_control_tube.send(&IrqHandlerRequest::Exit) {
                warn!("failed to send exit signal to IRQ worker: {}", e);
            }
        }

        // Ensure all children have exited and aren't stalled / stuck.
        for child in children {
            match child.join() {
                Ok(Err(e)) => warn!("IRQ worker child ended in error: {}", e),
                Err(e) => warn!("IRQ worker child panicked with error: {:?}", e),
                _ => {}
            }
        }

        Ok(())
    }
}

#[derive(EventToken)]
enum ChildToken {
    IrqHandlerControl,
    IrqEvent { event_index: IrqEventIndex },
}
/// An arbitrarily expandible worker for waiting on irq events.
/// This worker is responsible for hadling the irq events, whereas
/// the parent worker's job is just to handle the irq control tube requests.
struct IrqWaitWorkerChild {
    wait_ctx: Arc<WaitContext<ChildToken>>,
    irq_handler_control: Tube,
    irq_chip: Box<dyn IrqChipArch>,
    irq_frequencies: Arc<Mutex<Vec<u64>>>,
}

impl IrqWaitWorkerChild {
    fn start(
        irq_handler_control: Tube,
        irq_chip: Box<dyn IrqChipArch>,
        irq_frequencies: Arc<Mutex<Vec<u64>>>,
    ) -> Result<(Arc<WaitContext<ChildToken>>, JoinHandle<Result<()>>)> {
        let child_wait_ctx = Arc::new(WaitContext::new()?);
        let mut child = IrqWaitWorkerChild {
            wait_ctx: child_wait_ctx.clone(),
            irq_handler_control,
            irq_chip,
            irq_frequencies,
        };
        let join_handle = thread::Builder::new()
            .name("irq_child_wait_loop".into())
            .spawn(move || child.run())?;

        Ok((child_wait_ctx, join_handle))
    }

    fn run(&mut self) -> Result<()> {
        self.wait_ctx.add(
            self.irq_handler_control.get_read_notifier(),
            ChildToken::IrqHandlerControl,
        )?;
        'poll: loop {
            let events = {
                match self.wait_ctx.wait() {
                    Ok(v) => v,
                    Err(e) => {
                        error!("failed to wait on irq child thread: {}", e);
                        break 'poll;
                    }
                }
            };

            let token_count = events.len();
            let mut notify_control_on_iteration_end = false;

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    ChildToken::IrqHandlerControl => {
                        match self.irq_handler_control.recv::<IrqHandlerRequest>() {
                            Ok(request) => match request {
                                IrqHandlerRequest::Exit => {
                                    info!("irq child event loop got exit event");
                                    break 'poll;
                                }
                                IrqHandlerRequest::AddIrqControlTubes(_tubes) => {
                                    panic!("Windows does not support adding devices on the fly.");
                                }
                                IrqHandlerRequest::WakeAndNotifyIteration => {
                                    notify_control_on_iteration_end = true;
                                }
                                IrqHandlerRequest::RefreshIrqEventTokens => {
                                    todo!("not implemented yet");
                                }
                            },
                            Err(e) => {
                                if let TubeError::Disconnected = e {
                                    panic!("irq handler control tube disconnected.");
                                } else {
                                    error!("failed to recv IrqHandlerRequest: {}", e);
                                }
                            }
                        }
                    }
                    ChildToken::IrqEvent { event_index } => {
                        self.irq_frequencies.lock()[event_index] += 1;
                        if let Err(e) = self.irq_chip.service_irq_event(event_index) {
                            error!("failed to signal irq {}: {}", event_index, e);
                        }
                    }
                }
            }

            if notify_control_on_iteration_end {
                if let Err(e) =
                    // We want to send the number of IRQ events processed in
                    // this iteration. Token count is almost what we want,
                    // except it counts the IrqHandlerControl token, so we just
                    // subtract it off to get the desired value.
                    self.irq_handler_control.send(
                        &IrqHandlerResponse::HandlerIterationComplete(token_count - 1),
                    )
                {
                    error!(
                        "failed to notify on child iteration completion (snapshotting may fail): {}",
                        e
                    );
                }
            }
        }
        Ok(())
    }
}
