// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtio console device.

pub mod control;
pub mod device;
pub mod input;
pub mod output;
pub mod port;
pub mod worker;

mod sys;

use std::collections::BTreeMap;

use anyhow::Context;
use base::RawDescriptor;
use hypervisor::ProtectionType;
use snapshot::AnySnapshot;
use vm_memory::GuestMemory;

use crate::serial::sys::InStreamType;
use crate::virtio::console::device::ConsoleDevice;
use crate::virtio::console::device::ConsoleSnapshot;
use crate::virtio::console::port::ConsolePort;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;
use crate::PciAddress;

const QUEUE_SIZE: u16 = 256;

/// Virtio console device.
pub struct Console {
    console: ConsoleDevice,
    max_queue_sizes: Vec<u16>,
    pci_address: Option<PciAddress>,
}

impl Console {
    fn new(
        protection_type: ProtectionType,
        input: Option<InStreamType>,
        output: Option<Box<dyn std::io::Write + Send>>,
        keep_rds: Vec<RawDescriptor>,
        pci_address: Option<PciAddress>,
        max_queue_sizes: Option<Vec<u16>>,
    ) -> Console {
        let port = ConsolePort::new(input, output, None, keep_rds);
        let console = ConsoleDevice::new_single_port(protection_type, port);
        let max_queue_sizes =
            max_queue_sizes.unwrap_or_else(|| vec![QUEUE_SIZE; console.max_queues()]);

        // TODO: Move these checks into cmdline validation or something so it is more user
        // friendly when it fails.
        assert_eq!(max_queue_sizes.len(), console.max_queues());
        for qs in &max_queue_sizes {
            assert!(qs.is_power_of_two());
        }

        Console {
            console,
            max_queue_sizes,
            pci_address,
        }
    }
}

impl VirtioDevice for Console {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        self.console.keep_rds()
    }

    fn features(&self) -> u64 {
        self.console.features()
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Console
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.max_queue_sizes
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.console.read_config(offset, data);
    }

    fn on_device_sandboxed(&mut self) {
        self.console.start_input_threads();
    }

    fn activate(
        &mut self,
        _mem: GuestMemory,
        _interrupt: Interrupt,
        queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        for (idx, queue) in queues.into_iter() {
            self.console.start_queue(idx, queue)?
        }
        Ok(())
    }

    fn pci_address(&self) -> Option<PciAddress> {
        self.pci_address
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        self.console.reset()
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        // Stop and collect all the queues.
        let mut queues = BTreeMap::new();
        for idx in 0..self.console.max_queues() {
            if let Some(queue) = self
                .console
                .stop_queue(idx)
                .with_context(|| format!("failed to stop queue {idx}"))?
            {
                queues.insert(idx, queue);
            }
        }

        if !queues.is_empty() {
            Ok(Some(queues))
        } else {
            Ok(None)
        }
    }

    fn virtio_wake(
        &mut self,
        queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
    ) -> anyhow::Result<()> {
        if let Some((_mem, _interrupt, queues)) = queues_state {
            for (idx, queue) in queues.into_iter() {
                self.console.start_queue(idx, queue)?;
            }
        }
        Ok(())
    }

    fn virtio_snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        let snap = self.console.snapshot()?;
        AnySnapshot::to_any(snap).context("failed to snapshot virtio console")
    }

    fn virtio_restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        let snap: ConsoleSnapshot =
            AnySnapshot::from_any(data).context("failed to deserialize virtio console")?;
        self.console.restore(&snap)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use base::windows::named_pipes;
    use tempfile::tempfile;

    use super::*;
    use crate::suspendable_virtio_tests;

    struct ConsoleContext {
        #[cfg(windows)]
        input_pipe_client: named_pipes::PipeConnection,
    }

    fn modify_device(_context: &mut ConsoleContext, b: &mut Console) {
        let input_buffer = b.console.ports[0].clone_input_buffer();
        input_buffer.lock().push_back(0);
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn create_device() -> (ConsoleContext, Console) {
        let input = Box::new(tempfile().unwrap());
        let output = Box::new(tempfile().unwrap());

        let console = Console::new(
            hypervisor::ProtectionType::Unprotected,
            Some(input),
            Some(output),
            Vec::new(),
            None,
            None,
        );

        let context = ConsoleContext {};
        (context, console)
    }

    #[cfg(windows)]
    fn create_device() -> (ConsoleContext, Console) {
        let (input_pipe_server, input_pipe_client) = named_pipes::pair(
            &named_pipes::FramingMode::Byte,
            &named_pipes::BlockingMode::NoWait,
            0,
        )
        .unwrap();

        let input = Box::new(input_pipe_server);
        let output = Box::new(tempfile().unwrap());

        let console = Console::new(
            hypervisor::ProtectionType::Unprotected,
            Some(input),
            Some(output),
            Vec::new(),
            None,
            None,
        );

        let context = ConsoleContext { input_pipe_client };

        (context, console)
    }

    suspendable_virtio_tests!(console, create_device, 2, modify_device);

    #[test]
    fn test_inactive_sleep_resume() {
        let (_ctx, mut device) = create_device();

        let input_buffer = device.console.ports[0].clone_input_buffer();

        // Initialize the device, starting the input thread, but don't activate any queues.
        device.on_device_sandboxed();

        // No queues were started, so `virtio_sleep()` should return `None`.
        let sleep_result = device.virtio_sleep().expect("failed to sleep");
        assert!(sleep_result.is_none());

        // Inject some input data.
        input_buffer.lock().extend(b"Hello".iter());

        // Ensure snapshot does not fail and contains the buffered input data.
        let snapshot = device.virtio_snapshot().expect("failed to snapshot");
        let snapshot: ConsoleSnapshot =
            AnySnapshot::from_any(snapshot).expect("failed to deserialize snapshot");

        assert_eq!(snapshot.ports[0].input_buffer, b"Hello");

        // Wake up the device, which should start the input thread again.
        device.virtio_wake(None).expect("failed to wake");
    }
}
