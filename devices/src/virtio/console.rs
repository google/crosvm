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
    queue_sizes: Vec<u16>,
    pci_address: Option<PciAddress>,
}

impl Console {
    fn new(
        protection_type: ProtectionType,
        input: Option<InStreamType>,
        output: Option<Box<dyn std::io::Write + Send>>,
        keep_rds: Vec<RawDescriptor>,
        pci_address: Option<PciAddress>,
    ) -> Console {
        let port = ConsolePort::new(input, output, None, keep_rds);
        let console = ConsoleDevice::new_single_port(protection_type, port);
        let queue_sizes = vec![QUEUE_SIZE; console.max_queues()];

        Console {
            console,
            queue_sizes,
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
        &self.queue_sizes
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
        interrupt: Interrupt,
        queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        for (idx, queue) in queues.into_iter() {
            self.console.start_queue(idx, queue, interrupt.clone())?
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
        if let Some((_mem, interrupt, queues)) = queues_state {
            for (idx, queue) in queues.into_iter() {
                self.console.start_queue(idx, queue, interrupt.clone())?;
            }
        }
        Ok(())
    }

    fn virtio_snapshot(&mut self) -> anyhow::Result<serde_json::Value> {
        let snap = self.console.snapshot()?;
        serde_json::to_value(snap).context("failed to snapshot virtio console")
    }

    fn virtio_restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let snap: ConsoleSnapshot =
            serde_json::from_value(data).context("failed to deserialize virtio console")?;
        self.console.restore(&snap)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use base::windows::named_pipes;
    use tempfile::tempfile;
    use vm_memory::GuestAddress;

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

        let snapshot_input_buffer = snapshot
            .get("ports")
            .unwrap()
            .get(0)
            .unwrap()
            .get("input_buffer")
            .unwrap()
            .as_array()
            .unwrap();

        assert_eq!(snapshot_input_buffer.len(), b"Hello".len());
        assert_eq!(snapshot_input_buffer[0].as_i64(), Some(b'H' as i64));
        assert_eq!(snapshot_input_buffer[1].as_i64(), Some(b'e' as i64));
        assert_eq!(snapshot_input_buffer[2].as_i64(), Some(b'l' as i64));
        assert_eq!(snapshot_input_buffer[3].as_i64(), Some(b'l' as i64));
        assert_eq!(snapshot_input_buffer[4].as_i64(), Some(b'o' as i64));

        // Wake up the device, which should start the input thread again.
        device.virtio_wake(None).expect("failed to wake");
    }
}
