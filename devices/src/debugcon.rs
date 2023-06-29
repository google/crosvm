// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::Write;

use base::error;
#[cfg(windows)]
use base::named_pipes;
use base::Event;
use base::FileSync;
use base::RawDescriptor;
use base::Result;
use hypervisor::ProtectionType;

use crate::pci::CrosvmDeviceId;
use crate::serial_device::SerialInput;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::DeviceId;
use crate::SerialDevice;
use crate::Suspendable;

const BOCHS_DEBUGCON_READBACK: u8 = 0xe9;

pub struct Debugcon {
    out: Option<Box<dyn io::Write + Send>>,
}

impl SerialDevice for Debugcon {
    fn new(
        _protection_type: ProtectionType,
        _interrupt_evt: Event,
        _input: Option<Box<dyn SerialInput>>,
        out: Option<Box<dyn io::Write + Send>>,
        _sync: Option<Box<dyn FileSync + Send>>,
        _out_timestamp: bool,
        _keep_rds: Vec<RawDescriptor>,
    ) -> Debugcon {
        Debugcon { out }
    }

    #[cfg(windows)]
    fn new_with_pipe(
        _protection_type: ProtectionType,
        _interrupt_evt: Event,
        _pipe_in: named_pipes::PipeConnection,
        _pipe_out: named_pipes::PipeConnection,
        _keep_rds: Vec<RawDescriptor>,
    ) -> Debugcon {
        unimplemented!("new_with_pipe unimplemented for Debugcon");
    }
}

impl BusDevice for Debugcon {
    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::DebugConsole.into()
    }

    fn debug_label(&self) -> String {
        "debugcon".to_owned()
    }

    fn write(&mut self, _info: BusAccessInfo, data: &[u8]) {
        if data.len() != 1 {
            return;
        }
        if let Err(e) = self.handle_write(data) {
            error!("debugcon failed write: {}", e);
        }
    }

    fn read(&mut self, _info: BusAccessInfo, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }
        data[0] = BOCHS_DEBUGCON_READBACK;
    }
}

impl Debugcon {
    fn handle_write(&mut self, data: &[u8]) -> Result<()> {
        if let Some(out) = self.out.as_mut() {
            out.write_all(data)?;
            out.flush()?;
        }
        Ok(())
    }
}

impl Suspendable for Debugcon {
    fn sleep(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn snapshot(&self) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::Value::Null)
    }

    fn restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        anyhow::ensure!(
            data == serde_json::Value::Null,
            "unexpected snapshot data: should be null, got {}",
            data,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

    use sync::Mutex;

    use super::*;

    const ADDR: BusAccessInfo = BusAccessInfo {
        offset: 0,
        address: 0,
        id: 0,
    };

    // XXX(gerow): copied from devices/src/serial.rs
    #[derive(Clone)]
    struct SharedBuffer {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedBuffer {
        fn new() -> SharedBuffer {
            SharedBuffer {
                buf: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buf.lock().write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.buf.lock().flush()
        }
    }

    #[test]
    fn write() {
        let debugcon_out = SharedBuffer::new();
        let mut debugcon = Debugcon::new(
            ProtectionType::Unprotected,
            Event::new().unwrap(),
            None,
            Some(Box::new(debugcon_out.clone())),
            None,
            false,
            Vec::new(),
        );

        debugcon.write(ADDR, &[b'a']);
        debugcon.write(ADDR, &[b'b']);
        debugcon.write(ADDR, &[b'c']);
        assert_eq!(debugcon_out.buf.lock().as_slice(), [b'a', b'b', b'c']);
    }

    #[test]
    fn read() {
        let mut debugcon = Debugcon::new(
            ProtectionType::Unprotected,
            Event::new().unwrap(),
            None,
            None,
            None,
            false,
            Vec::new(),
        );

        let mut data = [0u8; 1];
        debugcon.read(ADDR, &mut data[..]);
        assert_eq!(data[0], 0xe9);
    }
}
