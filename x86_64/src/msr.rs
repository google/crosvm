// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::rc::Rc;

use anyhow::Context;
use arch::MsrAction;
use arch::MsrConfig;
use arch::MsrExitHandlerError;
use arch::MsrFilter;
use arch::MsrRWType;
use arch::MsrValueFrom;
use base::debug;
use base::error;
use remain::sorted;
use thiserror::Error as ThisError;

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Unable to open host msr file: {0}")]
    HostMsrGetError(anyhow::Error),
    #[error("Unable to get metadata of dev file for msr: {0}")]
    HostMsrGetMetadataError(std::io::Error),
    #[error("Unable to read host msr: {0}")]
    HostMsrReadError(std::io::Error),
    #[error("Unable to set permissions of dev file for msr: {0}")]
    HostMsrSetPermsError(std::io::Error),
    #[error("Unable to write host msr: {0}")]
    HostMsrWriteError(std::io::Error),
    #[error("Not set msr action parameter")]
    InvalidAction,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Wrap for userspace MSR file descriptor (/dev/cpu/*/msr).
pub struct MsrDevFile {
    dev_msr: File,
}

impl MsrDevFile {
    /// Create a new MSR file descriptor.
    ///
    /// "Passthrough" handler will create file descriptor with both read and write
    /// permissions. MsrHandlers controls read/write with MsrRWType. This avoids
    /// the corner case that some MSRs are read-only while other MSRs need write
    /// permission.
    /// "Emulate" handler will create read-only file descriptor. This read-only
    /// descriptor will only be used once to initialize MSR value and "Emulate"
    /// handler won't store its descriptor at MsrHandlers level.
    fn new(cpu_id: usize, read_only: bool) -> Result<Self> {
        let filename = format!("/dev/cpu/{}/msr", cpu_id);
        let dev_msr = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(&filename)
            .context(format!("Cannot open {}, are you root?", filename))
            .map_err(Error::HostMsrGetError)?;
        Ok(MsrDevFile { dev_msr })
    }

    fn read(&self, index: u32) -> Result<u64> {
        let mut data = [0; 8];
        self.dev_msr
            .read_exact_at(&mut data, index.into())
            .map_err(Error::HostMsrReadError)?;
        Ok(u64::from_ne_bytes(data))
    }

    // In fact, only "passthrough" will write into MSR file.
    fn write(&self, index: u32, data: u64) -> Result<()> {
        self.dev_msr
            .write_all_at(&data.to_ne_bytes(), index.into())
            .map_err(Error::HostMsrWriteError)?;
        Ok(())
    }
}

/// Wrap for general RDMSR/WRMSR handling.
///
/// Each specific handler needs to implement this trait.
pub trait MsrHandling {
    fn read(&self) -> Result<u64>;
    // For "emulate" handler, it need to update MSR value which is stored in
    // `msr_data` of MsrEmulate. So declare `self` as mutable.
    fn write(&mut self, data: u64) -> Result<()>;
}

type MsrFileType = Rc<RefCell<BTreeMap<usize /* vcpu */, Rc<MsrDevFile>>>>;

/// MsrPassthroughHandler - passthrough handler that will handle RDMSR/WRMSR
///                         by reading/writing MSR file directly.
/// For RDMSR, this handler will give Guest the current MSR value on Host.
/// For WRMSR, this handler will directly pass the change desired by the Guest
/// to the host, and expect the change to take effect on the MSR of the host.
struct MsrPassthroughHandler {
    /// MSR index.
    index: u32,
    /// MSR source CPU, CPU 0 or running CPU.
    from: MsrValueFrom,
    /// Reference of MSR file descriptors.
    msr_file: MsrFileType,
}

impl MsrPassthroughHandler {
    fn new(index: u32, msr_config: &MsrConfig, msr_file: MsrFileType) -> Result<Self> {
        let pass = MsrPassthroughHandler {
            index,
            from: msr_config.from,
            msr_file,
        };
        pass.get_msr_dev()?;
        Ok(pass)
    }

    /// A helper interface to get MSR file descriptor.
    fn get_msr_dev(&self) -> Result<Rc<MsrDevFile>> {
        let cpu_id = self.from.get_cpu_id();
        // First, check if the descriptor is stored before.
        if let Some(dev_msr) = self.msr_file.borrow().get(&cpu_id) {
            return Ok(Rc::clone(dev_msr));
        }

        // If descriptor isn't found, create new one.
        let new_dev_msr = Rc::new(MsrDevFile::new(cpu_id, false)?);
        // Note: For MsrValueFrom::RWFromRunningCPU case, just store
        // the new descriptor and don't remove the previous.
        // This is for convenience, since the most decriptor number is
        // same as Host CPU count.
        self.msr_file
            .borrow_mut()
            .insert(cpu_id, Rc::clone(&new_dev_msr));
        Ok(new_dev_msr)
    }
}

impl MsrHandling for MsrPassthroughHandler {
    fn read(&self) -> Result<u64> {
        let index = self.index;
        self.get_msr_dev()?.read(index)
    }

    fn write(&mut self, data: u64) -> Result<()> {
        let index = self.index;
        self.get_msr_dev()?.write(index, data)
    }
}

/// MsrPassthroughHandler - emulate handler that will handle RDMSR/WRMSR
///                         with a dummy MSR value other than access to real
///                         MSR.
/// This Handler will initialize a value(`msr_data`) with the corresponding
/// Host MSR value, then handle the RDMSR/WRMSR based on this "value".
///
/// For RDMSR, this handler will give Guest the stored `msr_data`.
/// For WRMSR, this handler will directly change `msr_data` without the
/// modification on real Host MSR. The change will not take effect on the
/// real MSR of Host.
///
/// 'emulate' Handler is used in the case, that some driver need to control
/// MSR and user just wants to make WRMSR successful and doesn't care about
/// if WRMSR really works. This handlers make Guest's control of CPU not
/// affect the host
struct MsrEmulateHandler {
    /// Only initialize msr_data with MSR source pCPU, and will not update
    /// msr value changes on host cpu into msr_data.
    msr_data: u64,
}

impl MsrEmulateHandler {
    fn new(index: u32, msr_config: &MsrConfig, msr_file: &MsrFileType) -> Result<Self> {
        let cpu_id = msr_config.from.get_cpu_id();
        let msr_data: u64 = if let Some(dev_msr) = msr_file.borrow().get(&cpu_id) {
            dev_msr.read(index)?
        } else {
            // Don't allow to write. Only read the value to initialize
            // `msr_data` and won't store in MsrHandlers level.
            MsrDevFile::new(cpu_id, true)?.read(index)?
        };

        Ok(MsrEmulateHandler { msr_data })
    }
}

impl MsrHandling for MsrEmulateHandler {
    fn read(&self) -> Result<u64> {
        Ok(self.msr_data)
    }

    fn write(&mut self, data: u64) -> Result<()> {
        self.msr_data = data;
        Ok(())
    }
}

/// MSR handler configuration. Per-cpu.
#[derive(Default)]
pub struct MsrHandlers {
    /// Store read/write permissions to control read/write brfore calling
    /// MsrHandling trait.
    pub handler: BTreeMap<u32, (MsrRWType, Rc<RefCell<Box<dyn MsrHandling>>>)>,
    /// Store file descriptor here to avoid cache duplicate descriptors
    /// for each MSR.
    /// Only collect descriptor of 'passthrough' handler, since 'emulate'
    /// uses descriptor only once during initialization.
    pub msr_file: MsrFileType,
}

impl MsrHandlers {
    pub fn new() -> Self {
        MsrHandlers {
            ..Default::default()
        }
    }

    pub fn read(&self, index: u32) -> Option<u64> {
        if let Some((rw_type, handler)) = self.handler.get(&index) {
            // It's not error. This means user does't want to handle
            // RDMSR. Just log it.
            if matches!(rw_type, MsrRWType::WriteOnly) {
                debug!("RDMSR is not allowed for msr: {:#x}", index);
                return None;
            }

            match handler.borrow().read() {
                Ok(data) => Some(data),
                Err(e) => {
                    error!("MSR host read failed {:#x} {:?}", index, e);
                    None
                }
            }
        } else {
            None
        }
    }

    pub fn write(&self, index: u32, data: u64) -> Option<()> {
        if let Some((rw_type, handler)) = self.handler.get(&index) {
            // It's not error. This means user does't want to handle
            // WRMSR. Just log it.
            if matches!(rw_type, MsrRWType::ReadOnly) {
                debug!("WRMSR is not allowed for msr: {:#x}", index);
                return None;
            }

            match handler.borrow_mut().write(data) {
                Ok(_) => Some(()),
                Err(e) => {
                    error!("MSR host write failed {:#x} {:?}", index, e);
                    None
                }
            }
        } else {
            None
        }
    }

    pub fn add_handler(
        &mut self,
        index: u32,
        msr_config: MsrConfig,
        cpu_id: usize,
    ) -> std::result::Result<(), MsrExitHandlerError> {
        match msr_config.action {
            MsrAction::MsrPassthrough => {
                let msr_handler: Rc<RefCell<Box<dyn MsrHandling>>> =
                    match MsrPassthroughHandler::new(index, &msr_config, Rc::clone(&self.msr_file))
                    {
                        Ok(r) => Rc::new(RefCell::new(Box::new(r))),
                        Err(e) => {
                            error!(
                                "failed to create MSR passthrough handler for vcpu {}: {:#}",
                                cpu_id, e
                            );
                            return Err(MsrExitHandlerError::HandlerCreateFailed);
                        }
                    };
                self.handler
                    .insert(index, (msr_config.rw_type, msr_handler));
            }
            MsrAction::MsrEmulate => {
                let msr_handler: Rc<RefCell<Box<dyn MsrHandling>>> =
                    match MsrEmulateHandler::new(index, &msr_config, &self.msr_file) {
                        Ok(r) => Rc::new(RefCell::new(Box::new(r))),
                        Err(e) => {
                            error!(
                                "failed to create MSR emulate handler for vcpu {}: {:#}",
                                cpu_id, e
                            );
                            return Err(MsrExitHandlerError::HandlerCreateFailed);
                        }
                    };
                self.handler
                    .insert(index, (msr_config.rw_type, msr_handler));
            }
        };
        Ok(())
    }
}

/// get override msr list
pub fn get_override_msr_list(
    msr_list: &BTreeMap<u32, MsrConfig>,
) -> (
    Vec<u32>, /* read override */
    Vec<u32>, /* write override */
) {
    let mut rd_msrs: Vec<u32> = Vec::new();
    let mut wr_msrs: Vec<u32> = Vec::new();

    for (index, config) in msr_list.iter() {
        if config.filter == MsrFilter::Override {
            match config.rw_type {
                MsrRWType::ReadOnly => {
                    rd_msrs.push(*index);
                }
                MsrRWType::WriteOnly => {
                    wr_msrs.push(*index);
                }
                MsrRWType::ReadWrite => {
                    rd_msrs.push(*index);
                    wr_msrs.push(*index);
                }
            }
        }
    }
    (rd_msrs, wr_msrs)
}
