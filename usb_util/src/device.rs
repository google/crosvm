// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryInto;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::mem::size_of_val;
use std::os::raw::c_int;
use std::os::raw::c_uchar;
use std::os::raw::c_uint;
use std::os::raw::c_void;
use std::sync::Arc;

use base::error;
use base::handle_eintr_errno;
use base::AsRawDescriptor;
use base::IoctlNr;
use base::RawDescriptor;
use data_model::vec_with_array_field;
use libc::EAGAIN;
use libc::ENODEV;
use libc::ENOENT;
use libc::EPIPE;

use crate::control_request_type;
use crate::descriptor;
use crate::ConfigDescriptorTree;
use crate::ControlRequestDataPhaseTransferDirection;
use crate::ControlRequestRecipient;
use crate::ControlRequestType;
use crate::DeviceDescriptor;
use crate::DeviceDescriptorTree;
use crate::DeviceSpeed;
use crate::Error;
use crate::Result;
use crate::StandardControlRequest;

/// Device represents a USB device.
pub struct Device {
    fd: Arc<File>,
    device_descriptor_tree: DeviceDescriptorTree,
}

/// Transfer contains the information necessary to submit a USB request
/// and, once it has been submitted and completed, contains the response.
pub struct Transfer {
    // NOTE: This Vec is actually a single URB with a trailing
    // variable-length field created by vec_with_array_field().
    urb: Vec<usb_sys::usbdevfs_urb>,
    pub buffer: Vec<u8>,
    callback: Option<Box<dyn Fn(Transfer) + Send + Sync>>,
}

/// TransferHandle is a handle that allows cancellation of in-flight transfers
/// between submit_transfer() and get_completed_transfer().
/// Attempting to cancel a transfer that has already completed is safe and will
/// return an error.
pub struct TransferHandle {
    weak_transfer: std::sync::Weak<Transfer>,
    fd: std::sync::Weak<File>,
}

#[derive(PartialEq, Eq)]
pub enum TransferStatus {
    Completed,
    Error,
    Cancelled,
    NoDevice,
    Stalled,
}

impl Device {
    /// Create a new `Device` from a file descriptor.
    /// `fd` should be a file in usbdevfs (e.g. `/dev/bus/usb/001/002`).
    pub fn new(mut fd: File) -> Result<Self> {
        fd.seek(SeekFrom::Start(0)).map_err(Error::DescriptorRead)?;
        let mut descriptor_data = Vec::new();
        fd.read_to_end(&mut descriptor_data)
            .map_err(Error::DescriptorRead)?;
        let device_descriptor_tree = descriptor::parse_usbfs_descriptors(&descriptor_data)?;

        let device = Device {
            fd: Arc::new(fd),
            device_descriptor_tree,
        };
        Ok(device)
    }

    pub fn fd(&self) -> Arc<File> {
        self.fd.clone()
    }

    unsafe fn ioctl(&self, nr: IoctlNr) -> Result<i32> {
        let ret = handle_eintr_errno!(base::ioctl(&*self.fd, nr));
        if ret < 0 {
            return Err(Error::IoctlFailed(nr, base::Error::last()));
        }
        Ok(ret)
    }

    unsafe fn ioctl_with_ref<T>(&self, nr: IoctlNr, arg: &T) -> Result<i32> {
        let ret = handle_eintr_errno!(base::ioctl_with_ref(&*self.fd, nr, arg));
        if ret < 0 {
            return Err(Error::IoctlFailed(nr, base::Error::last()));
        }
        Ok(ret)
    }

    unsafe fn ioctl_with_mut_ref<T>(&self, nr: IoctlNr, arg: &mut T) -> Result<i32> {
        let ret = handle_eintr_errno!(base::ioctl_with_mut_ref(&*self.fd, nr, arg));
        if ret < 0 {
            return Err(Error::IoctlFailed(nr, base::Error::last()));
        }
        Ok(ret)
    }

    unsafe fn ioctl_with_mut_ptr<T>(&self, nr: IoctlNr, arg: *mut T) -> Result<i32> {
        let ret = handle_eintr_errno!(base::ioctl_with_mut_ptr(&*self.fd, nr, arg));
        if ret < 0 {
            return Err(Error::IoctlFailed(nr, base::Error::last()));
        }
        Ok(ret)
    }

    /// Submit a transfer to the device.
    /// The transfer will be processed asynchronously by the device.
    /// Call `poll_transfers()` on this device to check for completed transfers.
    pub fn submit_transfer(&mut self, transfer: Transfer) -> Result<TransferHandle> {
        let mut rc_transfer = Arc::new(transfer);

        // Technically, Arc::from_raw() should only be called on pointers returned
        // from Arc::into_raw(). However, we need to stash this value inside the
        // Arc<Transfer> itself, so we manually calculate the address that would be
        // returned from Arc::into_raw() via Deref and then call Arc::into_raw()
        // to forget the Arc without dropping its contents.
        // Do not remove the into_raw() call!
        let raw_transfer = (&*rc_transfer) as *const Transfer as usize;
        match Arc::get_mut(&mut rc_transfer) {
            Some(t) => t.urb_mut().usercontext = raw_transfer,
            None => {
                // This should never happen, since there is only one strong reference
                // at this point.
                return Err(Error::RcGetMutFailed);
            }
        }
        let _ = Arc::into_raw(rc_transfer.clone());

        let urb_ptr = rc_transfer.urb.as_ptr() as *mut usb_sys::usbdevfs_urb;

        // Safe because we control the lifetime of the URB via Arc::into_raw() and
        // Arc::from_raw() in poll_transfers().
        unsafe {
            self.ioctl_with_mut_ptr(usb_sys::USBDEVFS_SUBMITURB(), urb_ptr)?;
        }

        let weak_transfer = Arc::downgrade(&rc_transfer);

        Ok(TransferHandle {
            weak_transfer,
            fd: Arc::downgrade(&self.fd),
        })
    }

    /// Check for completed asynchronous transfers submitted via `submit_transfer()`.
    /// The callback for each completed transfer will be called.
    pub fn poll_transfers(&self) -> Result<()> {
        // Reap completed transfers until we get EAGAIN.
        loop {
            let mut urb_ptr: *mut usb_sys::usbdevfs_urb = std::ptr::null_mut();
            // Safe because we provide a valid urb_ptr to be filled by the kernel.
            let result =
                unsafe { self.ioctl_with_mut_ref(usb_sys::USBDEVFS_REAPURBNDELAY(), &mut urb_ptr) };
            match result {
                // EAGAIN indicates no more completed transfers right now.
                Err(Error::IoctlFailed(_nr, e)) if e.errno() == EAGAIN => break,
                Err(e) => return Err(e),
                Ok(_) => {}
            }

            if urb_ptr.is_null() {
                break;
            }

            // Safe because the URB usercontext field is always set to the result of
            // Arc::into_raw() in submit_transfer().
            let rc_transfer: Arc<Transfer> =
                unsafe { Arc::from_raw((*urb_ptr).usercontext as *const Transfer) };

            // There should always be exactly one strong reference to rc_transfer,
            // so try_unwrap() should never fail.
            let mut transfer = Arc::try_unwrap(rc_transfer).map_err(|_| Error::RcUnwrapFailed)?;

            if let Some(cb) = transfer.callback.take() {
                cb(transfer);
            }
        }

        Ok(())
    }

    /// Perform a USB port reset to reinitialize a device.
    pub fn reset(&self) -> Result<()> {
        // TODO(dverkamp): re-enable reset once crbug.com/1058059 is resolved.
        // Skip reset for all non-Edge TPU devices.
        let vid = self.device_descriptor_tree.idVendor;
        let pid = self.device_descriptor_tree.idProduct;
        match (vid, pid) {
            (0x1a6e, 0x089a) => (),
            _ => return Ok(()),
        }

        // Safe because self.fd is a valid usbdevfs file descriptor.
        let result = unsafe { self.ioctl(usb_sys::USBDEVFS_RESET()) };

        if let Err(Error::IoctlFailed(_nr, errno_err)) = result {
            // The device may disappear after a reset if e.g. its firmware changed.
            // Treat that as success.
            if errno_err.errno() == libc::ENODEV {
                return Ok(());
            }
        }

        result?;
        Ok(())
    }

    /// Claim an interface on this device.
    pub fn claim_interface(&self, interface_number: u8) -> Result<()> {
        let disconnect_claim = usb_sys::usbdevfs_disconnect_claim {
            interface: interface_number.into(),
            flags: 0,
            driver: [0u8; 256],
        };
        // Safe because self.fd is a valid usbdevfs file descriptor and we pass a valid
        // pointer to a usbdevs_disconnect_claim structure.
        unsafe {
            self.ioctl_with_ref(usb_sys::USBDEVFS_DISCONNECT_CLAIM(), &disconnect_claim)?;
        }

        Ok(())
    }

    /// Release an interface previously claimed with `claim_interface()`.
    pub fn release_interface(&self, interface_number: u8) -> Result<()> {
        let ifnum: c_uint = interface_number.into();
        // Safe because self.fd is a valid usbdevfs file descriptor and we pass a valid
        // pointer to unsigned int.
        unsafe {
            self.ioctl_with_ref(usb_sys::USBDEVFS_RELEASEINTERFACE(), &ifnum)?;
        }

        Ok(())
    }

    /// Activate an alternate setting for an interface.
    pub fn set_interface_alt_setting(
        &self,
        interface_number: u8,
        alternative_setting: u8,
    ) -> Result<()> {
        let setinterface = usb_sys::usbdevfs_setinterface {
            interface: interface_number.into(),
            altsetting: alternative_setting.into(),
        };
        // Safe because self.fd is a valid usbdevfs file descriptor and we pass a valid
        // pointer to a usbdevfs_setinterface structure.
        unsafe {
            self.ioctl_with_ref(usb_sys::USBDEVFS_SETINTERFACE(), &setinterface)?;
        }
        Ok(())
    }

    /// Set active configuration for this device.
    pub fn set_active_configuration(&mut self, config: u8) -> Result<()> {
        let config: c_int = config.into();
        // Safe because self.fd is a valid usbdevfs file descriptor and we pass a valid
        // pointer to int.
        unsafe {
            self.ioctl_with_ref(usb_sys::USBDEVFS_SETCONFIGURATION(), &config)?;
        }

        Ok(())
    }

    /// Get the device descriptor of this device.
    pub fn get_device_descriptor(&self) -> Result<DeviceDescriptor> {
        Ok(*self.device_descriptor_tree)
    }

    pub fn get_device_descriptor_tree(&self) -> &DeviceDescriptorTree {
        &self.device_descriptor_tree
    }

    /// Get active config descriptor of this device.
    pub fn get_config_descriptor(&self, config: u8) -> Result<ConfigDescriptorTree> {
        match self.device_descriptor_tree.get_config_descriptor(config) {
            Some(config_descriptor) => Ok(config_descriptor.clone()),
            None => Err(Error::NoSuchDescriptor),
        }
    }

    /// Get a configuration descriptor by its index within the list of descriptors returned
    /// by the device.
    pub fn get_config_descriptor_by_index(&self, config_index: u8) -> Result<ConfigDescriptorTree> {
        match self
            .device_descriptor_tree
            .get_config_descriptor_by_index(config_index)
        {
            Some(config_descriptor) => Ok(config_descriptor.clone()),
            None => Err(Error::NoSuchDescriptor),
        }
    }

    /// Get bConfigurationValue of the currently active configuration.
    pub fn get_active_configuration(&self) -> Result<u8> {
        // If the device only exposes a single configuration, bypass the control transfer below
        // by looking up the configuration value from the descriptor.
        if self.device_descriptor_tree.bNumConfigurations == 1 {
            if let Some(config_descriptor) = self
                .device_descriptor_tree
                .get_config_descriptor_by_index(0)
            {
                return Ok(config_descriptor.bConfigurationValue);
            }
        }

        // Send a synchronous control transfer to get the active configuration.
        let mut active_config: u8 = 0;
        let ctrl_transfer = usb_sys::usbdevfs_ctrltransfer {
            bRequestType: control_request_type(
                ControlRequestType::Standard,
                ControlRequestDataPhaseTransferDirection::DeviceToHost,
                ControlRequestRecipient::Device,
            ),
            bRequest: StandardControlRequest::GetConfiguration as u8,
            wValue: 0,
            wIndex: 0,
            wLength: size_of_val(&active_config) as u16,
            timeout: 5000, // milliseconds
            data: &mut active_config as *mut u8 as *mut c_void,
        };
        // Safe because self.fd is a valid usbdevfs file descriptor and we pass a valid
        // pointer to a usbdevfs_ctrltransfer structure.
        unsafe {
            self.ioctl_with_ref(usb_sys::USBDEVFS_CONTROL(), &ctrl_transfer)?;
        }
        Ok(active_config)
    }

    /// Get the total number of configurations for this device.
    pub fn get_num_configurations(&self) -> u8 {
        self.device_descriptor_tree.bNumConfigurations
    }

    /// Clear the halt/stall condition for an endpoint.
    pub fn clear_halt(&self, ep_addr: u8) -> Result<()> {
        let endpoint: c_uint = ep_addr.into();
        // Safe because self.fd is a valid usbdevfs file descriptor and we pass a valid
        // pointer to unsigned int.
        unsafe {
            self.ioctl_with_ref(usb_sys::USBDEVFS_CLEAR_HALT(), &endpoint)?;
        }

        Ok(())
    }

    /// Get speed of this device.
    pub fn get_speed(&self) -> Result<Option<DeviceSpeed>> {
        let speed = unsafe { self.ioctl(usb_sys::USBDEVFS_GET_SPEED()) }?;
        match speed {
            1 => Ok(Some(DeviceSpeed::Low)),       // Low Speed
            2 => Ok(Some(DeviceSpeed::Full)),      // Full Speed
            3 => Ok(Some(DeviceSpeed::High)),      // High Speed
            4 => Ok(Some(DeviceSpeed::High)),      // Wireless, treat as a High Speed device
            5 => Ok(Some(DeviceSpeed::Super)),     // Super Speed
            6 => Ok(Some(DeviceSpeed::SuperPlus)), // Super Speed Plus
            _ => {
                error!("unexpected speed: {:?}", speed);
                Ok(None)
            }
        }
    }

    /// Allocate streams for the endpoint
    pub fn alloc_streams(&self, ep: u8, num_streams: u16) -> Result<()> {
        let mut streams = vec_with_array_field::<usb_sys::usbdevfs_streams, c_uchar>(1);
        streams[0].num_streams = num_streams as c_uint;
        streams[0].num_eps = 1 as c_uint;
        // Safe because we have allocated enough memory
        let eps = unsafe { streams[0].eps.as_mut_slice(1) };
        eps[0] = ep as c_uchar;
        // Safe because self.fd is a valid usbdevfs file descriptor and we pass a valid
        // pointer to a usbdevfs_streams structure.
        unsafe {
            self.ioctl_with_ref(usb_sys::USBDEVFS_ALLOC_STREAMS(), &streams[0])?;
        }
        Ok(())
    }

    /// Free streams for the endpoint
    pub fn free_streams(&self, ep: u8) -> Result<()> {
        let mut streams = vec_with_array_field::<usb_sys::usbdevfs_streams, c_uchar>(1);
        streams[0].num_eps = 1 as c_uint;
        // Safe because we have allocated enough memory
        let eps = unsafe { streams[0].eps.as_mut_slice(1) };
        eps[0] = ep as c_uchar;
        // Safe because self.fd is a valid usbdevfs file descriptor and we pass a valid
        // pointer to a usbdevfs_streams structure.
        unsafe {
            self.ioctl_with_ref(usb_sys::USBDEVFS_FREE_STREAMS(), &streams[0])?;
        }
        Ok(())
    }
}

impl AsRawDescriptor for Device {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.fd.as_raw_descriptor()
    }
}

impl Transfer {
    fn urb(&self) -> &usb_sys::usbdevfs_urb {
        // self.urb is a Vec created with `vec_with_array_field`; the first entry is
        // the URB itself.
        &self.urb[0]
    }

    fn urb_mut(&mut self) -> &mut usb_sys::usbdevfs_urb {
        &mut self.urb[0]
    }

    fn new(
        transfer_type: u8,
        endpoint: u8,
        buffer: Vec<u8>,
        iso_packets: &[usb_sys::usbdevfs_iso_packet_desc],
    ) -> Result<Transfer> {
        let mut transfer = Transfer {
            urb: vec_with_array_field::<usb_sys::usbdevfs_urb, usb_sys::usbdevfs_iso_packet_desc>(
                iso_packets.len(),
            ),
            buffer,
            callback: None,
        };

        transfer.urb_mut().urb_type = transfer_type;
        transfer.urb_mut().endpoint = endpoint;
        transfer.urb_mut().buffer = transfer.buffer.as_mut_ptr() as *mut c_void;
        transfer.urb_mut().buffer_length = transfer
            .buffer
            .len()
            .try_into()
            .map_err(Error::InvalidBufferLength)?;

        // Safe because we ensured there is enough space in transfer.urb to hold the number of
        // isochronous frames required.
        let iso_frame_desc = unsafe {
            transfer
                .urb_mut()
                .iso_frame_desc
                .as_mut_slice(iso_packets.len())
        };
        iso_frame_desc.copy_from_slice(iso_packets);

        Ok(transfer)
    }

    /// Create a control transfer.
    pub fn new_control(buffer: Vec<u8>) -> Result<Transfer> {
        let endpoint = 0;
        Self::new(usb_sys::USBDEVFS_URB_TYPE_CONTROL, endpoint, buffer, &[])
    }

    /// Create an interrupt transfer.
    pub fn new_interrupt(endpoint: u8, buffer: Vec<u8>) -> Result<Transfer> {
        Self::new(usb_sys::USBDEVFS_URB_TYPE_INTERRUPT, endpoint, buffer, &[])
    }

    /// Create a bulk transfer.
    pub fn new_bulk(endpoint: u8, buffer: Vec<u8>, stream_id: Option<u16>) -> Result<Transfer> {
        let mut transfer = Self::new(usb_sys::USBDEVFS_URB_TYPE_BULK, endpoint, buffer, &[])?;
        if let Some(stream_id) = stream_id {
            transfer.urb_mut().number_of_packets_or_stream_id = stream_id as u32;
        }
        Ok(transfer)
    }

    /// Create an isochronous transfer.
    pub fn new_isochronous(endpoint: u8, buffer: Vec<u8>) -> Result<Transfer> {
        // TODO(dverkamp): allow user to specify iso descriptors
        Self::new(usb_sys::USBDEVFS_URB_TYPE_ISO, endpoint, buffer, &[])
    }

    /// Get the status of a completed transfer.
    pub fn status(&self) -> TransferStatus {
        let status = self.urb().status;
        if status == 0 {
            TransferStatus::Completed
        } else if status == -ENODEV {
            TransferStatus::NoDevice
        } else if status == -ENOENT {
            TransferStatus::Cancelled
        } else if status == -EPIPE {
            TransferStatus::Stalled
        } else {
            TransferStatus::Error
        }
    }

    /// Get the actual amount of data transferred, which may be less than
    /// the original length.
    pub fn actual_length(&self) -> usize {
        self.urb().actual_length as usize
    }

    /// Set callback function for transfer completion.
    pub fn set_callback<C: 'static + Fn(Transfer) + Send + Sync>(&mut self, cb: C) {
        self.callback = Some(Box::new(cb));
    }
}

impl TransferHandle {
    /// Attempt to cancel the transfer associated with this `TransferHandle`.
    /// Safe to call even if the transfer has already completed;
    /// `Error::TransferAlreadyCompleted` will be returned in this case.
    pub fn cancel(self) -> Result<()> {
        let rc_transfer = match self.weak_transfer.upgrade() {
            None => return Err(Error::TransferAlreadyCompleted),
            Some(rc_transfer) => rc_transfer,
        };

        let urb_ptr = rc_transfer.urb.as_ptr() as *mut usb_sys::usbdevfs_urb;
        let fd = match self.fd.upgrade() {
            None => return Err(Error::NoDevice),
            Some(fd) => fd,
        };

        // Safe because fd is a valid usbdevfs file descriptor and we pass a valid
        // pointer to a usbdevfs_urb structure.
        if unsafe {
            handle_eintr_errno!(base::ioctl_with_mut_ptr(
                &*fd,
                usb_sys::USBDEVFS_DISCARDURB(),
                urb_ptr
            ))
        } < 0
        {
            return Err(Error::IoctlFailed(
                usb_sys::USBDEVFS_DISCARDURB(),
                base::Error::last(),
            ));
        }

        Ok(())
    }
}
