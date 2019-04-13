// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::size_of;
use std::os::raw::c_void;
use std::sync::{Arc, Weak};

use crate::bindings::{
    libusb_alloc_transfer, libusb_cancel_transfer, libusb_device_handle, libusb_free_transfer,
    libusb_submit_transfer, libusb_transfer, libusb_transfer_status, LIBUSB_TRANSFER_CANCELLED,
    LIBUSB_TRANSFER_COMPLETED, LIBUSB_TRANSFER_ERROR, LIBUSB_TRANSFER_NO_DEVICE,
    LIBUSB_TRANSFER_OVERFLOW, LIBUSB_TRANSFER_STALL, LIBUSB_TRANSFER_TIMED_OUT,
    LIBUSB_TRANSFER_TYPE_BULK, LIBUSB_TRANSFER_TYPE_CONTROL, LIBUSB_TRANSFER_TYPE_INTERRUPT,
};
use crate::error::{Error, Result};
use crate::types::UsbRequestSetup;

/// Status of transfer.
#[derive(PartialEq)]
pub enum TransferStatus {
    Completed,
    Error,
    TimedOut,
    Cancelled,
    Stall,
    NoDevice,
    Overflow,
}

impl From<libusb_transfer_status> for TransferStatus {
    fn from(s: libusb_transfer_status) -> Self {
        match s {
            LIBUSB_TRANSFER_COMPLETED => TransferStatus::Completed,
            LIBUSB_TRANSFER_ERROR => TransferStatus::Error,
            LIBUSB_TRANSFER_TIMED_OUT => TransferStatus::TimedOut,
            LIBUSB_TRANSFER_CANCELLED => TransferStatus::Cancelled,
            LIBUSB_TRANSFER_STALL => TransferStatus::Stall,
            LIBUSB_TRANSFER_NO_DEVICE => TransferStatus::NoDevice,
            LIBUSB_TRANSFER_OVERFLOW => TransferStatus::Overflow,
            _ => TransferStatus::Error,
        }
    }
}

/// Trait for usb transfer buffer.
pub trait UsbTransferBuffer: Send {
    fn as_ptr(&mut self) -> *mut u8;
    fn len(&self) -> i32;
}

/// Default buffer size for control data transfer.
const CONTROL_DATA_BUFFER_SIZE: usize = 1024;

/// Buffer type for control transfer. The first 8-bytes is a UsbRequestSetup struct.
#[repr(C, packed)]
pub struct ControlTransferBuffer {
    pub setup_buffer: UsbRequestSetup,
    pub data_buffer: [u8; CONTROL_DATA_BUFFER_SIZE],
}

impl ControlTransferBuffer {
    fn new() -> ControlTransferBuffer {
        ControlTransferBuffer {
            setup_buffer: UsbRequestSetup {
                request_type: 0,
                request: 0,
                value: 0,
                index: 0,
                length: 0,
            },
            data_buffer: [0; CONTROL_DATA_BUFFER_SIZE],
        }
    }

    /// Set request setup for this control buffer.
    pub fn set_request_setup(&mut self, request_setup: &UsbRequestSetup) {
        self.setup_buffer = *request_setup;
    }
}

impl UsbTransferBuffer for ControlTransferBuffer {
    fn as_ptr(&mut self) -> *mut u8 {
        self as *mut ControlTransferBuffer as *mut u8
    }

    fn len(&self) -> i32 {
        if self.setup_buffer.length as usize > CONTROL_DATA_BUFFER_SIZE {
            panic!("Setup packet has an oversize length");
        }
        self.setup_buffer.length as i32 + size_of::<UsbRequestSetup>() as i32
    }
}

/// Buffer type for Bulk transfer.
pub struct BulkTransferBuffer {
    buffer: Vec<u8>,
}

impl BulkTransferBuffer {
    fn with_size(buffer_size: usize) -> Self {
        BulkTransferBuffer {
            buffer: vec![0; buffer_size],
        }
    }

    /// Get mutable interal slice of this buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    /// Get interal slice of this buffer.
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }
}

impl UsbTransferBuffer for BulkTransferBuffer {
    fn as_ptr(&mut self) -> *mut u8 {
        if self.buffer.len() == 0 {
            // Vec::as_mut_ptr() won't give 0x0 even if len() is 0.
            std::ptr::null_mut()
        } else {
            self.buffer.as_mut_ptr()
        }
    }

    fn len(&self) -> i32 {
        self.buffer.len() as i32
    }
}

type UsbTransferCompletionCallback<T> = dyn Fn(UsbTransfer<T>) + Send + 'static;

// This wraps libusb_transfer pointer.
struct LibUsbTransfer {
    ptr: *mut libusb_transfer,
}

impl Drop for LibUsbTransfer {
    fn drop(&mut self) {
        // Safe because 'self.ptr' is allocated by libusb_alloc_transfer.
        unsafe {
            libusb_free_transfer(self.ptr);
        }
    }
}

// It is safe to invoke libusb functions from multiple threads.
// We cannot modify libusb_transfer safely from multiple threads. All the modifications happens
// in construct (UsbTransfer::new) or consume (UsbTransfer::into_raw), we can consider this thread
// safe.
unsafe impl Send for LibUsbTransfer {}
unsafe impl Sync for LibUsbTransfer {}

/// TransferCanceller can cancel the transfer.
pub struct TransferCanceller {
    transfer: Weak<LibUsbTransfer>,
}

impl TransferCanceller {
    /// Return false if fail to cancel.
    pub fn try_cancel(&self) -> bool {
        match self.transfer.upgrade() {
            Some(t) => {
                // Safe because self.transfer has ownership of the raw pointer.
                let r = unsafe { libusb_cancel_transfer(t.ptr) };
                if r == 0 {
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }
}

struct UsbTransferInner<T: UsbTransferBuffer> {
    transfer: Arc<LibUsbTransfer>,
    callback: Option<Box<UsbTransferCompletionCallback<T>>>,
    buffer: T,
}

/// UsbTransfer owns a LibUsbTransfer, it's buffer and callback.
pub struct UsbTransfer<T: UsbTransferBuffer> {
    inner: Box<UsbTransferInner<T>>,
}

/// Build a control transfer.
pub fn control_transfer(timeout: u32) -> UsbTransfer<ControlTransferBuffer> {
    UsbTransfer::<ControlTransferBuffer>::new(
        0,
        LIBUSB_TRANSFER_TYPE_CONTROL as u8,
        timeout,
        ControlTransferBuffer::new(),
    )
}

/// Build a data transfer.
pub fn bulk_transfer(endpoint: u8, timeout: u32, size: usize) -> UsbTransfer<BulkTransferBuffer> {
    UsbTransfer::<BulkTransferBuffer>::new(
        endpoint,
        LIBUSB_TRANSFER_TYPE_BULK as u8,
        timeout,
        BulkTransferBuffer::with_size(size),
    )
}

/// Build a data transfer.
pub fn interrupt_transfer(
    endpoint: u8,
    timeout: u32,
    size: usize,
) -> UsbTransfer<BulkTransferBuffer> {
    UsbTransfer::<BulkTransferBuffer>::new(
        endpoint,
        LIBUSB_TRANSFER_TYPE_INTERRUPT as u8,
        timeout,
        BulkTransferBuffer::with_size(size),
    )
}

impl<T: UsbTransferBuffer> UsbTransfer<T> {
    fn new(endpoint: u8, type_: u8, timeout: u32, buffer: T) -> Self {
        // Safe because alloc is safe.
        let transfer: *mut libusb_transfer = unsafe { libusb_alloc_transfer(0) };
        // Just panic on OOM.
        assert!(!transfer.is_null());
        let inner = Box::new(UsbTransferInner {
            transfer: Arc::new(LibUsbTransfer { ptr: transfer }),
            callback: None,
            buffer,
        });
        // Safe because we inited transfer.
        let raw_transfer: &mut libusb_transfer = unsafe { &mut *(inner.transfer.ptr) };
        raw_transfer.endpoint = endpoint;
        raw_transfer.type_ = type_;
        raw_transfer.timeout = timeout;
        raw_transfer.callback = Some(UsbTransfer::<T>::on_transfer_completed);
        UsbTransfer { inner }
    }

    /// Get canceller of this transfer.
    pub fn get_canceller(&self) -> TransferCanceller {
        let weak_transfer = Arc::downgrade(&self.inner.transfer);
        TransferCanceller {
            transfer: weak_transfer,
        }
    }

    /// Set callback function for transfer completion.
    pub fn set_callback<C: 'static + Fn(UsbTransfer<T>) + Send>(&mut self, cb: C) {
        self.inner.callback = Some(Box::new(cb));
    }

    /// Get a reference to the buffer.
    pub fn buffer(&self) -> &T {
        &self.inner.buffer
    }

    /// Get a mutable reference to the buffer.
    pub fn buffer_mut(&mut self) -> &mut T {
        &mut self.inner.buffer
    }

    /// Get actual length of data that was transferred.
    pub fn actual_length(&self) -> i32 {
        let transfer = self.inner.transfer.ptr;
        // Safe because inner.ptr is always allocated by libusb_alloc_transfer.
        unsafe { (*transfer).actual_length }
    }

    /// Get the transfer status of this transfer.
    pub fn status(&self) -> TransferStatus {
        let transfer = self.inner.transfer.ptr;
        // Safe because inner.ptr is always allocated by libusb_alloc_transfer.
        unsafe { TransferStatus::from((*transfer).status) }
    }

    /// Submit this transfer to device handle. 'self' is consumed. On success, the memory will be
    /// 'leaked' (and stored in user_data) and sent to libusb, when the async operation is done,
    /// on_transfer_completed will recreate 'self' and deliver it to callback/free 'self'. On
    /// faliure, 'self' is returned with an error.
    ///
    /// # Safety
    ///
    /// Assumes libusb_device_handle is an handled opened by libusb, self.inner.transfer.ptr is
    /// initialized with correct buffer and length.
    pub unsafe fn submit(self, handle: *mut libusb_device_handle) -> Result<()> {
        let transfer = self.into_raw();
        (*transfer).dev_handle = handle;
        match Error::from(libusb_submit_transfer(transfer)) {
            Error::Success(_e) => Ok(()),
            err => {
                UsbTransfer::<T>::from_raw(transfer);
                Err(err)
            }
        }
    }

    /// Invoke callback when transfer is completed.
    ///
    /// # Safety
    ///
    /// Assumes libusb_tranfser is finished. This function is called by libusb, don't call it
    /// manually.
    unsafe extern "C" fn on_transfer_completed(transfer: *mut libusb_transfer) {
        let mut transfer = UsbTransfer::<T>::from_raw(transfer);
        // Callback is reset to None.
        if let Some(cb) = transfer.inner.callback.take() {
            cb(transfer);
        }
    }

    fn into_raw(mut self) -> *mut libusb_transfer {
        let transfer: *mut libusb_transfer = self.inner.transfer.ptr;
        // Safe because transfer is allocated by libusb_alloc_transfer.
        unsafe {
            (*transfer).buffer = self.buffer_mut().as_ptr();
            (*transfer).length = self.buffer_mut().len();
            (*transfer).user_data = Box::into_raw(self.inner) as *mut c_void;
        }
        transfer
    }

    unsafe fn from_raw(transfer: *mut libusb_transfer) -> Self {
        UsbTransfer {
            inner: Box::<UsbTransferInner<T>>::from_raw(
                (*transfer).user_data as *mut UsbTransferInner<T>,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    pub fn fake_submit_transfer<T: UsbTransferBuffer>(transfer: UsbTransfer<T>) {
        let transfer = transfer.into_raw();
        unsafe {
            match (*transfer).callback {
                Some(cb) => cb(transfer),
                // Although no callback is invoked, we still need on_transfer_completed to
                // free memory.
                None => panic!("Memory leak!"),
            };
        }
    }

    #[test]
    fn check_control_buffer_size() {
        assert_eq!(
            size_of::<ControlTransferBuffer>(),
            size_of::<UsbRequestSetup>() + CONTROL_DATA_BUFFER_SIZE
        );
    }

    #[test]
    fn submit_transfer_no_callback_test() {
        let t = control_transfer(0);
        fake_submit_transfer(t);
        let t = bulk_transfer(0, 0, 1);
        fake_submit_transfer(t);
    }

    struct FakeTransferController {
        data: Mutex<u8>,
    }

    #[test]
    fn submit_transfer_with_callback() {
        let c = Arc::new(FakeTransferController {
            data: Mutex::new(0),
        });
        let c1 = Arc::downgrade(&c);
        let mut t = control_transfer(0);
        t.set_callback(move |_t| {
            let c = c1.upgrade().unwrap();
            *c.data.lock().unwrap() = 3;
        });
        fake_submit_transfer(t);
        assert_eq!(*c.data.lock().unwrap(), 3);
    }
}
