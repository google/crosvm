// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Error as IOError;

use remain::sorted;
use thiserror::Error;

use crate::utils::Error as UtilsError;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Cannot convert the u2f init packet from bytes")]
    CannotConvertInitPacketFromBytes,
    #[error("Cannot extract cid value from packet bytes")]
    CannotExtractCidFromBytes,
    #[error("The fido device is in an inconsistent state")]
    InconsistentFidoDeviceState,
    #[error("Invalid data buffer size")]
    InvalidDataBufferSize,
    #[error("The u2f init packet is invalid")]
    InvalidInitPacket,
    #[error("The u2f init packet contains invalid data size for the nonce")]
    InvalidNonceSize,
    #[error("Pending packet queue is full and cannot process more host packets")]
    PendingInQueueFull,
    #[error("Failed to read packet from hidraw device")]
    ReadHidrawDevice(IOError),
    #[error("Cannot start fido device queue")]
    StartAsyncFidoQueue(UtilsError),
    #[error("Unsupported TransferBuffer type")]
    UnsupportedTransferBufferType,
    #[error("Failed to write to hidraw device")]
    WriteHidrawDevice(IOError),
}

pub type Result<T> = std::result::Result<T, Error>;
