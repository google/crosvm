// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod defines;
mod descriptor;
mod memory_mapping;
mod shm;
pub mod sys;

pub use defines::*;
pub use descriptor::AsBorrowedDescriptor;
pub use descriptor::AsRawDescriptor;
pub use descriptor::FromRawDescriptor;
pub use descriptor::IntoRawDescriptor;
pub use memory_mapping::MemoryMapping;
pub use shm::SharedMemory;
pub use sys::platform::descriptor::OwnedDescriptor;
pub use sys::platform::descriptor::RawDescriptor;
pub use sys::platform::descriptor::DEFAULT_RAW_DESCRIPTOR;
pub use sys::platform::event::Event;
pub use sys::platform::pipe::create_pipe;
pub use sys::platform::pipe::ReadPipe;
pub use sys::platform::pipe::WritePipe;
pub use sys::platform::shm::round_up_to_page_size;
pub use sys::platform::tube::Listener;
pub use sys::platform::tube::Tube;
pub use sys::platform::wait_context::WaitContext;
