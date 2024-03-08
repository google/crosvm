// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use win_util::ProcessType;

use crate::protos::event_details::EmulatorProcessType;

impl From<ProcessType> for EmulatorProcessType {
    fn from(process_type: ProcessType) -> Self {
        match process_type {
            ProcessType::Block => EmulatorProcessType::PROCESS_TYPE_BLOCK,
            ProcessType::Main => EmulatorProcessType::PROCESS_TYPE_MAIN,
            ProcessType::Metrics => EmulatorProcessType::PROCESS_TYPE_METRICS,
            ProcessType::Net => EmulatorProcessType::PROCESS_TYPE_NET,
            ProcessType::Slirp => EmulatorProcessType::PROCESS_TYPE_SLIRP,
            ProcessType::Gpu => EmulatorProcessType::PROCESS_TYPE_GPU,
            ProcessType::Snd => EmulatorProcessType::PROCESS_TYPE_SOUND,
            ProcessType::Broker => EmulatorProcessType::PROCESS_TYPE_BROKER,
            ProcessType::Spu => EmulatorProcessType::PROCESS_TYPE_SPU,
            ProcessType::UnknownType => panic!("Unknown process type found"),
        }
    }
}
