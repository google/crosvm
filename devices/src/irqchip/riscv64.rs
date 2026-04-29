// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Result;
use snapshot::AnySnapshot;

use crate::IrqChip;

pub trait IrqChipRiscv64: IrqChip {
    /// Completes IrqChip setup. Must be called after Vcpus are created.
    fn finalize(&self) -> Result<()>;

    /// Returns the number of ids and sources supported by this IrqChip(assuming it's AIA).
    fn get_num_ids_sources(&self) -> (usize, usize);

    // Snapshot irqchip.
    fn snapshot(&self, _cpus_num: usize) -> anyhow::Result<AnySnapshot> {
        anyhow::bail!("snapshot not yet implemented for riscv64")
    }

    fn restore(&self, _data: AnySnapshot, _vcpus_num: usize) -> anyhow::Result<()> {
        anyhow::bail!("restore not yet implemented for riscv64")
    }
}
