// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Result;

use crate::IrqChip;

pub trait IrqChipRiscv64: IrqChip {
    /// Clones this trait as a `Box` version of itself.
    fn try_box_clone(&self) -> Result<Box<dyn IrqChipRiscv64>>;

    /// Returns self as the super-trait IrqChip.
    fn as_irq_chip(&self) -> &dyn IrqChip;

    /// Returns self as the mutable super-trait IrqChip.
    fn as_irq_chip_mut(&mut self) -> &mut dyn IrqChip;

    /// Completes IrqChip setup. Must be called after Vcpus are created.
    fn finalize(&self) -> Result<()>;

    /// Returns the number of ids and sources supported by this IrqChip(assuming it's AIA).
    fn get_num_ids_sources(&self) -> (usize, usize);

    // Snapshot irqchip.
    fn snapshot(&self, _cpus_num: usize) -> anyhow::Result<serde_json::Value> {
        anyhow::bail!("snapshot not yet implemented for riscv64")
    }

    fn restore(&mut self, _data: serde_json::Value, _vcpus_num: usize) -> anyhow::Result<()> {
        anyhow::bail!("restore not yet implemented for riscv64")
    }
}
