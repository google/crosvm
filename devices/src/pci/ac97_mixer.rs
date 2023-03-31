// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::pci::ac97_regs::*;
use crate::pci::PCI_VENDOR_ID_INTEL;

// Extented Audio ID
const AC97_EXTENDED_ID: u16 = MIXER_EI_VRA | MIXER_EI_CDAC | MIXER_EI_SDAC | MIXER_EI_LDAC;

// Master volume register is specified in 1.5dB steps.
const MASTER_VOLUME_STEP_DB: f64 = 1.5;

/// `Ac97Mixer` holds the mixer state for the AC97 bus.
/// The mixer is used by calling the `readb`/`readw`/`readl` functions to read register values and
/// the `writeb`/`writew`/`writel` functions to set register values.
pub struct Ac97Mixer {
    // Mixer Registers
    master_volume_l: u8,
    master_volume_r: u8,
    master_mute: bool,
    mic_muted: bool,
    mic_20db: bool,
    mic_volume: u8,
    record_gain_l: u8,
    record_gain_r: u8,
    record_gain_mute: bool,
    pcm_out_vol_l: u16,
    pcm_out_vol_r: u16,
    pcm_out_mute: bool,
    power_down_control: u16,
    ext_audio_status_ctl: u16,
    pcm_front_dac_rate: u16,
    pcm_surr_dac_rate: u16,
    pcm_lfe_dac_rate: u16,
}

impl Ac97Mixer {
    /// Creates an 'Ac97Mixer' with the standard default register values.
    pub fn new() -> Self {
        Ac97Mixer {
            master_volume_l: 0,
            master_volume_r: 0,
            master_mute: true,
            mic_muted: true,
            mic_20db: false,
            mic_volume: 0x8,
            record_gain_l: 0,
            record_gain_r: 0,
            record_gain_mute: true,
            pcm_out_vol_l: 0x8,
            pcm_out_vol_r: 0x8,
            pcm_out_mute: true,
            power_down_control: PD_REG_STATUS_MASK, // Report everything is ready.
            ext_audio_status_ctl: 0,
            // Default to 48 kHz.
            pcm_front_dac_rate: 0xBB80,
            pcm_surr_dac_rate: 0xBB80,
            pcm_lfe_dac_rate: 0xBB80,
        }
    }

    pub fn reset(&mut self) {
        // Upon reset, the audio sample rate registers default to 48 kHz, and VRA=0.
        self.ext_audio_status_ctl &= !MIXER_EI_VRA;
        self.pcm_front_dac_rate = 0xBB80;
        self.pcm_surr_dac_rate = 0xBB80;
        self.pcm_lfe_dac_rate = 0xBB80;
    }

    /// Reads a word from the register at `offset`.
    pub fn readw(&self, offset: u64) -> u16 {
        match offset {
            MIXER_RESET_00 => BC_DEDICATED_MIC,
            MIXER_MASTER_VOL_MUTE_02 => self.get_master_reg(),
            MIXER_MIC_VOL_MUTE_0E => self.get_mic_volume(),
            MIXER_PCM_OUT_VOL_MUTE_18 => self.get_pcm_out_volume(),
            MIXER_REC_VOL_MUTE_1C => self.get_record_gain_reg(),
            MIXER_POWER_DOWN_CONTROL_26 => self.power_down_control,
            MIXER_EXTENDED_AUDIO_ID_28 => AC97_EXTENDED_ID,
            MIXER_VENDOR_ID1_7C => PCI_VENDOR_ID_INTEL,
            MIXER_VENDOR_ID2_7E => PCI_VENDOR_ID_INTEL,
            MIXER_EXTENDED_AUDIO_STATUS_CONTROL_28 => self.ext_audio_status_ctl,
            MIXER_PCM_FRONT_DAC_RATE_2C => self.pcm_front_dac_rate,
            MIXER_PCM_SURR_DAC_RATE_2E => self.pcm_surr_dac_rate,
            MIXER_PCM_LFE_DAC_RATE_30 => self.pcm_lfe_dac_rate,
            _ => 0,
        }
    }

    /// Writes a word `val` to the register `offset`.
    pub fn writew(&mut self, offset: u64, val: u16) {
        match offset {
            MIXER_RESET_00 => self.reset(),
            MIXER_MASTER_VOL_MUTE_02 => self.set_master_reg(val),
            MIXER_MIC_VOL_MUTE_0E => self.set_mic_volume(val),
            MIXER_PCM_OUT_VOL_MUTE_18 => self.set_pcm_out_volume(val),
            MIXER_REC_VOL_MUTE_1C => self.set_record_gain_reg(val),
            MIXER_POWER_DOWN_CONTROL_26 => self.set_power_down_reg(val),
            MIXER_EXTENDED_AUDIO_STATUS_CONTROL_28 => self.ext_audio_status_ctl = val,
            MIXER_PCM_FRONT_DAC_RATE_2C => self.pcm_front_dac_rate = val,
            MIXER_PCM_SURR_DAC_RATE_2E => self.pcm_surr_dac_rate = val,
            MIXER_PCM_LFE_DAC_RATE_30 => self.pcm_lfe_dac_rate = val,
            _ => (),
        }
    }

    /// Returns the mute status and left and right attenuation from the master volume register.
    pub fn get_master_volume(&self) -> (bool, f64, f64) {
        (
            self.master_mute,
            f64::from(self.master_volume_l) * MASTER_VOLUME_STEP_DB,
            f64::from(self.master_volume_r) * MASTER_VOLUME_STEP_DB,
        )
    }

    /// Returns the front sample rate (reg 0x2c).
    pub fn get_sample_rate(&self) -> u16 {
        // MIXER_PCM_FRONT_DAC_RATE_2C, MIXER_PCM_SURR_DAC_RATE_2E, and MIXER_PCM_LFE_DAC_RATE_30
        // are updated to the same rate when playback with 2,4 and 6 tubes.
        self.pcm_front_dac_rate
    }

    // Returns the master mute and l/r volumes (reg 0x02).
    fn get_master_reg(&self) -> u16 {
        let reg = (u16::from(self.master_volume_l)) << 8 | u16::from(self.master_volume_r);
        if self.master_mute {
            reg | MUTE_REG_BIT
        } else {
            reg
        }
    }

    // Handles writes to the master register (0x02).
    fn set_master_reg(&mut self, val: u16) {
        self.master_mute = val & MUTE_REG_BIT != 0;
        self.master_volume_r = (val & VOL_REG_MASK) as u8;
        self.master_volume_l = (val >> 8 & VOL_REG_MASK) as u8;
    }

    // Returns the value read in the Mic volume register (0x0e).
    fn get_mic_volume(&self) -> u16 {
        let mut reg = u16::from(self.mic_volume);
        if self.mic_muted {
            reg |= MUTE_REG_BIT;
        }
        if self.mic_20db {
            reg |= MIXER_MIC_20DB;
        }
        reg
    }

    // Sets the mic input mute, boost, and volume settings (0x0e).
    fn set_mic_volume(&mut self, val: u16) {
        self.mic_volume = (val & MIXER_VOL_MASK) as u8;
        self.mic_muted = val & MUTE_REG_BIT != 0;
        self.mic_20db = val & MIXER_MIC_20DB != 0;
    }

    // Returns the value read in the Mic volume register (0x18).
    fn get_pcm_out_volume(&self) -> u16 {
        let reg = (self.pcm_out_vol_l << 8) | self.pcm_out_vol_r;
        if self.pcm_out_mute {
            reg | MUTE_REG_BIT
        } else {
            reg
        }
    }

    // Sets the pcm output mute and volume states (0x18).
    fn set_pcm_out_volume(&mut self, val: u16) {
        self.pcm_out_vol_r = val & MIXER_VOL_MASK;
        self.pcm_out_vol_l = (val >> MIXER_VOL_LEFT_SHIFT) & MIXER_VOL_MASK;
        self.pcm_out_mute = val & MUTE_REG_BIT != 0;
    }

    // Returns the record gain register (0x01c).
    fn get_record_gain_reg(&self) -> u16 {
        let reg = u16::from(self.record_gain_l) << 8 | u16::from(self.record_gain_r);
        if self.record_gain_mute {
            reg | MUTE_REG_BIT
        } else {
            reg
        }
    }

    // Handles writes to the record_gain register (0x1c).
    fn set_record_gain_reg(&mut self, val: u16) {
        self.record_gain_mute = val & MUTE_REG_BIT != 0;
        self.record_gain_r = (val & VOL_REG_MASK) as u8;
        self.record_gain_l = (val >> 8 & VOL_REG_MASK) as u8;
    }

    // Handles writes to the powerdown ctrl/status register (0x26).
    fn set_power_down_reg(&mut self, val: u16) {
        self.power_down_control =
            (val & !PD_REG_STATUS_MASK) | (self.power_down_control & PD_REG_STATUS_MASK);
    }
}
