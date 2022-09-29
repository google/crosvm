// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;

use chrono::DateTime;
use chrono::Datelike;
use chrono::Timelike;
use chrono::Utc;

use crate::pci::CrosvmDeviceId;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::DeviceId;
use crate::Suspendable;

const INDEX_MASK: u8 = 0x7f;
const INDEX_OFFSET: u64 = 0x0;
const DATA_OFFSET: u64 = 0x1;
const DATA_LEN: usize = 128;

pub type CmosNowFn = fn() -> DateTime<Utc>;

/// A CMOS/RTC device commonly seen on x86 I/O port 0x70/0x71.
pub struct Cmos {
    index: u8,
    data: [u8; DATA_LEN],
    now_fn: CmosNowFn,
}

impl Cmos {
    /// Constructs a CMOS/RTC device with initial data.
    /// `mem_below_4g` is the size of memory in bytes below the 32-bit gap.
    /// `mem_above_4g` is the size of memory in bytes above the 32-bit gap.
    /// `now_fn` is a function that returns the current date and time.
    pub fn new(mem_below_4g: u64, mem_above_4g: u64, now_fn: CmosNowFn) -> Cmos {
        let mut data = [0u8; DATA_LEN];

        data[0x0B] = 0x02; // Status Register B: 24-hour mode

        // Extended memory from 16 MB to 4 GB in units of 64 KB
        let ext_mem = min(
            0xFFFF,
            mem_below_4g.saturating_sub(16 * 1024 * 1024) / (64 * 1024),
        );
        data[0x34] = ext_mem as u8;
        data[0x35] = (ext_mem >> 8) as u8;

        // High memory (> 4GB) in units of 64 KB
        let high_mem = min(0xFFFFFF, mem_above_4g / (64 * 1024));
        data[0x5b] = high_mem as u8;
        data[0x5c] = (high_mem >> 8) as u8;
        data[0x5d] = (high_mem >> 16) as u8;

        Cmos {
            index: 0,
            data,
            now_fn,
        }
    }
}

impl BusDevice for Cmos {
    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::Cmos.into()
    }

    fn debug_label(&self) -> String {
        "cmos".to_owned()
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        if data.len() != 1 {
            return;
        }

        match info.offset {
            INDEX_OFFSET => self.index = data[0] & INDEX_MASK,
            DATA_OFFSET => self.data[self.index as usize] = data[0],
            o => panic!("bad write offset on CMOS device: {}", o),
        }
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        fn to_bcd(v: u8) -> u8 {
            assert!(v < 100);
            ((v / 10) << 4) | (v % 10)
        }

        if data.len() != 1 {
            return;
        }

        data[0] = match info.offset {
            INDEX_OFFSET => self.index,
            DATA_OFFSET => {
                let now = (self.now_fn)();
                let seconds = now.second(); // 0..=59
                let minutes = now.minute(); // 0..=59
                let hours = now.hour(); // 0..=23 (24-hour mode only)
                let week_day = now.weekday().number_from_sunday(); // 1 (Sun) ..= 7 (Sat)
                let day = now.day(); // 1..=31
                let month = now.month(); // 1..=12
                let year = now.year();
                match self.index {
                    0x00 => to_bcd(seconds as u8),
                    0x02 => to_bcd(minutes as u8),
                    0x04 => to_bcd(hours as u8),
                    0x06 => to_bcd(week_day as u8),
                    0x07 => to_bcd(day as u8),
                    0x08 => to_bcd(month as u8),
                    0x09 => to_bcd((year % 100) as u8),
                    0x32 => to_bcd((year / 100) as u8),
                    _ => {
                        // self.index is always guaranteed to be in range via INDEX_MASK.
                        self.data[(self.index & INDEX_MASK) as usize]
                    }
                }
            }
            o => panic!("bad read offset on CMOS device: {}", o),
        }
    }
}

impl Suspendable for Cmos {}

#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;

    use super::*;

    fn read_reg(cmos: &mut Cmos, reg: u8) -> u8 {
        // Write register number to INDEX_OFFSET (0).
        cmos.write(
            BusAccessInfo {
                offset: 0,
                address: 0x70,
                id: 0,
            },
            &[reg],
        );

        // Read register value back from DATA_OFFSET (1).
        let mut data = [0u8];
        cmos.read(
            BusAccessInfo {
                offset: 1,
                address: 0x71,
                id: 0,
            },
            &mut data,
        );
        data[0]
    }

    fn test_now_party_like_its_1999() -> DateTime<Utc> {
        // 1999-12-31T23:59:59+00:00
        DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(946684799, 0), Utc)
    }

    fn test_now_y2k_compliant() -> DateTime<Utc> {
        // 2000-01-01T00:00:00+00:00
        DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(946684800, 0), Utc)
    }

    fn test_now_2016_before_leap_second() -> DateTime<Utc> {
        // 2016-12-31T23:59:59+00:00
        DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(1483228799, 0), Utc)
    }

    fn test_now_2017_after_leap_second() -> DateTime<Utc> {
        // 2017-01-01T00:00:00+00:00
        DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(1483228800, 0), Utc)
    }

    #[test]
    fn cmos_date_time_1999() {
        let mut cmos = Cmos::new(1024, 0, test_now_party_like_its_1999);
        assert_eq!(read_reg(&mut cmos, 0x00), 0x59); // seconds
        assert_eq!(read_reg(&mut cmos, 0x02), 0x59); // minutes
        assert_eq!(read_reg(&mut cmos, 0x04), 0x23); // hours
        assert_eq!(read_reg(&mut cmos, 0x06), 0x06); // day of week
        assert_eq!(read_reg(&mut cmos, 0x07), 0x31); // day of month
        assert_eq!(read_reg(&mut cmos, 0x08), 0x12); // month
        assert_eq!(read_reg(&mut cmos, 0x09), 0x99); // year
        assert_eq!(read_reg(&mut cmos, 0x32), 0x19); // century
    }

    #[test]
    fn cmos_date_time_2000() {
        let mut cmos = Cmos::new(1024, 0, test_now_y2k_compliant);
        assert_eq!(read_reg(&mut cmos, 0x00), 0x00); // seconds
        assert_eq!(read_reg(&mut cmos, 0x02), 0x00); // minutes
        assert_eq!(read_reg(&mut cmos, 0x04), 0x00); // hours
        assert_eq!(read_reg(&mut cmos, 0x06), 0x07); // day of week
        assert_eq!(read_reg(&mut cmos, 0x07), 0x01); // day of month
        assert_eq!(read_reg(&mut cmos, 0x08), 0x01); // month
        assert_eq!(read_reg(&mut cmos, 0x09), 0x00); // year
        assert_eq!(read_reg(&mut cmos, 0x32), 0x20); // century
    }

    #[test]
    fn cmos_date_time_before_leap_second() {
        let mut cmos = Cmos::new(1024, 0, test_now_2016_before_leap_second);
        assert_eq!(read_reg(&mut cmos, 0x00), 0x59); // seconds
        assert_eq!(read_reg(&mut cmos, 0x02), 0x59); // minutes
        assert_eq!(read_reg(&mut cmos, 0x04), 0x23); // hours
        assert_eq!(read_reg(&mut cmos, 0x06), 0x07); // day of week
        assert_eq!(read_reg(&mut cmos, 0x07), 0x31); // day of month
        assert_eq!(read_reg(&mut cmos, 0x08), 0x12); // month
        assert_eq!(read_reg(&mut cmos, 0x09), 0x16); // year
        assert_eq!(read_reg(&mut cmos, 0x32), 0x20); // century
    }

    #[test]
    fn cmos_date_time_after_leap_second() {
        let mut cmos = Cmos::new(1024, 0, test_now_2017_after_leap_second);
        assert_eq!(read_reg(&mut cmos, 0x00), 0x00); // seconds
        assert_eq!(read_reg(&mut cmos, 0x02), 0x00); // minutes
        assert_eq!(read_reg(&mut cmos, 0x04), 0x00); // hours
        assert_eq!(read_reg(&mut cmos, 0x06), 0x01); // day of week
        assert_eq!(read_reg(&mut cmos, 0x07), 0x01); // day of month
        assert_eq!(read_reg(&mut cmos, 0x08), 0x01); // month
        assert_eq!(read_reg(&mut cmos, 0x09), 0x17); // year
        assert_eq!(read_reg(&mut cmos, 0x32), 0x20); // century
    }
}
