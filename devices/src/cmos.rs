// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::Event;
use base::EventToken;
use base::Timer;
use base::Tube;
use base::WaitContext;
use base::WorkerThread;
use chrono::DateTime;
use chrono::Datelike;
use chrono::TimeZone;
use chrono::Timelike;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
use sync::Mutex;
use vm_control::VmResponse;

use crate::pci::CrosvmDeviceId;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::DeviceId;
use crate::IrqEdgeEvent;
use crate::Suspendable;

pub const RTC_IRQ: u8 = 8;

const INDEX_MASK: u8 = 0x7f;
const INDEX_OFFSET: u64 = 0x0;
const DATA_OFFSET: u64 = 0x1;
const DATA_LEN: usize = 128;

const RTC_REG_SEC: usize = 0x0;
const RTC_REG_ALARM_SEC: usize = 0x1;
const RTC_REG_MIN: usize = 0x2;
const RTC_REG_ALARM_MIN: usize = 0x3;
const RTC_REG_HOUR: usize = 0x4;
const RTC_REG_ALARM_HOUR: usize = 0x5;
const RTC_REG_WEEK_DAY: usize = 0x6;
const RTC_REG_DAY: usize = 0x7;
const RTC_REG_MONTH: usize = 0x8;
const RTC_REG_YEAR: usize = 0x9;
pub const RTC_REG_CENTURY: usize = 0x32;
pub const RTC_REG_ALARM_DAY: usize = 0x33;
pub const RTC_REG_ALARM_MONTH: usize = 0x34;

const RTC_REG_B: usize = 0x0b;
const RTC_REG_B_UNSUPPORTED: u8 = 0xdd;
const RTC_REG_B_24_HOUR_MODE: u8 = 0x02;
const RTC_REG_B_ALARM_ENABLE: u8 = 0x20;

const RTC_REG_C: usize = 0x0c;
const RTC_REG_C_IRQF: u8 = 0x80;
const RTC_REG_C_AF: u8 = 0x20;

pub type CmosNowFn = fn() -> DateTime<Utc>;

/// A CMOS/RTC device commonly seen on x86 I/O port 0x70/0x71.
#[derive(Serialize)]
pub struct Cmos {
    index: u8,
    #[serde(serialize_with = "serialize_arr")]
    data: [u8; DATA_LEN],
    #[serde(skip_serializing)] // skip serializing time function.
    now_fn: CmosNowFn,
    #[serde(skip_serializing)] // skip serializing the timer
    alarm: Arc<Mutex<Timer>>,
    alarm_time: Option<DateTime<Utc>>,
    #[serde(skip_serializing)] // skip serializing the alarm function
    alarm_fn: Option<AlarmFn>,
    #[serde(skip_serializing)] // skip serializing the worker thread
    worker: Option<WorkerThread<AlarmFn>>,
}

fn serialize_arr<S>(data: &[u8; DATA_LEN], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let vec = data.to_vec();
    serde::Serialize::serialize(&vec, serializer)
}

struct AlarmFn {
    irq: IrqEdgeEvent,
    vm_control: Tube,
}

impl AlarmFn {
    fn fire(&self) -> anyhow::Result<()> {
        self.irq.trigger().context("failed to trigger irq")?;

        // The Linux kernel expects wakeups to come via ACPI when ACPI is enabled. There's
        // no real way to determine that here, so just send this unconditionally.
        self.vm_control
            .send(&vm_control::VmRequest::Rtc)
            .context("send failed")?;
        match self.vm_control.recv().context("recv failed")? {
            VmResponse::Ok => Ok(()),
            resp => Err(anyhow!("unexpected rtc response: {:?}", resp)),
        }
    }
}

impl Cmos {
    /// Constructs a CMOS/RTC device with initial data.
    /// `mem_below_4g` is the size of memory in bytes below the 32-bit gap.
    /// `mem_above_4g` is the size of memory in bytes above the 32-bit gap.
    /// `now_fn` is a function that returns the current date and time.
    pub fn new(
        mem_below_4g: u64,
        mem_above_4g: u64,
        now_fn: CmosNowFn,
        vm_control: Tube,
        irq: IrqEdgeEvent,
    ) -> anyhow::Result<Cmos> {
        Self::new_inner(
            mem_below_4g,
            mem_above_4g,
            now_fn,
            Some(AlarmFn { irq, vm_control }),
        )
    }

    fn new_inner(
        mem_below_4g: u64,
        mem_above_4g: u64,
        now_fn: CmosNowFn,
        alarm_fn: Option<AlarmFn>,
    ) -> anyhow::Result<Cmos> {
        let mut data = [0u8; DATA_LEN];

        data[0x0B] = RTC_REG_B_24_HOUR_MODE; // Status Register B: 24-hour mode

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

        Ok(Cmos {
            index: 0,
            data,
            now_fn,
            alarm: Arc::new(Mutex::new(Timer::new().context("cmos timer")?)),
            alarm_time: None,
            alarm_fn,
            worker: None,
        })
    }

    fn spawn_worker(&mut self) {
        let alarm = self.alarm.clone();
        let alarm_fn = self.alarm_fn.take().expect("no alarm function");
        self.worker = Some(WorkerThread::start("CMOS_alarm", move |kill_evt| {
            if let Err(e) = run_cmos_worker(alarm, kill_evt, &alarm_fn) {
                error!("Failed to spawn worker {:?}", e);
            }
            alarm_fn
        }));
    }

    fn set_alarm(&mut self) {
        if self.data[RTC_REG_B] & RTC_REG_B_ALARM_ENABLE != 0 {
            let now = (self.now_fn)();
            let target = alarm_from_registers(now.year(), &self.data).and_then(|this_year| {
                if this_year < now {
                    alarm_from_registers(now.year() + 1, &self.data)
                } else {
                    Some(this_year)
                }
            });
            if let Some(target) = target {
                if Some(target) != self.alarm_time {
                    self.alarm_time = Some(target);

                    if self.alarm_fn.is_some() {
                        self.spawn_worker();
                    }

                    let duration = target
                        .signed_duration_since(now)
                        .to_std()
                        .unwrap_or(Duration::new(0, 0));
                    if let Err(e) = self.alarm.lock().reset(duration, None) {
                        error!("Failed to set alarm {:?}", e);
                    }
                }
            }
        } else if self.alarm_time.take().is_some() {
            if let Err(e) = self.alarm.lock().clear() {
                error!("Failed to clear alarm {:?}", e);
            }
        }
    }
}

fn run_cmos_worker(
    alarm: Arc<Mutex<Timer>>,
    kill_evt: Event,
    alarm_fn: &AlarmFn,
) -> anyhow::Result<()> {
    #[derive(EventToken)]
    enum Token {
        Alarm,
        Kill,
    }

    let wait_ctx: WaitContext<Token> =
        WaitContext::build_with(&[(&*alarm.lock(), Token::Alarm), (&kill_evt, Token::Kill)])
            .context("worker context failed")?;

    loop {
        let events = wait_ctx.wait().context("wait failed")?;
        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::Alarm => {
                    if alarm.lock().mark_waited().context("timer ack failed")? {
                        continue;
                    }
                    alarm_fn.fire()?;
                }
                Token::Kill => return Ok(()),
            }
        }
    }
}

fn from_bcd(v: u8) -> Option<u32> {
    let ones = (v & 0xf) as u32;
    let tens = (v >> 4) as u32;
    if ones < 10 && tens < 10 {
        Some(10 * tens + ones)
    } else {
        None
    }
}

fn alarm_from_registers(year: i32, data: &[u8; DATA_LEN]) -> Option<DateTime<Utc>> {
    Utc.ymd_opt(
        year,
        from_bcd(data[RTC_REG_ALARM_MONTH])?,
        from_bcd(data[RTC_REG_ALARM_DAY])?,
    )
    .and_hms_opt(
        from_bcd(data[RTC_REG_ALARM_HOUR])?,
        from_bcd(data[RTC_REG_ALARM_MIN])?,
        from_bcd(data[RTC_REG_ALARM_SEC])?,
    )
    .single()
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
            DATA_OFFSET => {
                let mut data = data[0];
                if self.index == RTC_REG_B as u8 {
                    if data & RTC_REG_B_UNSUPPORTED != 0 {
                        error!(
                            "Ignoring unsupported bits: {:x}",
                            data & RTC_REG_B_UNSUPPORTED
                        );
                        data &= !RTC_REG_B_UNSUPPORTED;
                    }
                    if data & RTC_REG_B_24_HOUR_MODE == 0 {
                        error!("12-hour mode unsupported");
                        data |= RTC_REG_B_24_HOUR_MODE;
                    }
                }

                self.data[self.index as usize] = data;

                if self.index == RTC_REG_B as u8 {
                    self.set_alarm();
                }
            }
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
                match self.index as usize {
                    RTC_REG_SEC => to_bcd(seconds as u8),
                    RTC_REG_MIN => to_bcd(minutes as u8),
                    RTC_REG_HOUR => to_bcd(hours as u8),
                    RTC_REG_WEEK_DAY => to_bcd(week_day as u8),
                    RTC_REG_DAY => to_bcd(day as u8),
                    RTC_REG_MONTH => to_bcd(month as u8),
                    RTC_REG_YEAR => to_bcd((year % 100) as u8),
                    RTC_REG_CENTURY => to_bcd((year / 100) as u8),
                    RTC_REG_C => {
                        if self
                            .alarm_time
                            .map_or(false, |alarm_time| alarm_time <= now)
                        {
                            // Reading from RTC_REG_C resets interrupts, so clear the
                            // status bits. The IrqEdgeEvent is reset automatically.
                            self.alarm_time.take();
                            RTC_REG_C_IRQF | RTC_REG_C_AF
                        } else {
                            0
                        }
                    }
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

impl Suspendable for Cmos {
    fn snapshot(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(self).context("failed to serialize Cmos")
    }

    fn restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        #[derive(Deserialize)]
        struct CmosIndex {
            index: u8,
            data: Vec<u8>,
        }

        let deser: CmosIndex =
            serde_json::from_value(data).context("failed to deserialize Cmos")?;
        self.index = deser.index;
        self.data = deser
            .data
            .try_into()
            .map_err(|_| anyhow!("invalid cmos data"))?;
        self.set_alarm();

        Ok(())
    }

    fn sleep(&mut self) -> anyhow::Result<()> {
        if let Some(worker) = self.worker.take() {
            self.alarm_fn = Some(worker.stop());
        }
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        if self.alarm_time.is_some() {
            self.spawn_worker();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;

    use super::*;

    use crate::suspendable_tests;

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

    fn write_reg(cmos: &mut Cmos, reg: u8, val: u8) {
        // Write register number to INDEX_OFFSET (0).
        cmos.write(
            BusAccessInfo {
                offset: 0,
                address: 0x70,
                id: 0,
            },
            &[reg],
        );

        // Write register value to DATA_OFFSET (1).

        let data = [val];
        cmos.write(
            BusAccessInfo {
                offset: 1,
                address: 0x71,
                id: 0,
            },
            &data,
        );
    }

    fn timestamp_to_datetime(timestamp: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), Utc)
    }

    fn test_now_party_like_its_1999() -> DateTime<Utc> {
        // 1999-12-31T23:59:59+00:00
        timestamp_to_datetime(946684799)
    }

    fn test_now_y2k_compliant() -> DateTime<Utc> {
        // 2000-01-01T00:00:00+00:00
        timestamp_to_datetime(946684800)
    }

    fn test_now_2016_before_leap_second() -> DateTime<Utc> {
        // 2016-12-31T23:59:59+00:00
        timestamp_to_datetime(1483228799)
    }

    fn test_now_2017_after_leap_second() -> DateTime<Utc> {
        // 2017-01-01T00:00:00+00:00
        timestamp_to_datetime(1483228800)
    }

    #[test]
    fn cmos_write_index() {
        let mut cmos = Cmos::new_inner(1024, 0, test_now_party_like_its_1999, None).unwrap();
        // Write index.
        cmos.write(
            BusAccessInfo {
                offset: 0,
                address: 0x71,
                id: 0,
            },
            &[0x41],
        );
        assert_eq!(cmos.index, 0x41);
    }

    #[test]
    fn cmos_write_data() {
        let mut cmos = Cmos::new_inner(1024, 0, test_now_party_like_its_1999, None).unwrap();
        // Write data 0x01 at index 0x41.
        cmos.write(
            BusAccessInfo {
                offset: 0,
                address: 0x71,
                id: 0,
            },
            &[0x41],
        );
        cmos.write(
            BusAccessInfo {
                offset: 1,
                address: 0x71,
                id: 0,
            },
            &[0x01],
        );
        assert_eq!(cmos.data[0x41], 0x01);
    }

    fn modify_device(cmos: &mut Cmos) {
        let info_index = BusAccessInfo {
            offset: 0,
            address: 0x71,
            id: 0,
        };

        let info_data = BusAccessInfo {
            offset: 1,
            address: 0x71,
            id: 0,
        };
        // change index to 0x42.
        cmos.write(info_index, &[0x42]);
        cmos.write(info_data, &[0x01]);
    }

    #[test]
    fn cmos_date_time_1999() {
        let mut cmos = Cmos::new_inner(1024, 0, test_now_party_like_its_1999, None).unwrap();
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
        let mut cmos = Cmos::new_inner(1024, 0, test_now_y2k_compliant, None).unwrap();
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
        let mut cmos = Cmos::new_inner(1024, 0, test_now_2016_before_leap_second, None).unwrap();
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
        let mut cmos = Cmos::new_inner(1024, 0, test_now_2017_after_leap_second, None).unwrap();
        assert_eq!(read_reg(&mut cmos, 0x00), 0x00); // seconds
        assert_eq!(read_reg(&mut cmos, 0x02), 0x00); // minutes
        assert_eq!(read_reg(&mut cmos, 0x04), 0x00); // hours
        assert_eq!(read_reg(&mut cmos, 0x06), 0x01); // day of week
        assert_eq!(read_reg(&mut cmos, 0x07), 0x01); // day of month
        assert_eq!(read_reg(&mut cmos, 0x08), 0x01); // month
        assert_eq!(read_reg(&mut cmos, 0x09), 0x17); // year
        assert_eq!(read_reg(&mut cmos, 0x32), 0x20); // century
    }

    #[test]
    fn cmos_alarm() {
        // 2000-01-02T03:04:05+00:00
        let now_fn = || timestamp_to_datetime(946782245);
        let mut cmos = Cmos::new_inner(1024, 0, now_fn, None).unwrap();

        // A date later this year
        write_reg(&mut cmos, 0x01, 0x06); // seconds
        write_reg(&mut cmos, 0x03, 0x05); // minutes
        write_reg(&mut cmos, 0x05, 0x04); // hours
        write_reg(&mut cmos, 0x33, 0x03); // day of month
        write_reg(&mut cmos, 0x34, 0x02); // month
        write_reg(&mut cmos, 0x0b, 0x20); // RTC_REG_B_ALARM_ENABLE
                                          // 2000-02-03T04:05:06+00:00
        assert_eq!(cmos.alarm_time, Some(timestamp_to_datetime(949550706)));

        // A date (one year - one second) in the future
        write_reg(&mut cmos, 0x01, 0x04); // seconds
        write_reg(&mut cmos, 0x03, 0x04); // minutes
        write_reg(&mut cmos, 0x05, 0x03); // hours
        write_reg(&mut cmos, 0x33, 0x02); // day of month
        write_reg(&mut cmos, 0x34, 0x01); // month
        write_reg(&mut cmos, 0x0b, 0x20); // RTC_REG_B_ALARM_ENABLE
                                          // 2001-01-02T03:04:04+00:00
        assert_eq!(cmos.alarm_time, Some(timestamp_to_datetime(978404644)));

        // The current time
        write_reg(&mut cmos, 0x01, 0x05); // seconds
        write_reg(&mut cmos, 0x03, 0x04); // minutes
        write_reg(&mut cmos, 0x05, 0x03); // hours
        write_reg(&mut cmos, 0x33, 0x02); // day of month
        write_reg(&mut cmos, 0x34, 0x01); // month
        write_reg(&mut cmos, 0x0b, 0x20); // RTC_REG_B_ALARM_ENABLE
        assert_eq!(cmos.alarm_time, Some(timestamp_to_datetime(946782245)));
        assert_eq!(read_reg(&mut cmos, 0x0c), 0xa0); // RTC_REG_C_IRQF | RTC_REG_C_AF
        assert_eq!(cmos.alarm_time, None);
        assert_eq!(read_reg(&mut cmos, 0x0c), 0);

        // Invalid BCD
        write_reg(&mut cmos, 0x01, 0xa0); // seconds
        write_reg(&mut cmos, 0x0b, 0x20); // RTC_REG_B_ALARM_ENABLE
        assert_eq!(cmos.alarm_time, None);
    }

    #[test]
    fn cmos_snapshot_restore() -> anyhow::Result<()> {
        // time function doesn't matter in this case.
        let mut cmos = Cmos::new_inner(1024, 0, test_now_party_like_its_1999, None).unwrap();

        let info_index = BusAccessInfo {
            offset: 0,
            address: 0x71,
            id: 0,
        };

        let info_data = BusAccessInfo {
            offset: 1,
            address: 0x71,
            id: 0,
        };

        // change index to 0x41.
        cmos.write(info_index, &[0x41]);
        cmos.write(info_data, &[0x01]);

        let snap = cmos.snapshot().context("failed to snapshot Cmos")?;

        // change index to 0x42.
        cmos.write(info_index, &[0x42]);
        cmos.write(info_data, &[0x01]);

        // Restore Cmos.
        cmos.restore(snap).context("failed to restore Cmos")?;

        // after restore, the index should be 0x41, which was the index before snapshot was taken.
        assert_eq!(cmos.index, 0x41);
        assert_eq!(cmos.data[0x41], 0x01);
        assert_ne!(cmos.data[0x42], 0x01);
        Ok(())
    }

    #[test]
    fn cmos_sleep_wake() {
        // 2000-01-02T03:04:05+00:00
        let now_fn = || timestamp_to_datetime(946782245);
        let alarm_fn = AlarmFn {
            irq: IrqEdgeEvent::new().unwrap(),
            vm_control: Tube::pair().unwrap().0,
        };
        let mut cmos = Cmos::new_inner(1024, 0, now_fn, Some(alarm_fn)).unwrap();

        // A date later this year
        write_reg(&mut cmos, 0x01, 0x06); // seconds
        write_reg(&mut cmos, 0x03, 0x05); // minutes
        write_reg(&mut cmos, 0x05, 0x04); // hours
        write_reg(&mut cmos, 0x33, 0x03); // day of month
        write_reg(&mut cmos, 0x34, 0x02); // month
        write_reg(&mut cmos, 0x0b, 0x20); // RTC_REG_B_ALARM_ENABLE
                                          // 2000-02-03T04:05:06+00:00
        assert_eq!(cmos.alarm_time, Some(timestamp_to_datetime(949550706)));
        assert!(cmos.worker.is_some());

        cmos.sleep().unwrap();
        assert!(cmos.worker.is_none());

        cmos.wake().unwrap();
        assert!(cmos.worker.is_some());
    }

    suspendable_tests!(
        cmos1999,
        Cmos::new_inner(1024, 0, test_now_party_like_its_1999, None).unwrap(),
        modify_device
    );
    suspendable_tests!(
        cmos2k,
        Cmos::new_inner(1024, 0, test_now_y2k_compliant, None).unwrap(),
        modify_device
    );
    suspendable_tests!(
        cmos2016,
        Cmos::new_inner(1024, 0, test_now_2016_before_leap_second, None).unwrap(),
        modify_device
    );
    suspendable_tests!(
        cmos2017,
        Cmos::new_inner(1024, 0, test_now_2017_after_leap_second, None).unwrap(),
        modify_device
    );
}
