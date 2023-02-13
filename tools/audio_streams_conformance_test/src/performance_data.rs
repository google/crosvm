// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::time::Duration;

use num::integer::Roots;
use serde::Serialize;

use crate::args::Args;
use crate::error::*;

const NANOS_PER_MICROS: f32 = 1_000_000.0;

/// `PerformanceReport` is the estimated buffer consumption rate and error term
/// derived by the linear regression of `BufferConsumptionRecord`.
#[derive(Debug, Serialize)]
pub struct PerformanceReport {
    args: Args,
    cold_start_latency: Duration,
    record_count: usize,
    rate: EstimatedRate,
    /// {min, max, avg, stddev}_time for per "next_buffer + zero write + commit" call
    min_time: Duration,
    max_time: Duration,
    avg_time: Duration,
    stddev_time: Duration,
    /// How many times that consumed frames are different from buffer_frames.
    mismatched_frame_count: u32,
}

impl fmt::Display for PerformanceReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.mismatched_frame_count != 0 {
            eprint!(
                "[Error] {} consumed buffers size != {} frames",
                self.mismatched_frame_count, self.args.buffer_frames
            );
        }
        write!(
            f,
            r#"{}
Cold start latency: {:?}
Records count: {}
[Step] min: {:.2} ms, max: {:.2} ms, average: {:.2} ms, standard deviation: {:.2} ms.
{}
"#,
            self.args,
            self.cold_start_latency,
            self.record_count,
            to_micros(self.min_time),
            to_micros(self.max_time),
            to_micros(self.avg_time),
            to_micros(self.stddev_time),
            self.rate,
        )
    }
}

/// `BufferConsumptionRecord` records the timestamp and the
/// accumulated number of consumed frames at every stream buffer commit.
/// It is used to compute the buffer consumption rate.
#[derive(Debug, Default)]
pub struct BufferConsumptionRecord {
    pub ts: Duration,
    pub frames: usize,
}

impl BufferConsumptionRecord {
    pub fn new(frames: usize, ts: Duration) -> Self {
        Self { ts, frames }
    }
}

#[derive(Debug, Serialize, PartialEq)]
pub struct EstimatedRate {
    /// linear coefficients of LINEST(frames,timestamps).
    rate: f64,
    /// STEYX(frames, timestamps).
    error: f64,
}

impl EstimatedRate {
    fn new(rate: f64, error: f64) -> Self {
        Self { rate, error }
    }
}

impl fmt::Display for EstimatedRate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[Linear Regression] rate: {:.2} frames/s, standard error: {:.2} ",
            self.rate, self.error
        )
    }
}

#[derive(Debug, Default)]
pub struct PerformanceData {
    pub cold_start: Duration,
    pub records: Vec<BufferConsumptionRecord>,
}

fn to_micros(t: Duration) -> f32 {
    t.as_nanos() as f32 / NANOS_PER_MICROS
}

fn linear_regression(x: &[f64], y: &[f64]) -> Result<EstimatedRate> {
    if x.len() != y.len() {
        return Err(Error::MismatchedSamples);
    }

    if x.len() <= 2 {
        return Err(Error::NotEnoughSamples);
    }

    /* hat(y_i) = b(x_i) + a */
    let x_sum: f64 = x.iter().sum();
    let x_average = x_sum / x.len() as f64;
    // sum(x_i * x_i)
    let x_square_sum: f64 = x.iter().map(|&xi| xi * xi).sum();
    // sum(x_i * y_i)
    let x_y_sum: f64 = x.iter().zip(y.iter()).map(|(&xi, &yi)| xi * yi).sum();

    let y_sum: f64 = y.iter().sum();

    let y_square_sum: f64 = y.iter().map(|yi| yi * yi).sum();
    /* b = (n * sum(x * y) - sum(x) * sum(y)) / (n * sum(x ^ 2) - sum(x) ^ 2)
    = (sum(x * y) - avg(x) * sum(y)) / (sum(x ^ 2) - avg(x) * sum(x)) */
    let b = (x_y_sum - x_average * y_sum) / (x_square_sum - x_average * x_sum);
    let n = y.len() as f64;
    /* err = sqrt(sum((y_i - hat(y_i)) ^ 2) / n) */
    let err: f64 = ((n * y_square_sum - y_sum * y_sum - b * b * (n * x_square_sum - x_sum * x_sum))
        as f64
        / (n * (n - 2.0)))
        .sqrt();

    Ok(EstimatedRate::new(b, err))
}

impl PerformanceData {
    pub fn print_records(&self) {
        println!("TS\t\tTS_DIFF\t\tPLAYED");
        let mut previous_ts = 0.0;
        for record in &self.records {
            println!(
                "{:.6}\t{:.6}\t{}",
                record.ts.as_secs_f64(),
                record.ts.as_secs_f64() - previous_ts,
                record.frames
            );
            previous_ts = record.ts.as_secs_f64();
        }
    }
    pub fn gen_report(&self, args: Args) -> Result<PerformanceReport> {
        let time_records: Vec<f64> = self
            .records
            .iter()
            .map(|record| record.ts.as_secs_f64())
            .collect();

        let frames: Vec<f64> = self
            .records
            .iter()
            .map(|record| record.frames as f64)
            .collect();

        let mut steps = Vec::new();
        let mut mismatched_frame_count = 0;
        for i in 1..frames.len() {
            let time_diff = self.records[i].ts - self.records[i - 1].ts;
            steps.push(time_diff);

            let frame_diff = self.records[i].frames - self.records[i - 1].frames;
            if frame_diff != args.buffer_frames {
                mismatched_frame_count += 1;
            }
        }
        let avg_time = steps
            .iter()
            .sum::<Duration>()
            .checked_div(steps.len() as u32)
            .ok_or(Error::NotEnoughSamples)?;
        let stddev_time = (steps
            .iter()
            .map(|x| {
                x.as_nanos().abs_diff(avg_time.as_nanos())
                    * x.as_nanos().abs_diff(avg_time.as_nanos())
            })
            .sum::<u128>()
            / steps.len() as u128)
            .sqrt();

        let rate = linear_regression(&time_records, &frames)?;
        let min_time = steps.iter().min().unwrap().to_owned();
        let max_time = steps.iter().max().unwrap().to_owned();

        Ok(PerformanceReport {
            args,
            cold_start_latency: self.cold_start,
            record_count: self.records.len(),
            rate,
            min_time,
            max_time,
            avg_time,
            stddev_time: Duration::from_nanos(stddev_time as u64),
            mismatched_frame_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test1() {
        let xs: Vec<f64> = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let ys: Vec<f64> = vec![1.0, 2.0, 3.0, 4.0, 5.0];

        assert_eq!(
            EstimatedRate::new(1.0, 0.0),
            linear_regression(&xs, &ys).expect("test1 should pass")
        );
    }

    #[test]
    fn test2() {
        let xs: Vec<f64> = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let ys: Vec<f64> = vec![2.0, 4.0, 5.0, 4.0, 5.0];

        assert_eq!(
            EstimatedRate::new(0.6, 0.8944271909999159),
            linear_regression(&xs, &ys).expect("test2 should pass")
        );
    }
}
