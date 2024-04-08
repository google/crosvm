// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module contains stats that useful on the system. Local stats may not a be in
//! state to be consumed by metris reporter or it might not be efficient to report
//! metrics in the current state to the backend.

use std::fmt;
use std::fmt::Debug;
use std::ops::Add;
use std::ops::Div;
use std::ops::Range;
use std::ops::Sub;
use std::sync::Arc;
use std::time::Instant;

use anyhow::anyhow;
use anyhow::Result;
use base::info;
use sync::Mutex;

pub trait Limits {
    fn absolute_min() -> Self;
    fn absolute_max() -> Self;
}

impl Limits for u64 {
    fn absolute_min() -> Self {
        u64::MIN
    }

    fn absolute_max() -> Self {
        u64::MAX
    }
}

// Aggregate information about a collection that does require large memory footprint.
pub trait SummaryStats<T> {
    /// Count of data points that tracked.
    fn count(&self) -> u64;

    /// Sum of all data points.
    /// Returns None if count is zero.
    fn sum(&self) -> Option<T>;

    /// Minimum value of data points.
    /// Returns None if count is zero.
    fn min(&self) -> Option<T>;

    /// Maximum value of data points.
    /// Returns None if count is zero.
    fn max(&self) -> Option<T>;

    /// Average value of data points.
    /// Returns None if count is zero.
    fn average(&self) -> Option<T>;
}

pub trait NumberType:
    Limits + Div<u64, Output = Self> + Add<Output = Self> + Clone + Ord + PartialOrd + Debug + Sub<Self>
{
    fn as_f64(&self) -> f64;
}

impl NumberType for u64 {
    fn as_f64(&self) -> f64 {
        *self as f64
    }
}

/// Light weight stat struct that helps you get aggregate stats like min, max, average, count and
/// sum.
/// Median and standard deviation are intentionally excluded to keep the structure light weight.
#[derive(Eq, PartialEq)]
pub struct SimpleStat<T: NumberType> {
    count: u64,
    sum: T,
    min: T,
    max: T,
}

/// A helper trait that can be associated with information that is tracked with a histogram.
/// For example, if histogram is tracking latencies and for debugging reasons, if we want to track
/// size of IO along with latency, this trait makes that posssible.
pub trait Details<T: NumberType>: Debug {
    /// Returns a value that is being traked by the histogram.
    fn value(&self) -> T;
}

impl<T: NumberType> Details<T> for T {
    fn value(&self) -> T {
        self.clone()
    }
}

impl Details<u64> for Range<u64> {
    fn value(&self) -> u64 {
        self.end - self.start
    }
}

impl<T: NumberType> Debug for SimpleStat<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.count == 0 {
            f.debug_struct("SimpleStat")
                .field("count", &self.count)
                .finish()
        } else {
            f.debug_struct("SimpleStat")
                .field("count", &self.count)
                .field("sum", &self.sum)
                .field("min", &self.min)
                .field("max", &self.max)
                .field("average", &self.average().unwrap())
                .finish()
        }
    }
}

impl<T: NumberType> SimpleStat<T> {
    pub fn add(&mut self, value: T) {
        self.count += 1;
        self.sum = self.sum.clone() + value.clone();
        if self.max < value {
            self.max = value.clone();
        }
        if self.min > value {
            self.min = value;
        }
    }
}

impl<T: NumberType> Default for SimpleStat<T> {
    fn default() -> Self {
        Self {
            count: 0,
            sum: T::absolute_min(),
            min: T::absolute_max(),
            max: T::absolute_min(),
        }
    }
}

impl<T: NumberType> SummaryStats<T> for SimpleStat<T> {
    fn count(&self) -> u64 {
        self.count
    }

    fn sum(&self) -> Option<T> {
        if self.count == 0 {
            return None;
        }
        Some(self.sum.clone())
    }

    fn min(&self) -> Option<T> {
        if self.count == 0 {
            return None;
        }
        Some(self.min.clone())
    }

    fn max(&self) -> Option<T> {
        if self.count == 0 {
            return None;
        }
        Some(self.max.clone())
    }

    fn average(&self) -> Option<T> {
        if self.count == 0 {
            return None;
        }
        Some(self.sum.clone() / self.count)
    }
}

/// Computes and returns median of `values`.
/// This is an expensive function as it sorts values to get the median.
fn median<T: NumberType, D: Details<T>>(values: &[D]) -> T {
    let mut sorted: Vec<T> = values.iter().map(|v| v.value()).collect();
    sorted.sort();
    sorted.get(sorted.len() / 2).unwrap().clone()
}

/// Computes and returns standard deviation of `values`.
fn stddev<T: NumberType, D: Details<T>>(values: &[D], simple_stat: &SimpleStat<T>) -> f64 {
    let avg = simple_stat.sum().unwrap().as_f64() / simple_stat.count() as f64;
    (values
        .iter()
        .map(|value| {
            let diff = avg - (value.value().as_f64());
            diff * diff
        })
        .sum::<f64>()
        / simple_stat.count as f64)
        .sqrt()
}

/// Buckets of an histogram.
#[derive(Debug)]
struct Bucket<T: NumberType> {
    simple_stat: SimpleStat<T>,
    range: Range<T>,
}

impl<T: NumberType> Bucket<T> {
    fn new(range: Range<T>) -> Self {
        Self {
            simple_stat: SimpleStat::default(),
            range,
        }
    }

    fn add(&mut self, value: T) {
        self.simple_stat.add(value);
    }
}

/// A histogram that optionally holds details about each added value. These values let
/// us compute standard deviation and median.
pub struct DetailedHistogram<T: NumberType, D: Details<T>> {
    buckets: Vec<Bucket<T>>,
    values: Option<Vec<D>>,
}

impl<T: NumberType, D: Details<T>> Debug for DetailedHistogram<T, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("DetailedHistogram");
        let simple_stat = self.simple_stat();
        dbg.field("simple_stats", &simple_stat);
        if simple_stat.count > 0 {
            if let Some(values) = &self.values {
                dbg.field("median", &median(values));
                dbg.field("std_dev", &stddev(values, &simple_stat));
                dbg.field("values", values);
            }
        }
        dbg.field("buckets", &self.buckets);
        dbg.finish()
    }
}

impl<T: NumberType, D: Details<T>> DetailedHistogram<T, D> {
    fn new_internal(ranges: &[Range<T>], details: bool) -> Result<Self> {
        let mut last = T::absolute_min();
        let mut buckets = vec![];
        for r in ranges {
            if r.start > r.end {
                return Err(anyhow!("invalid range {:?}", r));
            }

            if r.start < last {
                return Err(anyhow!("Ranges overlap {:?} ", r));
            }
            last = r.end.clone();
            buckets.push(Bucket::new(r.clone()));
        }
        let values = if details { Some(vec![]) } else { None };

        Ok(Self { buckets, values })
    }

    /// Creates an histogram with given ranges of buckets.
    pub fn new(ranges: &[Range<T>]) -> Result<Self> {
        Self::new_internal(ranges, false)
    }

    /// Creating a histogram that maintains details about all the events can
    /// get expensive if the events are frequent. Hence this feature is for
    /// debug builds only.
    #[cfg(feature = "experimental")]
    pub fn new_with_details(ranges: &[Range<T>]) -> Result<Self> {
        Self::new_internal(ranges, true)
    }

    /// Adds a value to histogram.
    pub fn add(&mut self, value: D) -> Result<()> {
        for b in &mut self.buckets {
            if value.value() >= b.range.start && value.value() < b.range.end {
                b.add(value.value());
                if let Some(values) = &mut self.values {
                    values.push(value);
                }
                return Ok(());
            }
        }
        Err(anyhow!(
            "value does not fit in any buckets: {:?}",
            value.value()
        ))
    }

    /// Returns simple stat for the histogram.
    pub fn simple_stat(&self) -> SimpleStat<T> {
        let count = self.count();
        if count == 0 {
            SimpleStat::default()
        } else {
            SimpleStat {
                count: self.count(),
                sum: self.sum().unwrap(),
                min: self.min().unwrap(),
                max: self.max().unwrap(),
            }
        }
    }
}

impl<T: NumberType, D: Details<T>> SummaryStats<T> for DetailedHistogram<T, D> {
    fn count(&self) -> u64 {
        let mut count = 0;
        for b in &self.buckets {
            count += b.simple_stat.count();
        }
        count
    }

    fn sum(&self) -> Option<T> {
        let mut sum = T::absolute_min();
        let mut ret = None;
        for b in &self.buckets {
            if let Some(v) = b.simple_stat.sum() {
                sum = sum.clone() + v;
                ret = Some(sum.clone())
            }
        }
        ret
    }

    fn min(&self) -> Option<T> {
        for b in &self.buckets {
            let min = b.simple_stat.min();
            if min.is_some() {
                return min;
            }
        }
        None
    }

    fn max(&self) -> Option<T> {
        for b in self.buckets.iter().rev() {
            let max = b.simple_stat.max();
            if max.is_some() {
                return max;
            }
        }
        None
    }

    fn average(&self) -> Option<T> {
        let mut count = 0;
        let mut sum = T::absolute_min();
        for b in &self.buckets {
            if b.simple_stat.count != 0 {
                sum = sum + b.simple_stat.sum().unwrap();
                count += b.simple_stat.count();
            }
        }
        if count != 0 {
            Some(sum / count)
        } else {
            None
        }
    }
}

/// A helper type alias for Histogram that doesn't store details.
/// The structure can be used in production without much memory penalty.
pub type Histogram<T> = DetailedHistogram<T, T>;

/// A helper struct that makes it easy to get time spent in a scope.
pub struct CallOnDrop<V, F: ?Sized + Fn(&V)> {
    init_value: V,
    update_value: F,
}

impl<V, F: Fn(&V)> CallOnDrop<V, F> {
    pub fn new(init_value: V, update_value: F) -> Self {
        Self {
            init_value,
            update_value,
        }
    }
}

impl<V, F: ?Sized + Fn(&V)> Drop for CallOnDrop<V, F> {
    fn drop(&mut self) {
        let f = &(self.update_value);
        f(&self.init_value);
    }
}

pub fn timed_scope(
    histogram: Arc<Mutex<DetailedHistogram<u64, u64>>>,
) -> CallOnDrop<
    (Arc<Mutex<DetailedHistogram<u64, u64>>>, Instant),
    fn(&(Arc<Mutex<DetailedHistogram<u64, u64>>>, Instant)),
> {
    CallOnDrop::new((histogram, Instant::now()), |(histogram, x)| {
        if histogram.lock().add(x.elapsed().as_nanos() as u64).is_err() {
            info!("Error adding timed scope stat");
        }
    })
}

/// A helper struct to collect metrics for byte transferred and latency.
#[derive(Debug)]
pub struct BytesLatencyStats {
    /// Collects latency related metrics. The unit, u64, is large enough to hold nano-second
    /// granularity.
    pub latency: DetailedHistogram<u64, u64>,
    /// Collects bytes transferred metrics. The unit, u64, is large enough to hold byte level
    /// offset and length.
    pub bytes_transferred: DetailedHistogram<u64, Range<u64>>,
}

impl BytesLatencyStats {
    pub fn new_with_buckets(latency_buckets: &[Range<u64>], bytes_buckets: &[Range<u64>]) -> Self {
        Self {
            latency: DetailedHistogram::new(latency_buckets).unwrap(),
            bytes_transferred: DetailedHistogram::new(bytes_buckets).unwrap(),
        }
    }
}

pub trait GetStatsForOp<OperationType> {
    fn get_stats_for_op(&mut self, op: OperationType) -> &mut BytesLatencyStats;
}

/// A generic struct that temporarily holds reference of a `Stats` to update details for an
/// operation of type `OperationType` when the instance of `OpInfo` is dropped.
#[cfg(any(test, feature = "collect"))]
pub struct OpInfo<Stats, OperationType> {
    stats: Arc<Mutex<Stats>>,
    io_range: Range<u64>,
    operation: OperationType,
    start_time: Instant,
}

/// Helper routine to collect byte latency stat.
///
/// The mutex protecting `Stats` is not held across operation but is only held to
/// update the stats atomically. The order of events is
///   # get `start_time`
///   # caller performs the operation like read(), write(), etc.
///   # hold the stats lock
///   # update the stats
///   # drop the lock
#[cfg(any(test, feature = "collect"))]
pub fn collect_scoped_byte_latency_stat<
    Stats: GetStatsForOp<OperationType> + Debug,
    OperationType: Copy + Clone + Debug,
>(
    stats: Arc<Mutex<Stats>>,
    io_range: Range<u64>,
    operation: OperationType,
) -> CallOnDrop<OpInfo<Stats, OperationType>, fn(&OpInfo<Stats, OperationType>)> {
    let info = OpInfo {
        stats,
        io_range,
        operation,
        start_time: Instant::now(),
    };
    CallOnDrop::new(info, |info| {
        let mut stats = info.stats.lock();
        let op_stats = stats.get_stats_for_op(info.operation);

        if op_stats
            .latency
            .add(info.start_time.elapsed().as_nanos() as u64)
            .is_err()
        {
            info!("Error adding disk IO latency stat");
        }

        if op_stats
            .bytes_transferred
            .add(info.io_range.clone())
            .is_err()
        {
            info!("Error adding disk IO bytes transferred stat");
        }
    })
}

#[cfg(all(not(test), not(feature = "collect")))]
pub struct OpInfo {}

#[cfg(all(not(test), not(feature = "collect")))]
pub fn collect_scoped_byte_latency_stat<
    Stats: GetStatsForOp<OperationType> + Debug,
    OperationType: Copy + Clone + Debug,
>(
    _stats: Arc<Mutex<Stats>>,
    _io_range: Range<u64>,
    _operation: OperationType,
) -> OpInfo {
    OpInfo {}
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use super::*;

    #[test]
    fn simple_stat_init() {
        let x = SimpleStat::<u64>::default();
        assert_eq!(x.count, 0);
        assert_eq!(x.max(), None);
        assert_eq!(x.min(), None);
        assert_eq!(x.average(), None);
        assert_eq!(x.sum(), None);
    }

    #[test]
    fn simple_stat_updates() {
        let mut x = SimpleStat::<u64>::default();
        x.add(10);
        assert_eq!(x.count, 1);
        assert_eq!(x.max(), Some(10));
        assert_eq!(x.min(), Some(10));
        assert_eq!(x.average(), Some(10));
        assert_eq!(x.sum(), Some(10));
        x.add(2);
        assert_eq!(x.count, 2);
        assert_eq!(x.max(), Some(10));
        assert_eq!(x.min(), Some(2));
        assert_eq!(x.average(), Some(6));
        assert_eq!(x.sum(), Some(12));
        x.add(1);
        assert_eq!(x.count, 3);
        assert_eq!(x.max(), Some(10));
        assert_eq!(x.min(), Some(1));
        assert_eq!(x.average(), Some(4));
        assert_eq!(x.sum(), Some(13));
        x.add(0);
        assert_eq!(x.count, 4);
        assert_eq!(x.max(), Some(10));
        assert_eq!(x.min(), Some(0));
        assert_eq!(x.average(), Some(3));
        assert_eq!(x.sum(), Some(13));
    }

    fn bucket_check(bucket: &Bucket<u64>, values: &[u64]) {
        let mut stats = SimpleStat::default();
        for v in values {
            stats.add(*v);
        }
        assert_eq!(bucket.simple_stat.count(), stats.count());
        assert_eq!(bucket.simple_stat.sum(), stats.sum());
        assert_eq!(bucket.simple_stat.min(), stats.min());
        assert_eq!(bucket.simple_stat.max(), stats.max());
        assert_eq!(bucket.simple_stat.average(), stats.average());
    }

    #[test]
    fn histogram_without_details() {
        let mut histogram = Histogram::new(&[0..10, 10..100, 100..200]).unwrap();

        let mut simple_stats = SimpleStat::default();
        assert_eq!(histogram.simple_stat(), simple_stats);
        let values = [0, 20, 199, 50, 9, 5, 120];

        for v in values {
            histogram.add(v).unwrap();
            simple_stats.add(v);
        }

        bucket_check(&histogram.buckets[0], &[0, 9, 5]);
        bucket_check(&histogram.buckets[1], &[20, 50]);
        bucket_check(&histogram.buckets[2], &[199, 120]);
        assert_eq!(histogram.buckets.len(), 3);
        assert_eq!(histogram.simple_stat(), simple_stats);
        assert_eq!(histogram.values, None);
    }

    #[test]
    fn histogram_without_details_empty_first_last_buckets() {
        let mut histogram = Histogram::new(&[0..4, 4..10, 10..100, 100..200, 200..300]).unwrap();

        let mut simple_stats = SimpleStat::default();
        assert_eq!(histogram.simple_stat(), simple_stats);
        let values = [4, 20, 199, 50, 9, 5, 120];

        for v in values {
            histogram.add(v).unwrap();
            simple_stats.add(v);
        }

        bucket_check(&histogram.buckets[1], &[4, 9, 5]);
        bucket_check(&histogram.buckets[2], &[20, 50]);
        bucket_check(&histogram.buckets[3], &[199, 120]);
        assert_eq!(histogram.buckets.len(), 5);
        assert_eq!(histogram.simple_stat(), simple_stats);
        assert_eq!(histogram.values, None);
    }

    #[derive(Clone, Debug, PartialEq)]
    struct MyDetails(u64, u64);
    impl Details<u64> for MyDetails {
        fn value(&self) -> u64 {
            self.1 - self.0
        }
    }

    #[cfg(feature = "experimental")]
    fn test_detailed_values() -> Vec<MyDetails> {
        vec![
            MyDetails(0, 4),
            MyDetails(1, 21),
            MyDetails(2, 201),
            MyDetails(3, 53),
            MyDetails(10, 19),
            MyDetails(5, 10),
            MyDetails(120, 240),
        ]
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn histogram_with_details() {
        let mut histogram =
            DetailedHistogram::new_with_details(&[0..10, 10..100, 100..200]).unwrap();

        let mut simple_stats = SimpleStat::default();
        assert_eq!(histogram.simple_stat(), simple_stats);

        let values = test_detailed_values();

        for v in &values {
            simple_stats.add(v.value());
            histogram.add(v.clone()).unwrap();
        }

        bucket_check(histogram.buckets[0], &[4, 9, 5]);
        bucket_check(histogram.buckets[1], &[20, 50]);
        bucket_check(histogram.buckets[2], &[199, 120]);
        assert_eq!(histogram.buckets.len(), 3);
        assert_eq!(histogram.simple_stat(), simple_stats);
        assert_eq!(histogram.values, Some(values));
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn histogram_with_details_empty_first_last_buckets() {
        let mut histogram =
            DetailedHistogram::new_with_details(&[0..4, 4..10, 10..100, 100..200, 200..300])
                .unwrap();

        let mut simple_stats = SimpleStat::default();
        assert_eq!(histogram.simple_stat(), simple_stats);
        let values = test_detailed_values();

        for v in &values {
            simple_stats.add(v.value());
            histogram.add(v.clone()).unwrap();
        }

        bucket_check(histogram.buckets[0], &[]);
        bucket_check(histogram.buckets[4], &[]);
        bucket_check(histogram.buckets[1], &[4, 9, 5]);
        bucket_check(histogram.buckets[2], &[20, 50]);
        bucket_check(histogram.buckets[3], &[199, 120]);
        assert_eq!(histogram.buckets.len(), 5);
        assert_eq!(histogram.simple_stat(), simple_stats);
        assert_eq!(histogram.values, Some(values));
    }

    #[test]
    fn histogram_debug_fmt() {
        let range = 0..200;
        let mut histogram = Histogram::new(&[range]).unwrap();

        let mut simple_stats = SimpleStat::default();
        assert_eq!(histogram.simple_stat(), simple_stats);
        let values = [0, 20, 199];

        for v in values {
            histogram.add(v).unwrap();
            simple_stats.add(v);
        }
        assert_eq!(
            format!("{:#?}", histogram),
            r#"DetailedHistogram {
    simple_stats: SimpleStat {
        count: 3,
        sum: 219,
        min: 0,
        max: 199,
        average: 73,
    },
    buckets: [
        Bucket {
            simple_stat: SimpleStat {
                count: 3,
                sum: 219,
                min: 0,
                max: 199,
                average: 73,
            },
            range: 0..200,
        },
    ],
}"#
        );
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn detailed_histogram_debug_fmt() {
        let mut histogram = DetailedHistogram::new_with_details(&[0..200]).unwrap();

        let mut simple_stats = SimpleStat::default();
        assert_eq!(histogram.simple_stat(), simple_stats);
        let values = test_detailed_values();

        for v in &values {
            histogram.add(v.clone()).unwrap();
            simple_stats.add(v.value());
        }
        assert_eq!(
            format!("{:#?}", histogram),
            r#"DetailedHistogram {
    simple_stats: SimpleStat {
        count: 7,
        sum: 407,
        min: 4,
        max: 199,
        average: 58,
    },
    median: 20,
    std_dev: 69.03297053153779,
    values: [
        MyDetails(
            0,
            4,
        ),
        MyDetails(
            1,
            21,
        ),
        MyDetails(
            2,
            201,
        ),
        MyDetails(
            3,
            53,
        ),
        MyDetails(
            10,
            19,
        ),
        MyDetails(
            5,
            10,
        ),
        MyDetails(
            120,
            240,
        ),
    ],
    buckets: [
        Bucket {
            simple_stat: SimpleStat {
                count: 7,
                sum: 407,
                min: 4,
                max: 199,
                average: 58,
            },
            range: 0..200,
        },
    ],
}"#
        );
    }

    #[test]
    fn add_on_drop() {
        let range = 0..u64::MAX;
        let histogram = Arc::new(Mutex::new(DetailedHistogram::new(&[range]).unwrap()));

        {
            let _ = timed_scope(histogram.clone());
        }

        assert_eq!(histogram.lock().count(), 1);
        assert!(histogram.lock().sum().unwrap() > 1);
    }

    #[test]
    fn disk_io_stat() {
        #[derive(Debug)]
        struct DiskIOStats {
            read: BytesLatencyStats,
            write: BytesLatencyStats,
        }

        #[derive(Copy, Clone, Debug)]
        enum DiskOperationType {
            Read,
            Write,
        }

        impl GetStatsForOp<DiskOperationType> for DiskIOStats {
            fn get_stats_for_op(&mut self, op: DiskOperationType) -> &mut BytesLatencyStats {
                match op {
                    DiskOperationType::Read => &mut self.read,
                    DiskOperationType::Write => &mut self.write,
                }
            }
        }

        let stats = Arc::new(Mutex::new(DiskIOStats {
            read: BytesLatencyStats::new_with_buckets(
                &[0..100, 100..u64::MAX],
                &[0..100, 100..u64::MAX],
            ),
            write: BytesLatencyStats::new_with_buckets(
                &[0..100, 100..u64::MAX],
                &[0..100, 100..u64::MAX],
            ),
        }));

        {
            let _ =
                collect_scoped_byte_latency_stat(stats.clone(), 100..1000, DiskOperationType::Read);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(stats.lock().read.latency.count(), 1);
        assert_eq!(stats.lock().read.bytes_transferred.sum(), Some(900));
        assert_eq!(stats.lock().write.latency.count(), 0);

        {
            let _ = collect_scoped_byte_latency_stat(
                stats.clone(),
                200..1000,
                DiskOperationType::Write,
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(stats.lock().write.latency.count(), 1);
        assert_eq!(stats.lock().write.bytes_transferred.sum(), Some(800));
        assert_eq!(stats.lock().read.latency.count(), 1);
        assert_eq!(stats.lock().read.bytes_transferred.sum(), Some(900));
    }
}
