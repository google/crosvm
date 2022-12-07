// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use argh::FromArgs;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_json::to_string_pretty;
use serde_json::Number;
use serde_json::Value;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::hash::Hash;
use std::hash::Hasher;
use uuid::Uuid;

/// This tool takes results from Fuchsia performance tests (in Fuchsia's JSON perf test results
/// format) and converts them to the Catapult Dashboard's JSON HistogramSet format.
///
/// See <https://cs.opensource.google/fuchsia/fuchsia/+/main:src/testing/catapult_converter/README.md>
/// for details on arguments that are copied into output
#[derive(FromArgs)]
struct ConverterArgs {
    /// input file: perf test results JSON file
    #[argh(option, arg_name = "FILENAME")]
    input: String,

    /// output file: Catapult HistogramSet JSON file (default is stdout)
    #[argh(option, arg_name = "FILENAME")]
    output: Option<String>,

    /// release version in the format 0.yyyymmdd.a.b if applicable. e.g. 0.20200101.1.2
    #[argh(option, arg_name = "STRING")]
    product_version: Option<String>,

    /// copied into output file as pointId, used to order results from different builds in a graph
    #[argh(option, arg_name = "NUMBER")]
    execution_timestamp_ms: i64,

    /// copied into output file
    #[argh(option, arg_name = "STRING")]
    masters: String,

    /// copied into output file
    #[argh(option, arg_name = "STRING")]
    bots: String,

    /// copied into output file
    #[argh(option, arg_name = "URL")]
    log_url: String,
}

#[derive(Deserialize, Debug)]
enum FuchsiaPerfUnit {
    #[serde(alias = "nanoseconds", alias = "ns")]
    NanoSeconds,
    #[serde(alias = "milliseconds", alias = "ms")]
    Milliseconds,
    #[serde(alias = "bytes/second")]
    BytesPerSecond,
    #[serde(alias = "bits/second")]
    BitsPerSecond,
    #[serde(alias = "bytes")]
    Bytes,
    #[serde(alias = "frames/second")]
    FramesPerSecond,
    #[serde(alias = "percent")]
    Percent,
    #[serde(alias = "count")]
    Count,
    Watts,
}

#[derive(Serialize, Debug)]
enum HistogramUnit {
    #[serde(rename = "ms_smallerIsBetter")]
    Milliseconds,
    #[serde(rename = "unitless_biggerIsBetter")]
    UnitlessBiggerIsBetter,
    #[serde(rename = "sizeInBytes_smallerIsBetter")]
    Bytes,
    #[serde(rename = "Hz_biggerIsBetter")]
    FramesPerSecond,
    #[serde(rename = "n%_smallerIsBetter")]
    Percent,
    #[serde(rename = "count")]
    Count,
    #[serde(rename = "W_smallerIsBetter")]
    Watts,
}

#[derive(Deserialize, Debug)]
struct FuchsiaPerf {
    #[serde(alias = "label")]
    test_name: String,
    metric: Option<String>,
    test_suite: String,
    unit: FuchsiaPerfUnit,
    values: Vec<f64>,
}

fn convert_unit(input_unit: FuchsiaPerfUnit, values: &mut [f64]) -> HistogramUnit {
    match input_unit {
        FuchsiaPerfUnit::NanoSeconds => {
            for value in values.iter_mut() {
                *value /= 1e6;
            }
            HistogramUnit::Milliseconds
        }
        FuchsiaPerfUnit::Milliseconds => HistogramUnit::Milliseconds,
        // The Catapult dashboard does not yet support a "bytes per unit time"
        // unit (of any multiple), and it rejects unknown units, so we report
        // this as "unitless" here for now.
        FuchsiaPerfUnit::BytesPerSecond => HistogramUnit::UnitlessBiggerIsBetter,
        FuchsiaPerfUnit::BitsPerSecond => {
            // convert to bytes/s to be consistent with bytes/second
            for value in values.iter_mut() {
                *value /= 8.0;
            }
            HistogramUnit::UnitlessBiggerIsBetter
        }
        FuchsiaPerfUnit::Bytes => HistogramUnit::Bytes,
        FuchsiaPerfUnit::FramesPerSecond => HistogramUnit::FramesPerSecond,
        FuchsiaPerfUnit::Percent => HistogramUnit::Percent,
        FuchsiaPerfUnit::Count => HistogramUnit::Count,
        FuchsiaPerfUnit::Watts => HistogramUnit::Watts,
    }
}

#[derive(Serialize, Clone, Debug, Eq)]
struct Diagnostic {
    guid: String,
    #[serde(rename = "type", default = "GenericSet")]
    diag_type: String,
    values: Vec<Value>,
}

impl Hash for Diagnostic {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.guid.hash(state);
    }
}

impl PartialEq<Self> for Diagnostic {
    fn eq(&self, other: &Self) -> bool {
        self.guid == other.guid
    }
}

impl Default for Diagnostic {
    fn default() -> Self {
        Diagnostic {
            guid: Uuid::new_v4().to_string(),
            diag_type: "GenericSet".to_string(),
            values: Vec::default(),
        }
    }
}

#[derive(Serialize, Debug)]
struct Histogram {
    name: String,
    unit: HistogramUnit,
    #[serde(default)]
    description: String,
    diagnostics: HashMap<&'static str, String>,
    // serde_json converts NaN / infinite to null by default
    running: Vec<Option<Number>>,
    guid: String,
    #[serde(rename = "maxNumSampleValues")]
    max_num_sample_values: u64,
    #[serde(rename = "numNans", default)]
    num_nans: u64,
}

impl Histogram {
    fn new(
        test_name: &str,
        unit: FuchsiaPerfUnit,
        diagnostics: HashMap<&'static str, String>,
        original_values: Vec<f64>,
    ) -> Self {
        let mut values = original_values;
        let output_unit = convert_unit(unit, &mut values);

        let mut stats: Vec<Option<Number>> = Vec::new();
        let mean: f64 = values.iter().sum::<f64>() / values.len() as f64;

        // count
        stats.push(Some(values.len().into()));

        // max
        stats.push(Number::from_f64(
            values.iter().cloned().max_by(f64::total_cmp).unwrap(),
        ));

        // meanlogs
        stats.push(Number::from_f64(
            values.iter().map(|x| f64::ln(*x)).sum::<f64>() / values.len() as f64,
        ));

        // mean
        stats.push(Number::from_f64(mean));

        // min
        stats.push(Number::from_f64(
            values.iter().cloned().min_by(f64::total_cmp).unwrap(),
        ));

        // sum
        stats.push(Number::from_f64(values.iter().sum()));

        // variance
        // Bessel's correction applied. Bessel's correction gives us a better estimation of
        // the population's variance given a sample of the population.
        stats.push(Number::from_f64(if values.len() <= 1 {
            0.0
        } else {
            values
                .iter()
                .map(|x| (*x - mean) * (*x - mean))
                .sum::<f64>()
                / (values.len() - 1) as f64
        }));

        Histogram {
            name: test_name.to_string(),
            unit: output_unit,
            description: "".to_string(),
            diagnostics,
            running: stats,
            guid: Uuid::new_v4().to_string(),
            max_num_sample_values: values.len() as u64,
            // Assume for now that we didn't get any NaN values.
            num_nans: 0,
        }
    }
}

fn build_shared_diagnostic_map(
    args: &ConverterArgs,
) -> (HashMap<&'static str, String>, HashSet<Diagnostic>) {
    let mut diag_map = HashMap::new();
    let mut diag_set = HashSet::new();

    let diag = Diagnostic {
        values: vec![json!(args.execution_timestamp_ms)],
        ..Default::default()
    };
    diag_set.insert(diag.clone());
    diag_map.insert("pointId", diag.guid);

    let diag = Diagnostic {
        values: vec![json!(args.bots)],
        ..Default::default()
    };
    diag_set.insert(diag.clone());
    diag_map.insert("bots", diag.guid);

    let diag = Diagnostic {
        values: vec![json!(args.masters)],
        ..Default::default()
    };
    diag_set.insert(diag.clone());
    diag_map.insert("masters", diag.guid);

    if let Some(version) = &args.product_version {
        let diag = Diagnostic {
            values: vec![json!(version)],
            ..Default::default()
        };
        diag_set.insert(diag.clone());
        diag_map.insert("a_productVersions", diag.guid);
    }
    let diag = Diagnostic {
        values: vec![json!(vec!("Build Log".to_string(), args.log_url.clone()))],
        ..Default::default()
    };
    diag_set.insert(diag.clone());
    diag_map.insert("logUrls", diag.guid);
    (diag_map, diag_set)
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
enum HistogramSetElement {
    Diagnostic(Diagnostic),
    Histogram(Histogram),
}

fn main() {
    let args: ConverterArgs = argh::from_env();
    let content = fs::read_to_string(&args.input)
        .expect("Failed to read the file, have you specified the correct path?");

    let perf_data: Vec<FuchsiaPerf> =
        serde_json::from_str(&content).expect("Failed to parse input data file");

    let (shared_diag_map, mut diag_set) = build_shared_diagnostic_map(&args);

    let mut test_suite_guid_map = HashMap::new();

    for test_result in &perf_data {
        if !test_suite_guid_map.contains_key(&test_result.test_suite) {
            let new_uuid = Uuid::new_v4().to_string();
            test_suite_guid_map.insert(test_result.test_suite.clone(), new_uuid.to_owned());
            diag_set.insert(Diagnostic {
                values: vec![json!(test_result.test_suite)],
                guid: new_uuid,
                ..Default::default()
            });
        }
    }

    let mut output = Vec::<HistogramSetElement>::new();
    output.extend(
        diag_set
            .iter()
            .cloned()
            .map(HistogramSetElement::Diagnostic),
    );

    for test_result in perf_data {
        let mut diag_map = shared_diag_map.clone();
        diag_map.insert(
            "benchmarks",
            test_suite_guid_map[&test_result.test_suite].clone(),
        );

        let mut name = test_result.test_name.clone();
        if let Some(metric) = &test_result.metric {
            if metric != "real_time" {
                name += "/";
                name += metric.as_str();
            }
        }

        output.push(HistogramSetElement::Histogram(Histogram::new(
            name.replace(" ", "_").as_str(),
            test_result.unit,
            diag_map,
            test_result.values,
        )));
    }

    let serialized_output = to_string_pretty(&output).expect("Unable to serialize result");

    match &args.output {
        Some(file_name) => fs::write(file_name, serialized_output).unwrap(),
        None => println!("{}", serialized_output),
    }
}
