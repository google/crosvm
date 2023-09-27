// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::stdout;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;

use anyhow::Context;
use anyhow::Result;
use argh::FromArgs;
use env_logger::Env;
use parse::parse_event;
use parse::parse_sched_switch;
use parse::parse_sched_waking;
use parse::parse_task_rename;
use parse::parse_vcpu_id;
use parse::Event;

mod parse;

const VCPU_PROC_PREFIX: &str = "crosvm_vcpu";

#[derive(Debug, FromArgs)]
/// Bottleneck analysis of virtio device processes.
struct Args {
    /// path to the input trace-cmd report output
    #[argh(option, short = 'i')]
    input: String,

    /// log level (default: INFO)
    #[argh(option, short = 'l', default = "String::from(\"INFO\")")]
    log_level: String,

    /// show the result in the tast JSON format
    #[argh(switch, short = 't')]
    tast_json: bool,

    /// minimum duration to show a process (default: 0.2s)
    #[argh(option, short = 'm', default = "0.2")]
    minimum_duration: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcState {
    Unknown,
    Running,
    Sleep,
    Runnable,
    Preempted,
    Dead,
    Other,
}

impl std::fmt::Display for ProcState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcState::Unknown => write!(f, "unknown"),
            ProcState::Running => write!(f, "running"),
            ProcState::Sleep => write!(f, "sleep"),
            ProcState::Runnable => write!(f, "runnable"),
            ProcState::Preempted => write!(f, "preempted"),
            ProcState::Dead => write!(f, "dead"),
            ProcState::Other => write!(f, "other"),
        }
    }
}

struct VCPUState {
    state: ProcState,
    timestamp: f64,
    last_preemptor: i32,
}

impl VCPUState {
    fn new() -> Self {
        VCPUState {
            state: ProcState::Unknown,
            timestamp: 0.0,
            last_preemptor: -1,
        }
    }

    fn set_state(&mut self, new_state: ProcState, time_stamp: f64) -> (ProcState, f64) {
        let duration = if self.timestamp != 0.0 {
            time_stamp - self.timestamp
        } else {
            0.0
        };
        let prev_state = self.state;
        self.state = new_state;
        self.timestamp = time_stamp;
        (prev_state, duration)
    }
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();

    env_logger::Builder::from_env(Env::default().default_filter_or(&args.log_level)).init();

    let file = File::open(args.input)?;
    let reader = BufReader::new(file);

    let (vcpu_state_durations, block_duration, preempted_duration, proc_names) =
        calculate_durations(reader)?;

    let metrics = make_metrics(
        &vcpu_state_durations,
        &block_duration,
        &preempted_duration,
        &proc_names,
        args.minimum_duration,
    );

    if args.tast_json {
        print_tast_json(&metrics)?;
    } else {
        print_text(&metrics);
    }

    Ok(())
}

fn calculate_durations<T: io::Read>(
    mut reader: BufReader<T>,
) -> Result<(
    Vec<HashMap<ProcState, f64>>,
    HashMap<i32, f64>,
    HashMap<i32, f64>,
    HashMap<i32, String>,
)> {
    // Initialization
    let mut vcpu_state_durations = Vec::<HashMap<ProcState, f64>>::new();
    let mut block_duration = HashMap::<i32, f64>::new();
    let mut preempted_duration = HashMap::<i32, f64>::new();
    let mut proc_names = HashMap::<i32, String>::new();
    let mut vcpu_states = Vec::<VCPUState>::new();

    // Read the first line to get the number of CPUs
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let num_cpus = line
        .trim()
        .strip_prefix("cpus=")
        .and_then(|n| n.parse::<i32>().ok())
        .context("Failed to parse number of CPUs")?;

    // Initialize data structures for VCPUs
    for _ in 0..num_cpus {
        vcpu_state_durations.push(HashMap::new());
        vcpu_states.push(VCPUState::new());
    }

    log::info!("Start processing.");

    // Process lines from the trace-cmd file
    let mut line_number = 0;
    for line_result in reader.lines() {
        let line = line_result?;

        if !line.contains(VCPU_PROC_PREFIX) && !line.contains("task_rename") {
            continue; // Skip irrelevant lines
        }

        let event = parse_event(&line).with_context(|| {
            format!("Failed to parse event (line {}): {}", line_number + 1, line)
        })?;
        update_durations(
            &event,
            &mut vcpu_states,
            &mut vcpu_state_durations,
            &mut block_duration,
            &mut preempted_duration,
            &mut proc_names,
        )
        .with_context(|| {
            format!(
                "Failed to process event (line {}): {}",
                line_number + 1,
                line
            )
        })?;

        line_number += 1;
    }
    log::info!("Read {line_number} lines.");

    Ok((
        vcpu_state_durations,
        block_duration,
        preempted_duration,
        proc_names,
    ))
}

fn update_durations(
    event: &Event,
    vcpu_states: &mut [VCPUState],
    vcpu_state_durations: &mut [HashMap<ProcState, f64>],
    block_duration: &mut HashMap<i32, f64>,
    preempted_duration: &mut HashMap<i32, f64>,
    proc_names: &mut HashMap<i32, String>,
) -> Result<()> {
    match event.name.as_str() {
        // Update the VCPU process state duration and the VCPU-blocking time of a process which waked up a VCPU process.
        "sched_waking" => {
            let sched_waking = parse_sched_waking(&event.details)?;
            if !sched_waking.waked_proc_name.starts_with(VCPU_PROC_PREFIX) {
                // skip non-VCPU processes
                return Ok(());
            }

            // Ensure a valid VCPU ID
            let vcpu_id = parse_vcpu_id(&sched_waking.waked_proc_name)?;

            if vcpu_states[vcpu_id].state != ProcState::Unknown {
                *block_duration.entry(event.pid).or_default() +=
                    event.time - vcpu_states[vcpu_id].timestamp;
            }

            let (prev_state, dur) = vcpu_states[vcpu_id].set_state(ProcState::Runnable, event.time);
            *vcpu_state_durations[vcpu_id].entry(prev_state).or_default() += dur;

            update_proc_name_if_missing(
                &sched_waking.waked_proc_name,
                sched_waking.waked_pid,
                proc_names,
            );
        }
        // Update the VCPU process state duration and the VCPU-preemption time of a process if it preempted a VCPU process.
        "sched_switch" => {
            let sched_switch = parse_sched_switch(&event.details)?;
            if sched_switch.prev_proc_name.starts_with(VCPU_PROC_PREFIX) {
                let vcpu_id = parse_vcpu_id(&sched_switch.prev_proc_name)?;
                if sched_switch.prev_proc_state == ProcState::Preempted {
                    vcpu_states[vcpu_id].last_preemptor = sched_switch.new_pid;
                }
                let (prev_state, dur) =
                    vcpu_states[vcpu_id].set_state(sched_switch.prev_proc_state, event.time);
                *vcpu_state_durations[vcpu_id].entry(prev_state).or_default() += dur;

                update_proc_name_if_missing(
                    &sched_switch.new_proc_name,
                    sched_switch.new_pid,
                    proc_names,
                );
            }
            if sched_switch.new_proc_name.starts_with(VCPU_PROC_PREFIX) {
                let vcpu_id = parse_vcpu_id(&sched_switch.new_proc_name)?;
                let (prev_state, dur) =
                    vcpu_states[vcpu_id].set_state(ProcState::Running, event.time);
                *vcpu_state_durations[vcpu_id].entry(prev_state).or_default() += dur;

                if prev_state == ProcState::Preempted {
                    *preempted_duration
                        .entry(vcpu_states[vcpu_id].last_preemptor)
                        .or_default() += dur;
                    vcpu_states[vcpu_id].last_preemptor = -1;
                }

                update_proc_name_if_missing(
                    &sched_switch.prev_proc_name,
                    sched_switch.prev_pid,
                    proc_names,
                );
            }
        }
        "task_rename" => {
            let comm = parse_task_rename(&event.details)?;
            proc_names.insert(event.pid, comm);
        }
        _ => {}
    }

    Ok(())
}

// Update the process name only when it is missing. Callers which should not
// update the process name if we already know the name of pid calls this
// function. For example, process names which appear in events will not reflect
// task rename and might keep old names.
fn update_proc_name_if_missing(proc_name: &str, pid: i32, proc_names: &mut HashMap<i32, String>) {
    if pid == 0 {
        // Special handling for "<idle>"
        proc_names.insert(pid, "<idle>".to_string());
    } else {
        proc_names
            .entry(pid)
            .or_insert_with(|| proc_name.to_string());
    }
}

#[derive(Debug)]
struct Metric {
    name: String,
    /// The value of the metric. Currently the unit is always seconds.
    value: f64,
    /// The ratio of the value if it has any total value.
    ratio: Option<Ratio>,
}

#[derive(Debug)]
struct Ratio {
    /// Unit: percent
    value: f64,
    /// Description of the total value of the ratio.
    total_value_text: String,
}

fn make_metrics(
    vcpu_state_durations: &[HashMap<ProcState, f64>],
    block_duration: &HashMap<i32, f64>,
    preempted_duration: &HashMap<i32, f64>,
    proc_names: &HashMap<i32, String>,
    minimum_duration: f64,
) -> Vec<Metric> {
    let mut metrics = Vec::new();

    // VCPU state metrics
    let total_vcpu_proc_duration: HashMap<ProcState, f64> =
        vcpu_state_durations
            .iter()
            .fold(HashMap::new(), |mut acc, durations| {
                for (state, dur) in durations.iter() {
                    *acc.entry(*state).or_default() += dur;
                }
                acc
            });

    let vcpu_times: Vec<f64> = vcpu_state_durations
        .iter()
        .map(|durations| durations.values().sum())
        .collect();

    let total_vcpu_time: f64 = vcpu_times.iter().sum(); // Sum of durations across all vCPUs

    let proc_states_to_report: &[ProcState] = &[
        ProcState::Running,
        ProcState::Sleep,
        ProcState::Runnable,
        ProcState::Preempted,
    ];
    let proc_states_to_ignore: &[ProcState] =
        &[ProcState::Dead, ProcState::Other, ProcState::Unknown];

    for (cpu, durations) in vcpu_state_durations.iter().enumerate() {
        for state in proc_states_to_report {
            metrics.push(Metric {
                name: format!("vcpu{}_{}", cpu, state),
                value: durations.get(state).copied().unwrap_or(0.0),
                ratio: Some(Ratio {
                    value: durations.get(state).copied().unwrap_or(0.0) / vcpu_times[cpu] * 100.0,
                    total_value_text: format!("vcpu{cpu}_time"),
                }),
            });
        }
        for state in proc_states_to_ignore {
            if *durations.get(state).unwrap_or(&minimum_duration) > minimum_duration {
                log::warn!(
                    "{:?} duration {} > {}",
                    state,
                    durations.get(state).unwrap(),
                    minimum_duration
                );
            }
        }
    }

    // Total VCPU metrics
    for state in proc_states_to_report {
        // Safety: TODO
        metrics.push(Metric {
            name: format!("total_vcpu_{}", state),
            value: total_vcpu_proc_duration.get(state).copied().unwrap_or(0.0),
            ratio: Some(Ratio {
                value: total_vcpu_proc_duration.get(state).copied().unwrap_or(0.0)
                    / total_vcpu_time
                    * 100.0,
                total_value_text: "total_vcpu_time".to_string(),
            }),
        });
    }
    metrics.push(Metric {
        name: "total_vcpu_time".to_string(),
        value: total_vcpu_time,
        ratio: None,
    });

    // Preempted and Blocked metrics
    metrics.extend(make_sorted_duration_metrics(
        preempted_duration,
        proc_names,
        total_vcpu_time,
        minimum_duration,
        "preempted",
    ));
    metrics.extend(make_sorted_duration_metrics(
        block_duration,
        proc_names,
        total_vcpu_time,
        minimum_duration,
        "blocked",
    ));

    metrics
}

fn make_sorted_duration_metrics(
    durations_by_pid: &HashMap<i32, f64>,
    names: &HashMap<i32, String>,
    total_time: f64,
    filter_minimum: f64,
    metric_prefix: &str,
) -> Vec<Metric> {
    let mut durations_by_name: HashMap<String, f64> = HashMap::new();
    for (pid, dur) in durations_by_pid.iter() {
        let proc_name = names
            .get(pid)
            .unwrap_or(&format!("NoProcName({})", pid))
            .clone();
        *durations_by_name.entry(proc_name).or_default() += dur;
    }

    let mut names_sorted: Vec<&String> = durations_by_name.keys().collect();
    names_sorted.sort_by(|a, b| {
        durations_by_name[b.as_str()]
            .partial_cmp(&durations_by_name[a.as_str()])
            .unwrap()
    });

    let mut metrics = Vec::new();
    for n in names_sorted {
        if durations_by_name[n] < filter_minimum {
            break; // Stop if we reach durations below the threshold
        }
        metrics.push(Metric {
            name: format!("{}_{}", metric_prefix, n),
            value: durations_by_name[n],
            ratio: Some(Ratio {
                value: durations_by_name[n] / total_time * 100.0,
                total_value_text: "total_vcpu_time".to_string(),
            }),
        });
    }

    metrics
}

fn print_tast_json(metrics: &[Metric]) -> Result<()> {
    println!("{{");

    stdout()
        .write_all(
            metrics
                .iter()
                .map(build_tast_metric)
                .collect::<Vec<_>>()
                .join(",")
                .as_bytes(),
        )
        .with_context(|| "Failed to write to stdout")?;

    println!("\n}}");
    Ok(())
}

fn build_tast_metric(metric: &Metric) -> String {
    // Convert a Metric to a TAST metric json string
    let name = &metric.name;
    let value = metric.value;
    let mut json = format!(
        r#"
        "{name}": {{
            "summary": {{
                "units": "sec",
                "improvement_direction": "down",
                "type": "scalar",
                "value": {value}
            }}
        }}"#
    );
    // Append ratio metric if present
    if let Some(ratio) = &metric.ratio {
        let name = format!("{}_ratio", metric.name);
        let value = ratio.value;
        json.push_str(&format!(
            r#",
        "{name}": {{
            "summary": {{
                "units": "percent",
                "improvement_direction": "down",
                "type": "scalar",
                "value": {value}
            }}
        }}"#
        ));
    }
    json
}

fn print_text(metrics: &[Metric]) {
    for metric in metrics {
        print!("{}\t{:.4} sec", metric.name, metric.value);
        if let Some(ratio) = &metric.ratio {
            print!(
                "\t(ratio: {:.3}% of {})",
                ratio.value, ratio.total_value_text
            );
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use rstest::*;

    use super::*;

    #[rstest]
    #[case(
        r#"cpus=1
            <idle>-0 [000] 10.00: sched_waking: comm=crosvm_vcpu0 pid=2 prio=120 target_cpu=000
            other-17 [000] 20.00: sched_stat_runtime: comm=other pid=17 runtime=1 [ns] vruntime=1 [ns]
            <idle>-0 [000] 30.00: sched_switch: swapper/0:0 [120] R ==> crosvm_vcpu0:2 [120]
        "#,
        vec![(ProcState::Unknown, 0.0), (ProcState::Runnable, 20.0)].into_iter().collect()
    )]
    fn test_calculate_stats(
        #[case] test_data: &str,
        #[case] expected_vcpu_dur: HashMap<ProcState, f64>,
    ) {
        let reader = BufReader::new(test_data.as_bytes());
        let (v_cpudur, _, _, _) = calculate_durations(reader).unwrap();
        assert_eq!(v_cpudur[0], expected_vcpu_dur);
    }
}
