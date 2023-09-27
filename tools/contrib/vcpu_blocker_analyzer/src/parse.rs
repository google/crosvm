// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use once_cell::sync::OnceCell;
use regex::Regex;

use crate::ProcState;

#[derive(Debug)]
pub struct Event {
    pub pid: i32,
    pub proc_name: String,
    pub name: String,
    pub details: String,
    pub time: f64,
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.proc_name == other.proc_name
            && self.name == other.name
            && self.details == other.details
            && self.time.to_bits() == other.time.to_bits()
    }
}

static EVENT_PATTERN: OnceCell<Regex> = OnceCell::new();

pub fn parse_event(line: &str) -> Option<Event> {
    let event_pattern = EVENT_PATTERN.get_or_init(|| {
        Regex::new(
            r" +(?P<proc>.*)-(?P<pid>\d+) +\[(?P<cpu>\d+)\] +(?P<ts>\d+\.\d+): +(?P<event>\S*): +",
        )
        .expect("Failed to compile event pattern")
    });

    let event_captures = event_pattern.captures(line)?;

    Some(Event {
        pid: event_captures["pid"].parse::<i32>().ok()?,
        proc_name: event_captures["proc"].to_string(),
        name: event_captures["event"].to_string(),
        details: line[event_pattern.find(line)?.end()..].to_string(),
        time: event_captures["ts"].parse::<f64>().ok()?,
    })
}

static VCPU_ID_PATTERN: OnceCell<Regex> = OnceCell::new();

pub fn parse_vcpu_id(proc_name: &str) -> Result<usize> {
    let vcpu_id_pattern = VCPU_ID_PATTERN.get_or_init(|| Regex::new(r"crosvm_vcpu(\d+)").unwrap());

    if let Some(captures) = vcpu_id_pattern.captures(proc_name) {
        captures
            .get(1)
            .and_then(|id_match| id_match.as_str().parse::<usize>().ok())
            .ok_or_else(|| anyhow::anyhow!("Invalid vCPU ID format in process name: {}", proc_name))
    } else {
        Err(anyhow::anyhow!(
            "VCPU ID not found in process name: {}",
            proc_name
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SchedWaking {
    pub waked_proc_name: String,
    pub waked_pid: i32,
}

static SCHED_WAKING_PATTERN: OnceCell<Regex> = OnceCell::new();

pub fn parse_sched_waking(details: &str) -> Result<SchedWaking> {
    let sched_waking_pattern = SCHED_WAKING_PATTERN
        .get_or_init(|| Regex::new(r"comm=(?P<proc>.*) pid=(?P<pid>\d+)").unwrap());

    let sched_waking_captures = sched_waking_pattern
        .captures(details)
        .ok_or_else(|| anyhow!("Failed to parse sched_waking"))?;
    Ok(SchedWaking {
        waked_proc_name: sched_waking_captures["proc"].to_string(),
        waked_pid: sched_waking_captures["pid"]
            .parse::<i32>()
            .with_context(|| format!("Failed to parse pid: {}", &sched_waking_captures["pid"]))?,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub struct SchedSwitch {
    pub prev_proc_name: String,
    pub prev_pid: i32,
    pub prev_proc_state: ProcState,
    pub new_proc_name: String,
    pub new_pid: i32,
}

static SCHED_SWITCH_PATTERN: OnceCell<Regex> = OnceCell::new();

pub fn parse_sched_switch(details: &str) -> Result<SchedSwitch> {
    let sched_switch_pattern = SCHED_SWITCH_PATTERN.get_or_init(|| Regex::new(r"(?P<prev>.*):(?P<prev_pid>\d+) \[-?\d+\] (?P<state>\S+) ==> (?P<new>.*):(?P<new_pid>\d+) \[-?\d+\]").expect("failed to compile regex"));

    let sched_switch_captures = sched_switch_pattern
        .captures(details)
        .with_context(|| format!("Failed to parse sched_switch: {}", details))?;

    let prev_state = match &sched_switch_captures["state"] {
        "R" | "R+" => ProcState::Preempted,
        "D" | "S" => ProcState::Sleep,
        "X" => ProcState::Dead,
        _ => ProcState::Other,
    };

    Ok(SchedSwitch {
        prev_proc_name: sched_switch_captures["prev"].to_string(),
        prev_pid: sched_switch_captures["prev_pid"]
            .parse::<i32>()
            .with_context(|| {
                format!(
                    "Failed to parse pid: {}",
                    &sched_switch_captures["prev_pid"]
                )
            })?,
        prev_proc_state: prev_state,
        new_proc_name: sched_switch_captures["new"].to_string(),
        new_pid: sched_switch_captures["new_pid"]
            .parse::<i32>()
            .with_context(|| {
                format!("Failed to parse pid: {}", &sched_switch_captures["new_pid"])
            })?,
    })
}

static TASK_RENAME_PATTERN: OnceCell<Regex> = OnceCell::new();

pub fn parse_task_rename(details: &str) -> Result<String> {
    // Match a line like "newcomm=D-Bus Thread oom_score_adj="
    let task_rename_pattern = TASK_RENAME_PATTERN.get_or_init(|| {
        Regex::new(r"newcomm=(?P<comm>.*) +oom_score_adj=").expect("failed to compile regex")
    });

    Ok(task_rename_pattern
        .captures(details)
        .with_context(|| format!("Failed to parse task_rename: {}", details))?
        .name("comm")
        .with_context(|| format!("Failed to parse comm: {}", details))?
        .as_str()
        .to_owned())
}

#[cfg(test)]
mod tests {
    use rstest::*;

    use super::*;

    #[rstest]
    #[case(
        "normal",
        " trace-cmd-6563 [006] 575400.854473: sched_stat_runtime:  comm=trace-cmd pid=6563 runtime=44314 [ns] vruntime=112263744696292 [ns]",
        Event {
            proc_name: "trace-cmd".to_string(),
            pid: 6563,
            name: "sched_stat_runtime".to_string(),
            details: "comm=trace-cmd pid=6563 runtime=44314 [ns] vruntime=112263744696292 [ns]".to_string(),
            time: 575400.854473,
        }
    )]
    #[case(
        "proc name with a space",
        "  D-Bus thread-3284 [002] 575401.489380842: sched_waking:     comm=chrome pid=3269 prio=112 target_cpu=004",
        Event {
            proc_name: "D-Bus thread".to_string(),
            pid: 3284,
            name: "sched_waking".to_string(),
            details: "comm=chrome pid=3269 prio=112 target_cpu=004".to_string(),
            time: 575401.489380842,
        }
    )]
    fn test_parse_event(#[case] name: &str, #[case] line: &str, #[case] want: Event) {
        assert_eq!(parse_event(line), Some(want), "Test case: {}", name);
    }

    #[rstest]
    #[case(
        "normal",
        "comm=VizCompositorTh pid=3338 prio=112 target_cpu=000",
        SchedWaking {
            waked_proc_name: "VizCompositorTh".to_string(),
            waked_pid: 3338,
        }
    )]
    #[case(
        "proc name with a space",
        "comm=D-Bus thread pid=3338 prio=112 target_cpu=000",
        SchedWaking {
            waked_proc_name: "D-Bus thread".to_string(),
            waked_pid: 3338,
        }
    )]
    fn test_parse_sched_waking(#[case] name: &str, #[case] line: &str, #[case] want: SchedWaking) {
        assert_eq!(
            parse_sched_waking(line).unwrap(),
            want,
            "Test case: {}",
            name
        );
    }

    #[rstest]
    #[case(
        "normal",
        "trace-cmd:6559 [120] D ==> swapper/2:0 [120]",
        SchedSwitch {
            prev_proc_name: "trace-cmd".to_string(),
            prev_pid: 6559,
            prev_proc_state: ProcState::Sleep,
            new_proc_name: "swapper/2".to_string(),
            new_pid: 0,
        }
    )]
    #[case(
        "preempted",
        "trace-cmd:6559 [120] R+ ==> swapper/2:0 [120]",
        SchedSwitch {
            prev_proc_name: "trace-cmd".to_string(),
            prev_pid: 6559,
            prev_proc_state: ProcState::Preempted,
            new_proc_name: "swapper/2".to_string(),
            new_pid: 0,
        }
    )]
    // ... add more test cases as needed
    fn test_parse_sched_switch(#[case] name: &str, #[case] line: &str, #[case] want: SchedSwitch) {
        assert_eq!(
            parse_sched_switch(line).unwrap(),
            want,
            "Test case: {}",
            name
        );
    }

    #[rstest]
    #[case("crosvm_vcpu123", Some(123))]
    #[case("crosvm_vcpu4", Some(4))]
    #[case("invalid_format", None)]
    #[case("crosvm_vcpuXYZ", None)]
    #[case("", None)]
    fn test_parse_vcpu_id(#[case] input: &str, #[case] expected_output: Option<usize>) {
        // Test logic
        match super::parse_vcpu_id(input) {
            Ok(id) => assert_eq!(id, expected_output.unwrap()),
            Err(_) => assert!(expected_output.is_none()), // Assert an error was expected
        }
    }
}
