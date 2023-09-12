// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::anyhow;
use argh::FromArgs;
use libtracecmd::Event;
use libtracecmd::Handler;
use libtracecmd::Input;
use libtracecmd::Record;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Write;

#[derive(FromArgs, Debug)]
/// Command line parameters.
struct Config {
    #[argh(subcommand)]
    /// decide mode(average,flamegraph)
    mode: Mode,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Mode {
    Average(Average),
    Flamegraph(Flamegraph),
}

#[derive(FromArgs, PartialEq, Debug)]
/// output average latency of each cros_tracing event.
#[argh(subcommand, name = "average")]
struct Average {
    #[argh(option)]
    /// path to the input .dat file
    input: String,
    #[argh(option)]
    /// path to the output JSON file
    output_json: String,
}

#[derive(FromArgs, PartialEq, Debug)]
/// output data for flamegraph.
#[argh(subcommand, name = "flamegraph")]
struct Flamegraph {
    #[argh(option)]
    /// path to the input .dat file
    input: String,
    #[argh(option)]
    /// path to the output JSON file
    output_json: String,
    #[argh(option)]
    /// decide which function to focus on
    /// unspecified: output flamegraph for all event
    function: Option<String>,
    #[argh(option)]
    /// top <n> time consuming events
    /// unspecified: output flamegraph for all event
    count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventInformation {
    pid: i32,
    cpu: i32,
    name: String,
    time_stamp: u64,
    details: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct EventData {
    event_names: HashSet<String>,
    stats: Vec<EventInformation>,
}

impl EventData {
    // Populates all cros_tracing events in event_names
    fn populate_event_names(&mut self) {
        let mut event_names = HashSet::<String>::new();
        for stat in &self.stats {
            if stat.details.contains("Enter") {
                let split = stat.details.split_whitespace().collect::<Vec<&str>>();
                let name = split[4];
                event_names.insert(name.to_string());
            }
        }
        self.event_names = event_names;
    }

    // Calculates average latency of each cros_tracing event
    fn calculate_function_time(&self) -> HashMap<String, u64> {
        let mut values = HashMap::new();
        for event in self.event_names.iter() {
            let mut count = 0;
            let mut sum_time = 0;
            let enter = format!("Enter: {event}");
            let exit = format!("Exit: {event}");
            for i in 0..self.stats.len() {
                if self.stats[i].details.contains(&enter) {
                    let split_enter = self.stats[i]
                        .details
                        .split_whitespace()
                        .collect::<Vec<&str>>();
                    let enter_id = split_enter[1];
                    for j in i + 1..self.stats.len() {
                        if self.stats[j].details.contains(&exit) {
                            let split_exit = self.stats[j]
                                .details
                                .split_whitespace()
                                .collect::<Vec<&str>>();
                            let exit_id = split_exit[1];
                            if enter_id == exit_id {
                                let time = self.stats[j].time_stamp - self.stats[i].time_stamp;
                                sum_time += time;
                                count += 1;
                                break;
                            }
                        }
                    }
                }
            }
            let latency = sum_time / count;
            let name = format!("{event}_latency");
            values.insert(String::from(name), latency);
        }
        values
    }

    //Populates all cros_tracing events name and latency in LatencyData
    fn calculate_latency_data(&self) -> LatencyData {
        let mut latency_data: LatencyData = Default::default();
        for i in 0..self.stats.len() {
            if self.stats[i].details.contains("Enter") {
                let split_enter = self.stats[i]
                    .details
                    .split_whitespace()
                    .collect::<Vec<&str>>();
                let event_name = split_enter[4];
                let enter_id = split_enter[1];
                for j in i + 1..self.stats.len() {
                    if self.stats[j].details.contains("Exit") {
                        let split_exit = self.stats[j]
                            .details
                            .split_whitespace()
                            .collect::<Vec<&str>>();
                        let exit_id = split_exit[1];
                        if enter_id == exit_id {
                            let time = self.stats[j].time_stamp - self.stats[i].time_stamp;
                            let element = LatencyInformation {
                                event_name: event_name.to_string(),
                                enter_index: i,
                                exit_index: j,
                                latency: time,
                            };
                            latency_data.stats.push(element);
                            break;
                        }
                    }
                }
            }
        }
        latency_data
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
struct LatencyInformation {
    event_name: String,
    enter_index: usize,
    exit_index: usize,
    latency: u64,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
struct LatencyData {
    stats: Vec<LatencyInformation>,
}

impl LatencyData {
    fn calculate_root_layer_events(
        &self,
        eventdata: &EventData,
        function_filter: Option<String>,
        count_filter: Option<u64>,
    ) -> Vec<LayerData> {
        let mut base_layer_data: Vec<LayerData> = Vec::new();
        for i in 0..self.stats.len() {
            if let Some(count_filter) = count_filter {}
            if !self.stats[i]
                .event_name
                .contains(&*function_filter.as_ref().unwrap())
            {
                continue;
            }
            let mut layer_data: Vec<LayerData> = Vec::new();
            let mut index_counter = HashSet::new();
            let pid = eventdata.stats[self.stats[i].enter_index].pid;
            LatencyData::create_layer(
                eventdata,
                self.stats[i].enter_index,
                self.stats[i].exit_index,
                pid,
                &mut layer_data,
                &mut index_counter,
            );
            let data = LayerData {
                name: self.stats[i].event_name.clone(),
                value: self.stats[i].latency,
                children: layer_data,
            };
            base_layer_data.push(data);
        }
        if let Some(count_filter) = count_filter {
            base_layer_data.sort_by(|a, b| b.value.cmp(&a.value));
            if count_filter <= base_layer_data.len() as u64 {
                base_layer_data = base_layer_data[..count_filter as usize].to_vec();
            }
        }
        base_layer_data
    }

    // collect syscall data for flamegraph recursively
    fn create_layer(
        eventdata: &EventData,
        enter_index: usize,
        exit_index: usize,
        pid: i32,
        layer_data: &mut Vec<LayerData>,
        mut index_counter: &mut HashSet<usize>,
    ) {
        for i in enter_index + 1..exit_index {
            // calculate the nested syscalls
            if index_counter.contains(&i) {
                continue;
            }
            if eventdata.stats[i].pid != pid {
                continue;
            }
            let sys_enter_pid = eventdata.stats[i].pid;
            // example log: name: "sys_enter_write"
            if let Some(m) = eventdata.stats[i].name.find("enter") {
                index_counter.insert(i);
                // "m" represents e(nter),
                // m + "enter".len() represents the first character of syscall_name
                // example: write
                let syscall_name = &eventdata.stats[i].name[m + "enter".len()..];
                let name = format!("sys_{syscall_name}");
                let exit_name = format!("sys_exit_{syscall_name}");
                for j in i + 1..exit_index {
                    if eventdata.stats[j].pid != sys_enter_pid {
                        continue;
                    }
                    if !eventdata.stats[j].name.contains(&exit_name) {
                        continue;
                    }
                    let layer_time = eventdata.stats[j].time_stamp - eventdata.stats[i].time_stamp;
                    let mut new_layer: Vec<LayerData> = Vec::new();
                    LatencyData::create_layer(
                        eventdata,
                        i,
                        j,
                        sys_enter_pid,
                        &mut new_layer,
                        &mut index_counter,
                    );
                    let data = LayerData {
                        name: name.clone(),
                        value: layer_time,
                        children: new_layer,
                    };
                    layer_data.push(data);
                    break;
                }
            }
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
struct LayerData {
    name: String,
    value: u64,
    children: Vec<LayerData>,
}

// Struct that we implement `libtracecmd::Handler` for.
//unit struct
struct HandlerImplement;

impl Handler for HandlerImplement {
    /// Type of data passed to the callback to accumulate data.
    type AccumulatedData = EventData;
    /// Callback that processes each trace event `rec` and accumulate statistics to `data`.
    /// This callback is called for each trace event one by one.
    fn callback(
        input: &mut Input,
        rec: &mut Record,
        cpu: i32,
        data: &mut Self::AccumulatedData, //use for output
    ) -> i32 {
        let event: Event = input.find_event(rec).unwrap();
        let pid = input.handle_ref().unwrap().pid(rec);
        let time_stamp = rec.ts();
        let details = event.get_fields(rec);
        let name = event.name;
        let element = EventInformation {
            pid,
            cpu,
            name,
            time_stamp,
            details,
        };
        data.stats.push(element);
        0
    }
}

fn main() -> anyhow::Result<()> {
    let cfg: Config = argh::from_env();

    let mode = cfg.mode;
    match mode {
        Mode::Average(average) => {
            let input = average.input;
            let mut input = Input::new(&input)?;
            let mut stats = HandlerImplement::process(&mut input).unwrap();
            let output = average.output_json;
            if std::path::Path::new(&output)
                .extension()
                .and_then(OsStr::to_str)
                != Some("json")
            {
                return Err(anyhow!("file extension must be .json"));
            }

            stats.populate_event_names();
            let average_data = stats.calculate_function_time();
            write_to_file(average_data, &output)
        }

        Mode::Flamegraph(flamegraph) => {
            let input = flamegraph.input;
            let mut input = Input::new(&input)?;
            let mut stats = HandlerImplement::process(&mut input).unwrap();
            let output = flamegraph.output_json;
            if std::path::Path::new(&output)
                .extension()
                .and_then(OsStr::to_str)
                != Some("json")
            {
                return Err(anyhow!("file extension must be .json"));
            }
            let latency_data = stats.calculate_latency_data();
            let layer_data = latency_data.calculate_root_layer_events(
                &stats,
                flamegraph.function.clone(),
                flamegraph.count,
            );
            let data: LayerData = LayerData {
                name: "root".to_string(),
                // set root value to 0 because we don't need it
                value: 0,
                children: layer_data,
            };
            write_to_file(data, &output)
        }
    }
    Ok(())
}

fn write_to_file<T: serde::Serialize>(data: T, output: &str) {
    let mut fout = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output)
        .unwrap();
    let serialized = serde_json::to_string(&data).unwrap();
    fout.write_all(serialized.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    // example data
    fn setup() -> EventData {
        let stats = vec![
            EventInformation{
                pid: 100,
                cpu: 1,
                name: "print".to_string(),
                time_stamp: 100,
                details: " ip=tracing_mark_write buf=32256 VirtioFs Enter: lookup - (self.tag: \"mtdroot\")(parent: 5358)(name: \"LC_MESSAGES\")\n".to_string()
            },
            EventInformation {
                pid: 100,
                cpu: 1,
                name: "sys_enter_write".to_string(),
                time_stamp: 200,
                details: " __syscall_nr=1 fd=0x00000021 buf=0x7f21e4e0a02f count=0x00000001"
                    .to_string(),
            },
            EventInformation {
                pid: 100,
                cpu: 1,
                name: "sys_enter_read".to_string(),
                time_stamp: 300,
                details: " __syscall_nr=0 fd=0x00000011 buf=0x7f21ef3fc688 count=0x00000001"
                    .to_string(),
            },
            EventInformation {
                pid: 100,
                cpu: 1,
                name: "sys_exit_read".to_string(),
                time_stamp: 400,
                details: " __syscall_nr=0 ret=0x1".to_string(),
            },
            EventInformation {
                pid: 100,
                cpu: 1,
                name: "sys_exit_write".to_string(),
                time_stamp: 500,
                details: " __syscall_nr=1 ret=0x1".to_string(),
            },
            EventInformation {
                pid: 100,
                cpu: 1,
                name: "print".to_string(),
                time_stamp: 600,
                details: " ip=tracing_mark_write buf=32256 VirtioFs Exit: lookup\n".to_string(),
            },
        ];
        let event_names = HashSet::<String>::new();
        EventData { event_names, stats }
    }

    #[test]
    fn populate_event_names_test() {
        let mut data = setup();
        data.populate_event_names();
        assert_eq!(data.event_names, HashSet::from(["lookup".to_string()]));
    }

    #[test]
    fn calculate_latency_data_test() {
        let data = setup();
        let latency_data = data.calculate_latency_data();
        let expected_data = LatencyData {
            stats: [LatencyInformation {
                event_name: "lookup".to_string(),
                enter_index: 0,
                exit_index: 5,
                latency: 500,
            }]
            .to_vec(),
        };
        assert_eq!(latency_data, expected_data);
    }

    #[test]
    fn create_layer_test() {
        let data = setup();
        let mut test_layer_data: Vec<LayerData> = Vec::new();
        let mut test_index_counter = HashSet::new();
        LatencyData::create_layer(
            &data,
            0,
            5,
            100,
            &mut test_layer_data,
            &mut test_index_counter,
        );
        let expected_data = vec![LayerData {
            name: "sys_write".to_string(),
            value: 300,
            children: [LayerData {
                name: "sys_read".to_string(),
                value: 100,
                children: vec![].to_vec(),
            }]
            .to_vec(),
        }];
        assert_eq!(test_layer_data, expected_data);
    }
}
