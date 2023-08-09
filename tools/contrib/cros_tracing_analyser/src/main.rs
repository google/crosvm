// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use argh::FromArgs;
use libtracecmd::Event;
use libtracecmd::Handler;
use libtracecmd::Input;
use libtracecmd::Record;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Write;

#[derive(FromArgs, Debug)]
/// Command line parameters.
struct Config {
    #[argh(option)]
    /// path to the input .dat file
    input: String,
    #[argh(option)]
    /// path to the output .json file
    output: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EventInformation {
    pid: i32,
    cpu: i32,
    name: String,
    time_stamp: u64,
    details: String,
}

#[derive(Default, Debug, Serialize, Deserialize)]
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

fn main() {
    let cfg: Config = argh::from_env();
    let input = cfg.input.clone();
    let mut input = Input::new(&input).expect("input is invalid");

    let mut stats = HandlerImplement::process(&mut input).unwrap();
    stats.populate_event_names();
    let average_data = stats.calculate_function_time();
    let output = cfg.output.clone();
    let mut fout = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(&output)
        .unwrap();
    let serialized = serde_json::to_string(&average_data).unwrap();
    fout.write_all(serialized.as_bytes());
}
