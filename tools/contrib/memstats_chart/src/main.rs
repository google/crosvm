// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod record;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::channel;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use argh::FromArgs;
use log::info;
use record::*;
use regex::Regex;

// Utilities

fn parse_smaps_rollup(smaps: &str) -> Result<BTreeMap<String, u64>> {
    let re = Regex::new(&format!(r"\n([^:]+):\s*(\d+) kB")).unwrap();
    let mut mp = BTreeMap::new();
    for (_, [key, val]) in re.captures_iter(smaps).map(|c| c.extract()) {
        mp.insert(key.to_string(), val.parse::<u64>().unwrap());
    }
    Ok(mp)
}

fn extract_socket_path(cmdline: &str) -> Result<String> {
    let re = Regex::new(r"(--socket|-s)(\s+|=)(.*?) ").unwrap();
    let sock = re
        .captures(cmdline)
        .with_context(|| anyhow!("regex didn't match: {cmdline}"))?
        .get(3)
        .unwrap()
        .as_str()
        .to_string();
    Ok(sock)
}

#[derive(Debug)]
struct Process {
    pid: u32,
}

impl Process {
    fn new(pid: u32) -> Self {
        Self { pid }
    }

    fn name(&self) -> Result<String> {
        let pid = self.pid;
        let name = fs::read_to_string(format!("/proc/{pid}/comm"))?;
        Ok(name.trim().to_string())
    }

    fn mem_stats(&self) -> Result<ProcRecord> {
        let pid = self.pid;
        let name = self.name()?;
        let content = fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))?;

        let smaps = parse_smaps_rollup(&content)?;

        Ok(ProcRecord { pid, name, smaps })
    }
}

#[derive(Debug)]
struct CrosvmProc {
    proc: Process,
    path: PathBuf,
    sock: String,
    child_procs: Vec<Process>,
}

impl CrosvmProc {
    fn new() -> Result<Self> {
        let output = Command::new("pgrep").args(["crosvm$"]).output()?.stdout;
        let s = std::str::from_utf8(&output)?.trim();
        if s.contains("\n") {
            // TODO: Support multiple VMs
            bail!("multiple crosvm instances are running: {s}");
        }
        if s.is_empty() {
            bail!("no crosvm process found");
        }
        let pid = s.parse::<u32>().context("failed to parse crosvm pid")?;

        let cmdline = fs::read_to_string(format!("/proc/{pid}/cmdline"))?.replace("\0", " ");
        let sock = extract_socket_path(&cmdline).context("failed to extract socket path")?;
        let path = fs::read_link(format!("/proc/{pid}/exe"))?;

        let mut ret = Self {
            proc: Process::new(pid),
            child_procs: vec![],
            sock,
            path,
        };
        ret.update_children()
            .context("failed to update child PIDs")?;
        Ok(ret)
    }

    fn update_children(&mut self) -> Result<()> {
        let pid = self.proc.pid;
        let output = Command::new("pgrep")
            .args(["-P", &pid.to_string()])
            .output()?
            .stdout;
        let child_procs = std::str::from_utf8(&output)?
            .trim()
            .split("\n")
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<u32>().map(Process::new))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        self.child_procs = child_procs;
        Ok(())
    }

    fn balloon_stats(&self) -> Result<BalloonStats> {
        let output = Command::new(self.path.to_str().unwrap())
            .args(["balloon_stats", &self.sock])
            .output()?
            .stdout;
        let s = std::str::from_utf8(&output)?.trim();
        let stats: BTreeMap<String, BalloonStats> = serde_json::from_str(s)?;
        Ok(stats.get("BalloonStats").unwrap().to_owned())
    }

    fn get_record(&mut self, timestamp: u64) -> Result<Record> {
        self.update_children()?;

        let mut stats = vec![];
        stats.push(self.proc.mem_stats()?);
        for pid in &self.child_procs {
            stats.push(pid.mem_stats()?);
        }

        let balloon_stats = self.balloon_stats().ok();

        Ok(Record {
            timestamp,
            stats,
            balloon_stats,
        })
    }
}

#[derive(FromArgs)]
/// Argument
struct Args {
    /// duration in second.
    /// If it's not specified, it runs until Ctrl-C is sent.
    #[argh(option, short = 'd')]
    duration: Option<u64>,
    /// output JSON file path.
    #[argh(option, short = 'o')]
    output: String,
}

fn wait_for_crosvm() -> CrosvmProc {
    let interval = Duration::from_millis(100);
    let mut cnt = 0;
    loop {
        match CrosvmProc::new() {
            Ok(crosvm) => {
                return crosvm;
            }
            Err(e) => {
                if cnt % 10 == 0 {
                    info!("waiting for crosvm starting: {:#}", e);
                }
            }
        }
        cnt += 1;
        std::thread::sleep(interval);
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter(None, log::LevelFilter::Info)
        .init();

    let args: Args = argh::from_env();

    let mut crosvm = wait_for_crosvm();
    info!("crosvm process found");

    let mut stats = vec![];

    let start_time = std::time::Instant::now();

    let (tx, rx) = channel();
    ctrlc::set_handler(move || {
        println!("Ctrl-C is pressed");
        tx.send(()).expect("Could not send signal on channel.")
    })
    .expect("Error setting Ctrl-C handler");

    let timeout = match args.duration {
        Some(sec) => {
            info!("Collect data for {sec} seconds (or until Ctrl-C is sent)");
            sec
        }
        None => {
            info!("Collect data until Ctrl-C is sent");
            u64::MAX
        }
    };

    for ts in 0..timeout {
        if let Ok(()) = rx.try_recv() {
            println!("stop recording");
            break;
        }
        info!("timestamp: {ts} seconds");
        let rec = match crosvm.get_record(ts) {
            Ok(r) => r,
            Err(_) => {
                info!("crosvm process has gone");
                break;
            }
        };
        stats.push(rec);

        let now = std::time::Instant::now();
        let dur = start_time + Duration::from_secs(ts + 1) - now;
        std::thread::sleep(dur);
    }

    let json = serde_json::to_string(&stats)?;
    let result_path = args.output;
    std::fs::write(&result_path, json)?;
    println!("Wrote results to {result_path}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_smaps_rollup() {
        let smaps = r"5561ed990000-ffffffffff601000 ---p 00000000 00:00 0                      [rollup]
Rss:              391088 kB
Pss:              380165 kB
Pss_Anon:            270 kB
Pss_File:           1350 kB
Pss_Shmem:        378543 kB
Shared_Clean:       4016 kB
Shared_Dirty:      14788 kB
Private_Clean:       628 kB
Private_Dirty:    371656 kB
Referenced:       389220 kB
Anonymous:           344 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:             836004 kB
SwapPss:             396 kB
Locked:                0 kB
";

        let m = parse_smaps_rollup(smaps).unwrap();
        assert_eq!(m.get("Rss"), Some(&391088));
        assert_eq!(m.get("Pss"), Some(&380165));
        assert_eq!(m.get("Pss_Anon"), Some(&270));
        assert_eq!(m.get("Pss_Shmem"), Some(&378543));
        assert_eq!(m.get("Shared_Clean"), Some(&4016));
        assert_eq!(m.get("Shared_Dirty"), Some(&14788));
        assert_eq!(m.get("Locked"), Some(&0));
    }

    #[test]
    fn test_extract_socket_path() {
        const EXPECTED_SOCK_PATH: &str = "/path/to/crosvm.sock";
        let cmd = format!("crosvm run --socket {EXPECTED_SOCK_PATH} vmlinux");
        assert_eq!(extract_socket_path(&cmd).unwrap(), EXPECTED_SOCK_PATH);

        let cmd = format!("crosvm run --socket={EXPECTED_SOCK_PATH} vmlinux");
        assert_eq!(extract_socket_path(&cmd).unwrap(), EXPECTED_SOCK_PATH);

        let cmd = format!("crosvm run -s {EXPECTED_SOCK_PATH} vmlinux");
        assert_eq!(extract_socket_path(&cmd).unwrap(), EXPECTED_SOCK_PATH);

        let cmd = format!("crosvm run -s={EXPECTED_SOCK_PATH} vmlinux");
        assert_eq!(extract_socket_path(&cmd).unwrap(), EXPECTED_SOCK_PATH);
    }
}
