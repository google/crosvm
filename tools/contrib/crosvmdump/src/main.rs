// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::env;
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use rayon::prelude::*;

/// The target device running crosvm to collect information from.
struct Target {
    /// SSH host name.
    host: String,
}

impl Target {
    fn do_command(&self, command: Vec<&str>) -> Result<String> {
        let child = Command::new("ssh")
            .arg(&self.host)
            .args(&command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to execute process")?;
        let output = child
            .wait_with_output()
            .context("failed to wait on child")?;
        if !output.status.success() {
            bail!(format!("{:?}: output status: {}", command, output.status));
        }
        Ok(String::from_utf8(output.stdout).context("Failed to convert command output to utf8")?)
    }

    fn get_file(&self, filename: &str) -> Result<String> {
        Ok(self.do_command(vec!["cat", filename])?)
    }

    fn do_fincore(&self, filenames: &Vec<String>) -> Result<Vec<(u64, u64)>> {
        let mut command = vec!["fincore", "--raw", "--bytes"];
        command.extend(filenames.iter().map(|x| &**x));
        parse_fincore(&self.do_command(command)?)
    }
}

fn parse_fincore(text: &str) -> Result<Vec<(u64, u64)>> {
    let mut result = vec![];
    for line in text.lines().skip(1) {
        // res(bytes) pages size filename.
        let mut words = line.split(" ");
        let resident =
            str::parse::<u64>(words.next().context("res")?).context("number from fincore")?;
        let _pages = words.next().context("pages")?;
        let size =
            str::parse::<u64>(words.next().context("size")?).context("number from fincore")?;
        result.push((resident, size));
    }
    Ok(result)
}

// Extract only lines with a number as the second parameter, from /proc/pid/status
fn parse_status(text: &str) -> Result<std::collections::HashMap<&str, u32>> {
    let key_value_iter = text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut split = line.split_whitespace();
            let key = split.next().expect("key");
            if let Ok(value) = str::parse::<u32>(split.next().expect("number")) {
                Some((key, value))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let key_value_map: HashMap<_, _> = HashMap::from_iter(key_value_iter);
    Ok(key_value_map)
}

fn parse_smaps(smaps_rollup_text: &str) -> std::collections::HashMap<&str, u32> {
    let key_value_iter = smaps_rollup_text.lines().skip(1).map(|x| {
        let mut split = x.split_whitespace();
        let key = split.next().expect("key");
        let value = str::parse::<u32>(split.next().unwrap()).expect("kB") * 1024;
        let kb = split.next().unwrap();
        assert!(kb == "kB");
        (key, value)
    });
    let key_value_map: HashMap<_, _> = HashMap::from_iter(key_value_iter);
    key_value_map
}

struct BlockFds<'a> {
    // fd number.
    fd: u32,
    // The file path that the fd points to.
    path: &'a str,
}

fn find_block_fds(proc_fd: &str) -> Vec<BlockFds> {
    proc_fd
        .lines()
        .skip(1)
        .filter_map(|line| {
            let items: Vec<_> = line.split_whitespace().collect();
            assert_eq!(items[9], "->");
            let path = items[10];
            if path.contains("/memfd:")
                || path.contains("/dev/kvm")
                || path.contains("/dev/null")
                || path.contains("/dev/net/")
                || path.contains("/dev/dri/")
                || path.contains("/sys/fs")
                || path == "/"
            {
                None
            } else if path.contains("/") {
                Some(BlockFds {
                    fd: items[8].parse::<u32>().unwrap(),
                    path,
                })
            } else {
                None
            }
        })
        .collect()
}

fn parse_fd_blocks(target: &Target, who: &str, pid: u32) -> Result<()> {
    let lines = target
        .do_command(vec!["ls", "-l", &format!("/proc/{}/fd/", pid)])
        .context("ls -l for proc/fd")?;
    let block_fds = find_block_fds(&lines);
    block_fds.par_iter().for_each(|block_fd| {
        let fdinfo = target.get_file(&format!("/proc/{}/fdinfo/{}", pid, block_fd.fd)).expect("/proc/fdinfo");
        let flags = u32::from_str_radix(parse_proc_fdinfo_flags(&fdinfo), 8).expect("octal");
        let fincore = target.do_fincore(&vec![block_fd.path.to_string()]).unwrap();
        assert_eq!(fincore.len(), 1);

        println!(
            "{} {} {} flags: {:o}  o_direct on x86_64 {}, o_direct on arm {} page cache: {} MB / {} MB",
            who,
            block_fd.path,
            block_fd.fd,
            flags,
            (flags & 0o40000) != 0,
            (flags & 0o200000) != 0,
            fincore[0].0 >> 20,
            fincore[0].1 >> 20,
        );
    });
    Ok(())
}

fn parse_proc_fdinfo_flags(proc_fdinfo: &str) -> &str {
    let lines: HashMap<_, _> = proc_fdinfo
        .lines()
        .map(|line| {
            let mut words = line.split(":");
            (words.next().unwrap(), words.next().unwrap().trim())
        })
        .collect();
    lines["flags"]
}

fn parse_virtio_fs(target: &Target, pid: u32) -> Result<()> {
    let lines = target.do_command(vec!["ls", "-1", &format!("/proc/{}/task/", pid)])?;
    let task_pids: Vec<_> = lines.lines().map(|x| x.parse::<u32>().unwrap()).collect();
    let pid_name_pairs: Vec<_> = task_pids
        .par_iter()
        .map(|task_pid| {
            let comm = target
                .get_file(&format!("/proc/{}/comm", task_pid))
                .unwrap();
            let comm = comm.trim();
            (task_pid, comm.to_string())
        })
        .collect();
    let message = pid_name_pairs
        .iter()
        .map(|(task_pid, comm)| format!("{}:{}", task_pid, comm))
        .collect::<Vec<_>>()
        .join(" ");
    println!("virtio-fs {}", message);
    Ok(())
}

fn main() -> Result<()> {
    // Use a little less than 10 threads globally. 10 sessions is the limit on
    // sshd connection by default as it is on the chromebook.
    rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build_global()
        .unwrap();

    let host = env::args().nth(1).unwrap();
    let target = Target { host: host.clone() };
    while target.do_command(vec!["uname", "-a"]).is_err() {
        println!("Retrying {}", host);
        thread::sleep(Duration::from_millis(1000));
    }
    let crosvm_pid =
        str::parse::<u32>(&target.do_command(vec!["pgrep", "crosvm"]).unwrap().trim()).unwrap();
    let crosvm_cmdline = target.get_file(&format!("/proc/{}/cmdline", crosvm_pid))?;
    let commandline_flags: Vec<_> = crosvm_cmdline.split("\0").collect();

    let mut shared_dir_params = vec![];
    let mut disk_params = vec![];
    let mut socket = "";
    for (i, line) in commandline_flags.iter().enumerate() {
        match *line {
            "--shared-dir" => shared_dir_params.push(commandline_flags[i + 1]),
            "--rwdisk" => disk_params.push(commandline_flags[i + 1]),
            "--disk" => disk_params.push(commandline_flags[i + 1]),
            "--socket" => socket = commandline_flags[i + 1],
            _ => {
                // Skip other flags.
            }
        }
    }
    println!("{:?}", shared_dir_params);
    println!("{:?}", disk_params);

    // Parsed command line for paths to virtio disk blocks. Concierge gives links to /proc/self/fd, translate
    // them to actual end paths after resolving symlinks.
    let disk_blocks: Vec<_> = disk_params
        .par_iter()
        .map(|disk| {
            let block_path_in_proc = disk.split(",").nth(0).unwrap();
            // this would be like /proc/self/fd/26
            assert!(block_path_in_proc.starts_with("/proc/self/fd/"));
            let fd_id =
                str::parse::<u32>(block_path_in_proc.split("/").nth(4).unwrap().trim()).unwrap();
            let disk_block = target
                .do_command(vec![
                    "readlink",
                    &format!("/proc/{}/fd/{}", crosvm_pid, fd_id),
                ])
                .unwrap();
            disk_block.trim().to_string()
        })
        .collect();
    println!("{:?}", disk_blocks);

    // Get fincore stats.
    for (i, (res, size)) in target.do_fincore(&disk_blocks).unwrap().iter().enumerate() {
        println!(
            "fincore {}: {} MB / {} MB",
            disk_blocks[i],
            res >> 20,
            size >> 20
        );
    }

    // Look at fds of crosvm map
    parse_fd_blocks(&target, "crosvm", crosvm_pid)?;

    // find children of the process
    let crosvm_child_pids: Vec<_> = target
        .get_file(&format!(
            "/proc/{}/task/{}/children",
            crosvm_pid, crosvm_pid
        ))?
        .trim()
        .split(" ")
        .map(|x| str::parse::<u32>(x).expect("pid"))
        .collect();

    // Scanning for crosvm child processes
    crosvm_child_pids.par_iter().for_each(|child_pid| {
        let task_name = target
            .get_file(&format!("/proc/{}/comm", child_pid))
            .unwrap()
            .trim()
            .to_string();
        // task/*/comm contains thread names which are useful to tell the device
        // type.  smaps_rollup would be useful, smaps too.
        // values are in kB.
        let smaps_rollup = target
            .get_file(&format!("/proc/{}/smaps_rollup", child_pid))
            .unwrap();
        let parsed_smaps = parse_smaps(&smaps_rollup);
        let dirty = parsed_smaps["Private_Dirty:"];
        let rss = parsed_smaps["Rss:"];
        let status_text = target
            .get_file(&format!("/proc/{}/status", child_pid))
            .unwrap();
        let vmpte_kb = parse_status(&status_text).unwrap()["VmPTE:"];
        // output in MBs.
        println!(
            "{} {} private_dirty: {} MB rss: {} MB VmPTE: {} KiB",
            task_name,
            child_pid,
            dirty >> 20,
            rss >> 20,
            vmpte_kb,
        );

        match task_name.as_str() {
            "pcivirtio-block" => parse_fd_blocks(&target, "virtio-block", *child_pid),
            "pcivirtio-fs" => parse_virtio_fs(&target, *child_pid),
            _ => Ok(()),
        }
        .unwrap();
    });

    let balloon_stat_json = target.do_command(vec!["crosvm", "balloon_stats", socket])?;
    println!("{}", balloon_stat_json);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_smaps_basic() {
        let smaps_rollup_text =
            "55c9706ac000-7fff1d38e000 ---p 00000000 00:00 0                          [rollup]
Rss:                5940 kB
Pss:                 580 kB
Pss_Anon:            367 kB
Pss_File:            213 kB
Pss_Shmem:             0 kB
Shared_Clean:       3760 kB
Shared_Dirty:       1816 kB
Private_Clean:        64 kB
Private_Dirty:       300 kB
Referenced:         4244 kB
Anonymous:          2116 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
";
        let key_value_map = parse_smaps(smaps_rollup_text);
        assert_eq!(key_value_map["Private_Dirty:"], 300 * 1024);
    }

    #[test]
    fn parse_status_basic() -> Result<()> {
        let status_text = "Name:	pcivirtio-block
Umask:	0002
State:	S (sleeping)
Tgid:	22698
Ngid:	0
Pid:	22698
PPid:	22560
TracerPid:	0
Uid:	299	299	299	299
Gid:	299	299	299	299
FDSize:	512
Groups:	27 299 333 400 413 418 600 601 603 20128 20136 20162 
NStgid:	22698	39	1
NSpid:	22698	39	1
NSpgid:	22560	12	0
NSsid:	22142	0	0
VmPeak:	15278960 kB
VmSize:	15213424 kB
VmLck:	       0 kB
VmPin:	       0 kB
VmHWM:	  176796 kB
VmRSS:	  176796 kB
RssAnon:	    2320 kB
RssFile:	    6540 kB
RssShmem:	  167936 kB
VmData:	    3332 kB
VmStk:	     136 kB
VmExe:	   10628 kB
VmLib:	   15436 kB
VmPTE:	     132 kB
VmSwap:	       0 kB
CoreDumping:	0
THP_enabled:	1
Threads:	2
SigQ:	0/63125
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000010000
SigIgn:	0000000000001000
SigCgt:	0000000100000440
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000000000000000
CapAmb:	0000000000000000
NoNewPrivs:	1
Seccomp:	2
Seccomp_filters:	3
Speculation_Store_Bypass:	thread force mitigated
SpeculationIndirectBranch:	conditional force disabled
Cpus_allowed:	fff
Cpus_allowed_list:	0-11
Mems_allowed:	1
Mems_allowed_list:	0
voluntary_ctxt_switches:	533
nonvoluntary_ctxt_switches:	3
";
        let status = parse_status(status_text)?;
        assert_eq!(status["VmPTE:"], 132);
        Ok(())
    }

    #[test]
    fn fincore_test() -> Result<()> {
        let fincore_output =  "RES PAGES SIZE FILE\n474968064 115959 667250688 /opt/google/vms/android/system.raw.img\n10452992 2552 140140544 /opt/google/vms/android/vendor.raw.img\n0 0 0 /dev/null\n0 0 0 /dev/null\n215543808 52623 11468791808 /run/daemon-store/crosvm/8b3488f8d78a9827054a417ae7a4b9bb62586267/YXJjdm0=.img\n";
        parse_fincore(fincore_output)?;
        Ok(())
    }

    #[test]
    fn proc_fd_test() {
        let proc_fd = "total 0
lrwx------. 1 crosvm crosvm 64 Jul 19 09:20 54 -> 'anon_inode:[eventfd]'
lrwx------. 1 crosvm crosvm 64 Jul 19 09:20 55 -> 'anon_inode:[eventfd]'
lrwx------. 1 crosvm crosvm 64 Jul 19 09:20 56 -> 'anon_inode:[eventfd]'
lrwx------. 1 crosvm crosvm 64 Jul 19 09:20 6 -> 'anon_inode:[eventfd]'
lrwx------. 1 crosvm crosvm 64 Jul 19 09:20 7 -> '/memfd:crosvm_guest (deleted)'
lrwx------. 1 crosvm crosvm 64 Jul 19 09:20 8 -> 'anon_inode:[eventfd]'
lr-x------. 1 crosvm crosvm 64 Jul  9 09:20 85 -> /opt/google/vms/android/system.raw.img
lrwx------. 1 crosvm crosvm 64 Jul 19 09:20 9 -> 'anon_inode:[eventfd]'
";

        let v = find_block_fds(proc_fd);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].fd, 85);
        assert_eq!(v[0].path, "/opt/google/vms/android/system.raw.img");
    }

    #[test]
    fn test_fdinfo() {
        let proc_fdinfo = "pos:	0
flags:	0100002
mnt_id:	25
ino:	18
";

        assert_eq!(parse_proc_fdinfo_flags(proc_fdinfo), "0100002");
    }
}
