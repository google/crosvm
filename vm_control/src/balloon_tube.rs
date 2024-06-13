// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Balloon related control APIs.

use std::collections::VecDeque;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use balloon_control::BalloonTubeCommand;
use balloon_control::BalloonTubeResult;
use base::error;
use base::Error as SysError;
use base::Tube;
use serde::Deserialize;
use serde::Serialize;

use crate::VmResponse;

// Balloon commands that are sent on the crosvm control socket.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BalloonControlCommand {
    /// Set the size of the VM's balloon.
    Adjust {
        num_bytes: u64,
        wait_for_success: bool,
    },
    Stats,
    WorkingSet,
    WorkingSetConfig {
        bins: Vec<u32>,
        refresh_threshold: u32,
        report_threshold: u32,
    },
}

fn do_send(tube: &Tube, cmd: &BalloonControlCommand) -> Option<VmResponse> {
    match *cmd {
        BalloonControlCommand::Adjust {
            num_bytes,
            wait_for_success,
        } => {
            match tube.send(&BalloonTubeCommand::Adjust {
                num_bytes,
                allow_failure: wait_for_success,
            }) {
                Ok(_) => {
                    if wait_for_success {
                        None
                    } else {
                        Some(VmResponse::Ok)
                    }
                }
                Err(_) => Some(VmResponse::Err(SysError::last())),
            }
        }
        BalloonControlCommand::WorkingSetConfig {
            ref bins,
            refresh_threshold,
            report_threshold,
        } => {
            match tube.send(&BalloonTubeCommand::WorkingSetConfig {
                bins: bins.clone(),
                refresh_threshold,
                report_threshold,
            }) {
                Ok(_) => Some(VmResponse::Ok),
                Err(_) => Some(VmResponse::Err(SysError::last())),
            }
        }
        BalloonControlCommand::Stats => match tube.send(&BalloonTubeCommand::Stats) {
            Ok(_) => None,
            Err(_) => Some(VmResponse::Err(SysError::last())),
        },
        BalloonControlCommand::WorkingSet => match tube.send(&BalloonTubeCommand::WorkingSet) {
            Ok(_) => None,
            Err(_) => Some(VmResponse::Err(SysError::last())),
        },
    }
}

/// Utility for multiplexing a balloon tube between multiple control tubes. Commands
/// are sent and processed serially.
pub struct BalloonTube {
    tube: Tube,
    pending_queue: VecDeque<(BalloonControlCommand, Option<usize>)>,
    pending_adjust_with_completion: Option<(u64, usize)>,
}

impl BalloonTube {
    pub fn new(tube: Tube) -> Self {
        BalloonTube {
            tube,
            pending_queue: VecDeque::new(),
            pending_adjust_with_completion: None,
        }
    }

    /// Sends or queues the given command to this tube. Associates the
    /// response with the given key.
    pub fn send_cmd(
        &mut self,
        cmd: BalloonControlCommand,
        key: Option<usize>,
    ) -> Option<(VmResponse, usize)> {
        match cmd {
            BalloonControlCommand::Adjust {
                wait_for_success: true,
                num_bytes,
            } => {
                let Some(key) = key else {
                    error!("Asked for completion without reply key");
                    return None;
                };
                let resp = self
                    .pending_adjust_with_completion
                    .take()
                    .map(|(_, key)| (VmResponse::ErrString("Adjust overriden".to_string()), key));
                if do_send(&self.tube, &cmd).is_some() {
                    unreachable!("Unexpected early reply");
                }
                self.pending_adjust_with_completion = Some((num_bytes, key));
                resp
            }
            _ => {
                if !self.pending_queue.is_empty() {
                    self.pending_queue.push_back((cmd, key));
                    return None;
                }
                let resp = do_send(&self.tube, &cmd);
                if resp.is_none() {
                    self.pending_queue.push_back((cmd, key));
                }
                match key {
                    None => None,
                    Some(key) => resp.map(|r| (r, key)),
                }
            }
        }
    }

    /// Receives responses from the balloon tube, and returns them with
    /// their assoicated keys.
    pub fn recv(&mut self) -> Result<Vec<(VmResponse, usize)>> {
        let res = self
            .tube
            .recv::<BalloonTubeResult>()
            .context("failed to read balloon tube")?;
        if let BalloonTubeResult::Adjusted { num_bytes: actual } = res {
            let Some((target, key)) = self.pending_adjust_with_completion else {
                bail!("Unexpected balloon adjust to {}", actual);
            };
            if actual != target {
                return Ok(vec![]);
            }
            self.pending_adjust_with_completion.take();
            return Ok(vec![(VmResponse::Ok, key)]);
        }
        let mut responses = vec![];
        if self.pending_queue.is_empty() {
            bail!("Unexpected balloon tube result {:?}", res)
        }
        let resp = match (
            &self.pending_queue.front().expect("entry disappeared").0,
            res,
        ) {
            (
                BalloonControlCommand::Stats,
                BalloonTubeResult::Stats {
                    stats,
                    balloon_actual,
                },
            ) => VmResponse::BalloonStats {
                stats,
                balloon_actual,
            },
            (
                BalloonControlCommand::WorkingSet,
                BalloonTubeResult::WorkingSet { ws, balloon_actual },
            ) => VmResponse::BalloonWS { ws, balloon_actual },
            (_, resp) => {
                bail!("Unexpected balloon tube result {:?}", resp);
            }
        };
        let key = self.pending_queue.pop_front().expect("entry disappeared").1;
        if let Some(key) = key {
            responses.push((resp, key))
        }
        while let Some((cmd, key)) = self.pending_queue.front() {
            match do_send(&self.tube, cmd) {
                Some(resp) => {
                    if let Some(key) = key {
                        responses.push((resp, *key));
                    }
                    self.pending_queue.pop_front();
                }
                None => break,
            }
        }
        Ok(responses)
    }
}

#[cfg(test)]
mod tests {
    use balloon_control::BalloonStats;

    use super::*;

    fn balloon_device_respond_stats(device: &Tube) {
        let BalloonTubeCommand::Stats = device.recv::<BalloonTubeCommand>().unwrap() else {
            panic!("unexpected command");
        };

        device
            .send(&BalloonTubeResult::Stats {
                stats: BalloonStats::default(),
                balloon_actual: 0,
            })
            .unwrap();
    }

    #[test]
    fn test_stat_command() {
        let (host, device) = Tube::pair().unwrap();
        let mut balloon_tube = BalloonTube::new(host);

        let resp = balloon_tube.send_cmd(BalloonControlCommand::Stats, Some(0xc0ffee));
        assert!(resp.is_none());

        balloon_device_respond_stats(&device);

        let resp = balloon_tube.recv().unwrap();
        assert_eq!(resp.len(), 1);
        assert_eq!(resp[0].1, 0xc0ffee);
        assert!(matches!(resp[0].0, VmResponse::BalloonStats { .. }));
    }

    #[test]
    fn test_multiple_stat_command() {
        let (host, device) = Tube::pair().unwrap();
        let mut balloon_tube = BalloonTube::new(host);

        let resp = balloon_tube.send_cmd(BalloonControlCommand::Stats, Some(0xc0ffee));
        assert!(resp.is_none());
        let resp = balloon_tube.send_cmd(BalloonControlCommand::Stats, Some(0xbadcafe));
        assert!(resp.is_none());

        balloon_device_respond_stats(&device);

        let resp = balloon_tube.recv().unwrap();
        assert_eq!(resp.len(), 1);
        assert_eq!(resp[0].1, 0xc0ffee);
        assert!(matches!(resp[0].0, VmResponse::BalloonStats { .. }));

        balloon_device_respond_stats(&device);

        let resp = balloon_tube.recv().unwrap();
        assert_eq!(resp.len(), 1);
        assert_eq!(resp[0].1, 0xbadcafe);
        assert!(matches!(resp[0].0, VmResponse::BalloonStats { .. }));
    }

    #[test]
    fn test_queued_stats_adjust_no_reply() {
        let (host, device) = Tube::pair().unwrap();
        let mut balloon_tube = BalloonTube::new(host);

        let resp = balloon_tube.send_cmd(BalloonControlCommand::Stats, Some(0xc0ffee));
        assert!(resp.is_none());
        let resp = balloon_tube.send_cmd(
            BalloonControlCommand::Adjust {
                num_bytes: 0,
                wait_for_success: false,
            },
            Some(0xbadcafe),
        );
        assert!(resp.is_none());

        balloon_device_respond_stats(&device);

        let resp = balloon_tube.recv().unwrap();
        assert_eq!(resp.len(), 2);
        assert_eq!(resp[0].1, 0xc0ffee);
        assert!(matches!(resp[0].0, VmResponse::BalloonStats { .. }));
        assert_eq!(resp[1].1, 0xbadcafe);
        assert!(matches!(resp[1].0, VmResponse::Ok));

        let cmd = device.recv::<BalloonTubeCommand>().unwrap();
        assert!(matches!(cmd, BalloonTubeCommand::Adjust { .. }));
    }

    #[test]
    fn test_adjust_with_reply() {
        let (host, device) = Tube::pair().unwrap();
        let mut balloon_tube = BalloonTube::new(host);

        let resp = balloon_tube.send_cmd(
            BalloonControlCommand::Adjust {
                num_bytes: 0xc0ffee,
                wait_for_success: true,
            },
            Some(0xc0ffee),
        );
        assert!(resp.is_none());
        let cmd = device.recv::<BalloonTubeCommand>().unwrap();
        assert!(matches!(cmd, BalloonTubeCommand::Adjust { .. }));

        let resp = balloon_tube.send_cmd(
            BalloonControlCommand::Adjust {
                num_bytes: 0xbadcafe,
                wait_for_success: true,
            },
            Some(0xbadcafe),
        );
        assert!(matches!(resp, Some((VmResponse::ErrString(_), 0xc0ffee))));
        let cmd = device.recv::<BalloonTubeCommand>().unwrap();
        assert!(matches!(cmd, BalloonTubeCommand::Adjust { .. }));

        device
            .send(&BalloonTubeResult::Adjusted {
                num_bytes: 0xc0ffee,
            })
            .unwrap();
        let resp = balloon_tube.recv().unwrap();
        assert_eq!(resp.len(), 0);

        device
            .send(&BalloonTubeResult::Adjusted {
                num_bytes: 0xbadcafe,
            })
            .unwrap();
        let resp = balloon_tube.recv().unwrap();
        assert_eq!(resp.len(), 1);
        assert_eq!(resp[0].1, 0xbadcafe);
        assert!(matches!(resp[0].0, VmResponse::Ok));
    }

    #[test]
    fn test_stats_and_adjust_with_reply() {
        let (host, device) = Tube::pair().unwrap();
        let mut balloon_tube = BalloonTube::new(host);

        let resp = balloon_tube.send_cmd(BalloonControlCommand::Stats, Some(0xc0ffee));
        assert!(resp.is_none());

        let resp = balloon_tube.send_cmd(
            BalloonControlCommand::Adjust {
                num_bytes: 0xbadcafe,
                wait_for_success: true,
            },
            Some(0xbadcafe),
        );
        assert!(resp.is_none());

        let cmd = device.recv::<BalloonTubeCommand>().unwrap();
        assert!(matches!(cmd, BalloonTubeCommand::Stats));
        let cmd = device.recv::<BalloonTubeCommand>().unwrap();
        assert!(matches!(cmd, BalloonTubeCommand::Adjust { .. }));

        device
            .send(&BalloonTubeResult::Adjusted {
                num_bytes: 0xbadcafe,
            })
            .unwrap();
        let resp = balloon_tube.recv().unwrap();
        assert_eq!(resp.len(), 1);
        assert_eq!(resp[0].1, 0xbadcafe);
        assert!(matches!(resp[0].0, VmResponse::Ok));

        device
            .send(&BalloonTubeResult::Stats {
                stats: BalloonStats::default(),
                balloon_actual: 0,
            })
            .unwrap();
        let resp = balloon_tube.recv().unwrap();
        assert_eq!(resp.len(), 1);
        assert_eq!(resp[0].1, 0xc0ffee);
        assert!(matches!(resp[0].0, VmResponse::BalloonStats { .. }));
    }
}
