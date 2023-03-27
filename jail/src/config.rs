// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;
use serde_keyvalue::FromKeyValues;

fn jail_config_default_pivot_root() -> PathBuf {
    PathBuf::from(option_env!("DEFAULT_PIVOT_ROOT").unwrap_or("/var/empty"))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct JailConfig {
    #[serde(default = "jail_config_default_pivot_root")]
    pub pivot_root: PathBuf,
    #[cfg(unix)]
    #[serde(default)]
    pub seccomp_policy_dir: Option<PathBuf>,
    #[serde(default)]
    pub seccomp_log_failures: bool,
}

impl Default for JailConfig {
    fn default() -> Self {
        JailConfig {
            pivot_root: jail_config_default_pivot_root(),
            #[cfg(unix)]
            seccomp_policy_dir: None,
            seccomp_log_failures: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_keyvalue::from_key_values;

    use super::*;

    #[test]
    fn parse_jailconfig() {
        let config: JailConfig = Default::default();
        assert_eq!(
            config,
            JailConfig {
                pivot_root: jail_config_default_pivot_root(),
                #[cfg(unix)]
                seccomp_policy_dir: None,
                seccomp_log_failures: false,
            }
        );

        let config: JailConfig = from_key_values("").unwrap();
        assert_eq!(config, Default::default());

        let config: JailConfig = from_key_values("pivot-root=/path/to/pivot/root").unwrap();
        assert_eq!(
            config,
            JailConfig {
                pivot_root: "/path/to/pivot/root".into(),
                ..Default::default()
            }
        );

        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                let config: JailConfig =
                    from_key_values("seccomp-policy-dir=/path/to/seccomp/dir").unwrap();
                assert_eq!(config, JailConfig {
                    seccomp_policy_dir: Some("/path/to/seccomp/dir".into()),
                    ..Default::default()
                });
            }
        }

        let config: JailConfig = from_key_values("seccomp-log-failures").unwrap();
        assert_eq!(
            config,
            JailConfig {
                seccomp_log_failures: true,
                ..Default::default()
            }
        );

        let config: JailConfig = from_key_values("seccomp-log-failures=false").unwrap();
        assert_eq!(
            config,
            JailConfig {
                seccomp_log_failures: false,
                ..Default::default()
            }
        );

        let config: JailConfig =
            from_key_values("pivot-root=/path/to/pivot/root,seccomp-log-failures=true").unwrap();
        #[allow(clippy::needless_update)]
        let expected = JailConfig {
            pivot_root: "/path/to/pivot/root".into(),
            seccomp_log_failures: true,
            ..Default::default()
        };
        assert_eq!(config, expected);

        let config: std::result::Result<JailConfig, _> =
            from_key_values("seccomp-log-failures,invalid-arg=value");
        assert!(config.is_err());
    }
}
