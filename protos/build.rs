// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::error::Error;
use std::path::PathBuf;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct LocalProto {
    // Corresponding to the input file src/$module.proto.
    module: &'static str,
}

static LOCAL_PROTOS: &[LocalProto] = &[
    #[cfg(feature = "plugin")]
    LocalProto { module: "plugin" },
    #[cfg(feature = "composite-disk")]
    LocalProto {
        module: "cdisk_spec",
    },
];

fn main() -> Result<()> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    // Compile protos from the local src directory.
    let mut proto_paths = Vec::new();
    for proto in LOCAL_PROTOS {
        proto_paths.push(
            ["src", &format!("{}.proto", proto.module)]
                .iter()
                .collect::<PathBuf>(),
        );
    }
    proto_build_tools::build_protos(&out_dir, proto_paths.as_slice());

    Ok(())
}
