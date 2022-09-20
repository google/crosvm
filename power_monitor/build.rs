// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

fn main() {
    #[cfg(feature = "powerd")]
    {
        extern crate protoc_rust;

        use std::env;
        use std::fmt::Write as FmtWrite;
        use std::fs;
        use std::io::Write;
        use std::path::Path;
        use std::path::PathBuf;

        fn paths_to_strs<P: AsRef<Path>>(paths: &[P]) -> Vec<&str> {
            paths
                .iter()
                .map(|p| p.as_ref().as_os_str().to_str().unwrap())
                .collect()
        }

        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let power_manager_dir = match env::var("SYSROOT") {
            Ok(dir) => PathBuf::from(dir).join("usr/include/chromeos/dbus/power_manager"),
            // Use local copy of proto file when building upstream
            Err(_) => PathBuf::from("."),
        };

        let input_files = [power_manager_dir.join("power_supply_properties.proto")];
        let include_dirs = [power_manager_dir];

        protoc_rust::Codegen::new()
            .inputs(&paths_to_strs(&input_files))
            .includes(&paths_to_strs(&include_dirs))
            .out_dir(out_dir.as_os_str().to_str().unwrap())
            .run()
            .expect("protoc");

        let mut path_include_mods = String::new();
        for input_file in input_files.iter() {
            let stem = input_file.file_stem().unwrap().to_str().unwrap();
            let mod_path = out_dir.join(format!("{}.rs", stem));
            writeln!(
                &mut path_include_mods,
                "#[path = \"{}\"]",
                mod_path.display()
            )
            .unwrap();
            writeln!(&mut path_include_mods, "pub mod {};", stem).unwrap();
        }

        let mut mod_out = fs::File::create(out_dir.join("powerd_proto.rs")).unwrap();
        writeln!(mod_out, "pub mod system_api {{\n{}}}", path_include_mods).unwrap();
    }
}
