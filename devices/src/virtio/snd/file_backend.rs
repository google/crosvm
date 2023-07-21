// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::fs::OpenOptions;
use std::io::Error as IOError;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::Path;

use audio_streams::NoopStreamSourceGenerator;
use audio_util::FileStreamSourceGenerator;
use base::error;
use base::open_file_or_duplicate;
use base::AsRawDescriptor;
use base::RawDescriptor;
use thiserror::Error as ThisError;

use crate::virtio::snd::common_backend::SndData;
use crate::virtio::snd::constants::VIRTIO_SND_D_OUTPUT;
use crate::virtio::snd::parameters::Parameters;
use crate::virtio::snd::sys::SysAudioStreamSourceGenerator;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Failed to allocate space: {0}")]
    AllocateSpace(IOError),
    #[error("Failed to open file: {0}")]
    OpenFile(base::Error),
}

fn allocate_space(mut file: &File, size: usize) -> Result<(), Error> {
    file.seek(SeekFrom::Start(size as u64))
        .map_err(Error::AllocateSpace)?;
    file.write_all(&[0]).map_err(Error::AllocateSpace)?;
    file.seek(SeekFrom::Start(0))
        .map_err(Error::AllocateSpace)?;
    Ok(())
}

fn open_playback_file(dir_path: &String, stream_id: usize) -> Result<File, Error> {
    let file_name = format!("stream-{}.out", stream_id);
    let file_path = Path::new(dir_path).join(file_name);
    let file = open_file_or_duplicate(
        file_path,
        OpenOptions::new().read(true).create(true).write(true),
    )
    .map_err(Error::OpenFile)?;
    Ok(file)
}

pub(crate) fn create_file_stream_source_generators(
    params: &Parameters,
    snd_data: &SndData,
    keep_rds: &mut Vec<RawDescriptor>,
) -> Result<Vec<SysAudioStreamSourceGenerator>, Error> {
    let mut generators = Vec::new();

    for (stream, pcm_info) in snd_data.pcm_info.iter().enumerate() {
        let generator: SysAudioStreamSourceGenerator = if pcm_info.direction == VIRTIO_SND_D_OUTPUT
        {
            let file = open_playback_file(&params.playback_path, stream)?;
            allocate_space(&file, params.playback_size)?;
            keep_rds.push(file.as_raw_descriptor());

            Box::new(FileStreamSourceGenerator::new(file, params.playback_size))
        } else {
            // Capture is not supported yet
            Box::new(NoopStreamSourceGenerator::new())
        };

        generators.push(generator);
    }
    Ok(generators)
}
