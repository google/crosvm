// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::time::Instant;

use audio_streams::*;
use cros_async::Executor;

mod args;
mod error;
mod performance_data;
mod sys;

use crate::args::*;
use crate::error::Error;
use crate::error::Result;
use crate::performance_data::*;
use crate::sys::create_stream_source_generator as sys_create_stream_source_generators;

fn create_stream_source_generators(args: &Args) -> Box<dyn StreamSourceGenerator> {
    match args.stream_source {
        StreamSourceEnum::NoopStream => Box::new(NoopStreamSourceGenerator::new()),
        StreamSourceEnum::Sys(stream_source) => {
            sys_create_stream_source_generators(stream_source, args)
        }
    }
}

async fn run_playback(ex: &Executor, args: &Args) -> Result<PerformanceData> {
    let mut data = PerformanceData::default();
    let generator: Box<dyn StreamSourceGenerator> = create_stream_source_generators(args);
    let num_channels = args.channels;
    let format = args.format;
    let frame_rate = args.rate;
    let buffer_size = args.buffer_frames;
    let iterations = args.iterations;

    let mut stream_source = generator.generate().map_err(Error::GenerateStreamSource)?;
    let start = Instant::now();
    let (_, mut stream) = stream_source
        .new_async_playback_stream(num_channels, format, frame_rate, buffer_size, ex)
        .map_err(Error::CreateStream)?;
    data.cold_start = start.elapsed();
    let frame_size = args.format.sample_bytes() * args.channels;

    let start = Instant::now();
    let mut frames_played = 0;
    for _ in 0..iterations {
        let mut stream_buffer = stream
            .next_playback_buffer(ex)
            .await
            .map_err(Error::FetchBuffer)?;
        let bytes = stream_buffer
            .copy_from(&mut io::repeat(0))
            .map_err(Error::WriteBuffer)?;
        stream_buffer.commit().await;
        frames_played += bytes / frame_size;
        data.records
            .push(BufferConsumptionRecord::new(frames_played, start.elapsed()));
    }
    Ok(data)
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();
    let ex = Executor::new().expect("Failed to create an executor");
    let done = run_playback(&ex, &args);

    match ex.run_until(done) {
        Ok(Ok(data)) => {
            let report = data.gen_report(args)?;
            if args.debug {
                data.print_records();
            }
            if args.json {
                println!("{}", serde_json::to_string(&report)?);
            } else {
                print!("{}", report);
            }
        }
        Ok(Err(e)) => eprintln!("{}", e),
        Err(e) => eprintln!("Error happened in executor: {}", e),
    }
    Ok(())
}
