# Audio Server and Stream interfaces

The `audio_streams` crate provides a basic interface for playing audio.
This will be used to enable playback to various audio subsystems such as
Alsa and cras. To start, an empty playback example `NoopStreamSource`
is provided.
