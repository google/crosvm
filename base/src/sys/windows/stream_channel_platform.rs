// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::io;
use std::sync::Arc;

use log::error;
use log::warn;
use serde::ser::SerializeStruct;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
use sync::Mutex;

use super::named_pipes;
use super::named_pipes::PipeConnection;
use super::stream_channel::BlockingMode;
use super::stream_channel::FramingMode;
use super::MultiProcessMutex;
use super::PlatformEvent;
use super::RawDescriptor;
use super::Result;
use crate::descriptor::AsRawDescriptor;
use crate::CloseNotifier;
use crate::ReadNotifier;

impl From<FramingMode> for named_pipes::FramingMode {
    fn from(framing_mode: FramingMode) -> Self {
        match framing_mode {
            FramingMode::Message => named_pipes::FramingMode::Message,
            FramingMode::Byte => named_pipes::FramingMode::Byte,
        }
    }
}

impl From<BlockingMode> for named_pipes::BlockingMode {
    fn from(blocking_mode: BlockingMode) -> Self {
        match blocking_mode {
            BlockingMode::Blocking => named_pipes::BlockingMode::Wait,
            BlockingMode::Nonblocking => named_pipes::BlockingMode::NoWait,
        }
    }
}

pub const DEFAULT_BUFFER_SIZE: usize = 50 * 1024;

/// An abstraction over named pipes and unix socketpairs.
///
/// The ReadNotifier will return an event handle that is set when data is in the channel.
///
/// In message mode, single writes larger than
/// `crate::platform::named_pipes::DEFAULT_BUFFER_SIZE` are not permitted.
///
/// # Notes for maintainers
/// 1. This struct contains extremely subtle thread safety considerations.
/// 2. Serialization is not derived! New fields need to be added manually.
#[derive(Deserialize, Debug)]
pub struct StreamChannel {
    pipe_conn: named_pipes::PipeConnection,
    write_notify: PlatformEvent,
    read_notify: PlatformEvent,
    pipe_closed: PlatformEvent,

    // Held when reading on this end, to prevent additional writes from corrupting notification
    // state.
    remote_write_lock: MultiProcessMutex,

    // Held when a write is made on this end, so that if the remote end is reading, we wait to
    // write to avoid corrupting notification state.
    local_write_lock: MultiProcessMutex,

    // Held for the entire duration of a read. This enables the StreamChannel to be sync,
    // ensuring there is no chance of concurrent reads creating a bad state in StreamChannel.
    //
    // In practice, there is no use-case for multiple threads actually contending over
    // reading from a single pipe through StreamChannel, so this is mostly to provide a
    // compiler guarantee while passing the StreamChannel to/from background executors.
    //
    // Note that this mutex does not work across processes, so the same StreamChannel end should
    // NOT be concurrently used across process boundaries. (Odds are if you want to do this, it's
    // not what you want. Wanting this means you want two readers on the *same end* of the pipe,
    // which is not well defined behavior.)
    #[serde(skip)]
    #[serde(default = "create_read_lock")]
    read_lock: Arc<Mutex<()>>,

    // Serde only has an immutable reference. Because of that, we have to cheat to signal when this
    // channel end has been serialized. Once serialized, we know that the current end MUST NOT
    // signal the channel has been closed when it was dropped, because a copy of it was sent to
    // another process. It is the copy's responsibility to close the pipe.
    #[serde(skip)]
    #[serde(default = "create_true_cell")]
    is_channel_closed_on_drop: RefCell<bool>,

    // For StreamChannels created via pair_with_buffer_size, allows the channel to accept messages
    // up to that size.
    send_buffer_size: usize,
}

fn create_read_lock() -> Arc<Mutex<()>> {
    Arc::new(Mutex::new(()))
}

fn create_true_cell() -> RefCell<bool> {
    RefCell::new(true)
}

/// Serialize is manually implemented because we need to tell the local copy that a remote copy
/// exists, and to not send the close event. Our serialization is otherwise identical to what
/// derive would have generated.
impl Serialize for StreamChannel {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("StreamChannel", 7)?;
        s.serialize_field("pipe_conn", &self.pipe_conn)?;
        s.serialize_field("write_notify", &self.write_notify)?;
        s.serialize_field("read_notify", &self.read_notify)?;
        s.serialize_field("pipe_closed", &self.pipe_closed)?;
        s.serialize_field("remote_write_lock", &self.remote_write_lock)?;
        s.serialize_field("local_write_lock", &self.local_write_lock)?;
        s.serialize_field("send_buffer_size", &self.send_buffer_size)?;
        let ret = s.end();

        // Because this end has been serialized, the serialized copy is now responsible for setting
        // the close event.
        if ret.is_ok() {
            *self.is_channel_closed_on_drop.borrow_mut() = false;
        }

        ret
    }
}

impl Drop for StreamChannel {
    fn drop(&mut self) {
        if *self.is_channel_closed_on_drop.borrow() {
            if let Err(e) = self.pipe_closed.write(0) {
                warn!("failed to notify on channel drop: {}", e);
            }
        }
    }
}

impl StreamChannel {
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        // Safe because the pipe is open.
        if nonblocking {
            self.pipe_conn
                .set_blocking(&named_pipes::BlockingMode::NoWait)
        } else {
            self.pipe_conn
                .set_blocking(&named_pipes::BlockingMode::Wait)
        }
    }

    // WARNING: Generally, multiple StreamChannel ends are not wanted. StreamChannel behavior with
    // > 1 reader per end is not defined.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(StreamChannel {
            pipe_conn: self.pipe_conn.try_clone()?,
            write_notify: self.write_notify.try_clone()?,
            read_notify: self.read_notify.try_clone()?,
            pipe_closed: self.pipe_closed.try_clone()?,
            remote_write_lock: self.remote_write_lock.try_clone()?,
            local_write_lock: self.local_write_lock.try_clone()?,
            read_lock: self.read_lock.clone(),
            is_channel_closed_on_drop: create_true_cell(),
            send_buffer_size: self.send_buffer_size,
        })
    }

    fn get_readable_byte_count(&self) -> io::Result<u32> {
        self.pipe_conn.get_available_byte_count().map_err(|e| {
            error!("StreamChannel failed to get readable byte count: {}", e);
            e
        })
    }

    pub(super) fn inner_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        // We ensure concurrent read safety by holding a lock for the duration of the method.
        // (If multiple concurrent readers were permitted, the pipe could be emptied after we decide
        // that the notifier should be set, leading to an invalid notified/readable state which
        // could stall readers.)
        let _read_lock = self.read_lock.lock();

        let res = unsafe {
            // Safe because no partial reads are possible, and the underlying code bounds the
            // read by buf's size.
            self.pipe_conn.read(buf)
        };

        // The entire goal of this complex section is to avoid the need for shared memory between
        // each channel end to synchronize the notification state. It is very subtle, modify with
        // care.
        loop {
            // No other thread is reading, so we can find out, without the write lock, whether or
            // not we need to clear the read notifier. If we don't, then we don't even have to try
            // acquiring the write lock. This avoids deadlocks where the pipe is full and the write
            // side blocks on a writing with the lock held. If it looks like we do need to clear
            // the notifier though, then we have to be sure, so we'll proceed to the next section.
            let byte_count = self.get_readable_byte_count()?;
            if byte_count > 0 {
                // It's always safe to set the read notifier here because we know there is data in the
                // pipe, and no one else could read it out from under us.
                self.read_notify.write(0).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("failed to write to read notifier: {:?}", e),
                    )
                })?;

                // Notifier state has been safely synced.
                return res;
            }

            // At this point, there *may* be no data in the pipe, meaning we may want to clear the
            // notifier. Instead of just trying to acquire the lock outright which could deadlock
            // with the writing side, we'll try with a timeout. If it fails, we know that the other
            // side is in the middle of a write, so there either will be data in the pipe soon (a),
            // or there won't be and we have to clear a spurious notification (b).
            //
            // For (a), we can safely return from the read without needing the lock, so we just come
            // around in the loop to check again, and the loop will exit quickly.
            //
            // For (b) we'll return to this point and acquire the lock, as we're just waiting for
            // the spurious notification to arrive so we can clear it (that code path is very fast),
            // and the loop will exit.
            //
            // If we successfully acquire the lock though, then we can go ahead and clear the
            // notifier if the pipe is indeed empty, because we are assured that no writes are
            // happening (we hold the lock). Here, we wait up to 1ms to acquire the lock because
            // that's a decent balance between avoiding an unnecessary iteration, and minimizing
            // latency.
            if let Some(_write_lock) = self.remote_write_lock.try_lock(/* timeout_ms= */ 1) {
                let byte_count = self.get_readable_byte_count()?;
                if byte_count > 0 {
                    // Safe because no one else can be reading from the pipe.
                    self.read_notify.write(0).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("failed to write to read notifier: {:?}", e),
                        )
                    })?;
                } else {
                    // Safe because no other writes can be happening (_lock is held).
                    self.read_notify.reset().map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("failed to reset read notifier: {:?}", e),
                        )
                    })?;
                }

                // Notifier state has been safely synced.
                return res;
            }
        }
    }

    /// Exists as a workaround for Tube which does not expect its transport to be mutable,
    /// even though io::Write requires it.
    pub fn write_immutable(&self, buf: &[u8]) -> io::Result<usize> {
        if self.pipe_conn.get_framing_mode() == named_pipes::FramingMode::Message
            && buf.len() > self.send_buffer_size
        {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "StreamChannel forbids message mode writes larger than the \
                     default buffer size of {}.",
                    self.send_buffer_size,
                ),
            ));
        }

        let _lock = self.local_write_lock.lock();
        let res = self.pipe_conn.write(buf);

        // We can always set the write notifier because we know that the reader is in one of the
        // following states:
        //      1) a read is running, and it consumes these bytes, so the notification is
        //         unnecessary. That's fine, because the reader will resync the notifier state once
        //         it finishes reading.
        //      2) a read has completed and is blocked on the lock. The notification state is
        //         already correct, and the read's resync won't change that.
        if res.is_ok() {
            self.write_notify.write(0).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to write to read notifier: {:?}", e),
                )
            })?;
        }

        res
    }

    /// This only works with empty pipes. U.B. will result if used in any other scenario.
    pub fn from_pipes(
        pipe_a: PipeConnection,
        pipe_b: PipeConnection,
        send_buffer_size: usize,
    ) -> Result<(StreamChannel, StreamChannel)> {
        let (notify_a_write, notify_b_write) = (PlatformEvent::new()?, PlatformEvent::new()?);
        let pipe_closed = PlatformEvent::new()?;

        let write_lock_a = MultiProcessMutex::new()?;
        let write_lock_b = MultiProcessMutex::new()?;

        let sock_a = StreamChannel {
            pipe_conn: pipe_a,
            write_notify: notify_a_write.try_clone()?,
            read_notify: notify_b_write.try_clone()?,
            read_lock: Arc::new(Mutex::new(())),
            local_write_lock: write_lock_a.try_clone()?,
            remote_write_lock: write_lock_b.try_clone()?,
            pipe_closed: pipe_closed.try_clone()?,
            is_channel_closed_on_drop: create_true_cell(),
            send_buffer_size,
        };
        let sock_b = StreamChannel {
            pipe_conn: pipe_b,
            write_notify: notify_b_write,
            read_notify: notify_a_write,
            read_lock: Arc::new(Mutex::new(())),
            local_write_lock: write_lock_b,
            remote_write_lock: write_lock_a,
            pipe_closed,
            is_channel_closed_on_drop: create_true_cell(),
            send_buffer_size,
        };
        Ok((sock_a, sock_b))
    }

    /// Create a pair with a specific buffer size. Note that this is the only way to send messages
    /// larger than the default named pipe buffer size.
    pub fn pair_with_buffer_size(
        blocking_mode: BlockingMode,
        framing_mode: FramingMode,
        buffer_size: usize,
    ) -> Result<(StreamChannel, StreamChannel)> {
        let (pipe_a, pipe_b) = named_pipes::pair_with_buffer_size(
            &named_pipes::FramingMode::from(framing_mode),
            &named_pipes::BlockingMode::from(blocking_mode),
            0,
            buffer_size,
            false,
        )?;
        Self::from_pipes(pipe_a, pipe_b, buffer_size)
    }
    /// Creates a cross platform channel pair.
    /// On Windows the result is in the form (server, client).
    pub fn pair(
        blocking_mode: BlockingMode,
        framing_mode: FramingMode,
    ) -> Result<(StreamChannel, StreamChannel)> {
        let (pipe_a, pipe_b) = named_pipes::pair_with_buffer_size(
            &named_pipes::FramingMode::from(framing_mode),
            &named_pipes::BlockingMode::from(blocking_mode),
            0,
            DEFAULT_BUFFER_SIZE,
            false,
        )?;
        Self::from_pipes(pipe_a, pipe_b, DEFAULT_BUFFER_SIZE)
    }

    /// Blocks until the pipe buffer is empty.
    /// NOTE: that this will only work for server pipes on Windows.
    pub fn flush_blocking(&self) -> io::Result<()> {
        self.pipe_conn.flush_data_blocking().map_err(|e| e)
    }
}

impl io::Write for StreamChannel {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_immutable(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        // There is no userspace buffering inside crosvm to flush for named pipes. We write
        // directly to the named pipe using WriteFile.
        Ok(())
    }
}

impl AsRawDescriptor for &StreamChannel {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.pipe_conn.as_raw_descriptor()
    }
}

impl ReadNotifier for StreamChannel {
    /// Returns a RawDescriptor that can be polled for reads using WaitContext.
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        &self.read_notify
    }
}

impl CloseNotifier for StreamChannel {
    fn get_close_notifier(&self) -> &dyn AsRawDescriptor {
        &self.pipe_closed
    }
}

#[cfg(test)]
mod test {
    use std::io::Read;
    use std::io::Write;
    use std::time::Duration;

    use super::super::EventContext;
    use super::super::EventTrigger;
    use super::*;
    use crate::EventToken;
    use crate::ReadNotifier;

    #[derive(EventToken, Debug, Eq, PartialEq, Copy, Clone)]
    enum Token {
        ReceivedData,
    }

    const EVENT_WAIT_TIME: Duration = Duration::from_secs(10);

    #[test]
    fn test_read_notifies_multiple_writes() {
        let (mut sender, mut receiver) =
            StreamChannel::pair(BlockingMode::Blocking, FramingMode::Byte).unwrap();
        sender.write_all(&[1, 2]).unwrap();

        // Wait for the write to arrive.
        let event_ctx: EventContext<Token> = EventContext::build_with(&[EventTrigger::from(
            receiver.get_read_notifier(),
            Token::ReceivedData,
        )])
        .unwrap();
        assert_eq!(event_ctx.wait_timeout(EVENT_WAIT_TIME).unwrap().len(), 1);

        // Read just one byte. This leaves another byte in the pipe.
        let mut recv_buffer = [0u8; 1];
        let size = receiver.read(&mut recv_buffer).unwrap();
        assert_eq!(size, 1);
        assert_eq!(recv_buffer[0], 1);

        // The notifier should still be set, because the pipe has data.
        assert_eq!(event_ctx.wait_timeout(EVENT_WAIT_TIME).unwrap().len(), 1);
        let size = receiver.read(&mut recv_buffer).unwrap();
        assert_eq!(size, 1);
        assert_eq!(recv_buffer[0], 2);
    }

    #[test]
    fn test_blocked_writer_wont_deadlock() {
        let (mut writer, mut reader) =
            StreamChannel::pair_with_buffer_size(BlockingMode::Blocking, FramingMode::Byte, 100)
                .unwrap();
        const NUM_OPS: usize = 100;

        // We set the buffer size to 100 bytes. It seems that we must exceed that buffer size by
        // 100x before we run into a blocking write, so that's what we do here. This makes sense
        // to a degree because the docs suggest that some automatic expansion of a pipe's buffers
        // is supposed to be handled by the kernel.
        let writer = std::thread::spawn(move || {
            let buf = [0u8; 100];
            for _ in 0..NUM_OPS {
                assert_eq!(writer.write(&buf).unwrap(), buf.len());
            }
            writer
        });

        // The test passes if the reader can read (this used to deadlock).
        let mut buf = [0u8; 100];
        for _ in 0..NUM_OPS {
            assert_eq!(reader.read(&mut buf).unwrap(), buf.len());
        }

        // Writer must exit cleanly.
        writer.join().unwrap();
    }
}
