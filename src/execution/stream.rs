//! Stream handling for process output

use crate::errors::{Result, SandboxError};
use std::io::{BufRead, BufReader};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;

/// A chunk of process output
#[derive(Debug, Clone)]
pub enum StreamChunk {
    /// Data from stdout
    Stdout(String),
    /// Data from stderr
    Stderr(String),
    /// Process has exited
    Exit { exit_code: i32, signal: Option<i32> },
}

/// Handle for receiving process output streams
pub struct ProcessStream {
    receiver: Receiver<StreamChunk>,
}

impl ProcessStream {
    /// Create new process stream handler
    pub fn new() -> (ProcessStreamWriter, Self) {
        let (tx, rx) = channel();
        (ProcessStreamWriter { tx }, ProcessStream { receiver: rx })
    }

    /// Receive next chunk from process streams
    pub fn recv(&self) -> Result<Option<StreamChunk>> {
        self.receiver
            .recv()
            .ok()
            .ok_or_else(|| SandboxError::Io(std::io::Error::other("stream closed")))
            .map(Some)
    }

    /// Try to receive next chunk without blocking
    pub fn try_recv(&self) -> Result<Option<StreamChunk>> {
        match self.receiver.try_recv() {
            Ok(chunk) => Ok(Some(chunk)),
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(None),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Ok(None),
        }
    }
}

impl Default for ProcessStream {
    fn default() -> Self {
        Self::new().1
    }
}

pub struct StreamIter {
    receiver: Receiver<StreamChunk>,
}

impl Iterator for StreamIter {
    type Item = StreamChunk;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver.recv().ok()
    }
}

impl IntoIterator for ProcessStream {
    type Item = StreamChunk;
    type IntoIter = StreamIter;

    fn into_iter(self) -> Self::IntoIter {
        StreamIter {
            receiver: self.receiver,
        }
    }
}

/// Writer side for process streams
pub struct ProcessStreamWriter {
    pub tx: Sender<StreamChunk>,
}

impl ProcessStreamWriter {
    /// Send stdout chunk
    pub fn send_stdout(&self, data: String) -> Result<()> {
        self.tx
            .send(StreamChunk::Stdout(data))
            .map_err(|_| SandboxError::Io(std::io::Error::other("failed to send stdout chunk")))
    }

    /// Send stderr chunk
    pub fn send_stderr(&self, data: String) -> Result<()> {
        self.tx
            .send(StreamChunk::Stderr(data))
            .map_err(|_| SandboxError::Io(std::io::Error::other("failed to send stderr chunk")))
    }

    /// Send exit status
    pub fn send_exit(&self, exit_code: i32, signal: Option<i32>) -> Result<()> {
        self.tx
            .send(StreamChunk::Exit { exit_code, signal })
            .map_err(|_| SandboxError::Io(std::io::Error::other("failed to send exit chunk")))
    }
}

/// Spawn a reader thread for a file descriptor
pub fn spawn_fd_reader(
    fd: RawFd,
    is_stderr: bool,
    tx: Sender<StreamChunk>,
) -> Result<thread::JoinHandle<()>> {
    let handle = thread::spawn(move || {
        // SAFETY: This FD comes from a properly-managed pipe created by the parent.
        // We wrap it in OwnedFd to ensure proper cleanup.
        use std::os::unix::io::OwnedFd;

        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let file = std::fs::File::from(owned_fd);
        let reader = BufReader::new(file);

        for line in reader.lines() {
            match line {
                Ok(line) => {
                    let chunk = if is_stderr {
                        StreamChunk::Stderr(line)
                    } else {
                        StreamChunk::Stdout(line)
                    };

                    if tx.send(chunk).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    continue;
                }
            }
        }
    });

    Ok(handle)
}
