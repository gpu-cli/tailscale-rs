//! Messages for TCP streams.

use core::{
    fmt::{Debug, Formatter},
    net::SocketAddr,
};

use alloc::{sync::Arc, vec, vec::Vec};
use core::task::Waker;

use bytes::Bytes;
use smoltcp::iface::SocketHandle;

use crate::netcore::command;

/// The connection was reset or closed.
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
#[error("connection reset or closed")]
pub struct ConnectionResetOrClosed;

#[cfg(feature = "std")]
impl From<ConnectionResetOrClosed> for std::io::Error {
    fn from(_: ConnectionResetOrClosed) -> Self {
        std::io::ErrorKind::ConnectionReset.into()
    }
}

/// Commands for controlling TCP streams.
pub enum Command {
    /// Connect from the given local endpoint to the given remote endpoint.
    ///
    /// Neither endpoint may use an unspecified (zero) port.
    Connect {
        /// The local endpoint to connect from.
        local_endpoint: SocketAddr,
        /// The remote endpoint to connect to.
        remote_endpoint: SocketAddr,
    },

    /// Receive data incoming on the socket.
    ///
    /// Blocks until at least one byte can be received (or the remote closes its end of the
    /// stream).
    Recv {
        /// If `Some`, limit the length of the received data to at most the contained value.
        /// Otherwise, no limit.
        ///
        /// The payload may contain less data than specified here.
        ///
        /// Intended to be used to emulate socket APIs where the caller provides a byte
        /// buffer -- e.g. `sock.recv(&mut [u8])` -- where providing more data than the
        /// available buffer length would cause data loss.
        max_len: Option<usize>,
    },

    /// Send bytes over the connection.
    ///
    /// Blocks until at least one byte can be sent.
    Send {
        /// Bytes to send over the connection.
        buf: Bytes,
    },

    /// Move what a stream has queued to send into its socket.
    ///
    /// Retried as the socket frees room, and answered once the queue is empty; with
    /// `close`, the connection is then closed as by [`Command::Close`].
    Drain {
        /// The stream's queue of bytes to send.
        queue: Arc<SendQueue>,
        /// Close the connection once everything queued is in the socket.
        close: bool,
    },

    /// Close this connection.
    ///
    /// This message causes the connection to enter the closing state, but responds
    /// immediately -- the netstack does not wait to respond until the state machine
    /// finishes closing gracefully (this occurs in the background).
    Close,
}

impl Debug for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connect {
                local_endpoint,
                remote_endpoint,
            } => f
                .debug_struct("Connect")
                .field("local_endpoint", local_endpoint)
                .field("remote_endpoint", remote_endpoint)
                .finish(),
            Self::Recv { max_len } => f.debug_struct("Recv").field("max_len", max_len).finish(),
            Self::Send { buf } => f.debug_struct("Send").field("buf_len", &buf.len()).finish(),
            Self::Drain { close, .. } => f.debug_struct("Drain").field("close", close).finish(),
            Self::Close => f.write_str("Close"),
        }
    }
}

impl From<Command> for command::Command {
    fn from(value: Command) -> Self {
        command::Command::TcpStream(value)
    }
}

/// Responses to TCP stream [`Command`]s.
pub enum Response {
    /// Connection opened successfully.
    Connected {
        /// Handle for the newly created socket.
        handle: SocketHandle,
        /// How many bytes the stream may queue to send before a write waits.
        send_buffer: usize,
    },

    /// Sent `n` bytes over the connection
    Sent {
        /// The number of bytes of the original buffer that were accepted to be sent.
        ///
        /// Always at least 1.
        n: usize,
    },

    /// Received the contained bytes from the remote.
    Recv {
        /// Bytes received from the remote.
        buf: Bytes,
    },

    /// The remote has closed the sending side of its connection and will not send any more
    /// data; EOF.
    Finished,
}

impl From<Response> for command::Response {
    fn from(value: Response) -> Self {
        Self::TcpStream(value)
    }
}

impl Debug for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connected {
                handle,
                send_buffer,
            } => f
                .debug_struct("Connected")
                .field("handle", handle)
                .field("send_buffer", send_buffer)
                .finish(),
            Self::Sent { n } => f.debug_struct("Sent").field("n", n).finish(),
            Self::Recv { buf } => f.debug_struct("Recv").field("buf_len", &buf.len()).finish(),
            Self::Finished => f.write_str("Finished"),
        }
    }
}

/// The bytes a stream has written that the netstack has not yet moved into its socket.
///
/// It and the socket's own buffer together hold at most the socket's send buffer: a
/// write copies in what fits under that bound and returns at once, waiting only when
/// it is full, so a write costs no allocation and no round trip through the netstack,
/// and adds no queue the socket would not have had. The netstack drains it on a
/// [`Command::Drain`], and again each time the socket frees room, until it is empty
/// and no writer is waiting for room.
///
/// The lock is a spin lock because the crate builds without std; it is held only to copy
/// bytes in or out.
pub struct SendQueue {
    ring: spin::mutex::SpinMutex<Ring>,
}

struct Ring {
    bytes: Vec<u8>,
    head: usize,
    len: usize,
    /// What the socket held, unsent or unacknowledged, when the netstack last looked:
    /// room here is what the send buffer has left after it.
    in_socket: usize,
    /// A drain is on its way or under way: set by the writer that finds none coming,
    /// cleared by the drain that leaves nothing to do.
    draining: bool,
    /// The socket refused bytes: the connection is gone.
    failed: bool,
    /// The writer waiting for room.
    waker: Option<Waker>,
}

impl Ring {
    fn room(&self) -> usize {
        self.bytes.len().saturating_sub(self.len + self.in_socket)
    }

    /// Whether a writer must ask for a drain: none is coming. Marks one as coming.
    fn ask(&mut self) -> bool {
        !core::mem::replace(&mut self.draining, true)
    }
}

/// What [`SendQueue::put`] did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Put {
    /// Took `n` bytes.
    Took { n: usize, drain: bool },
    /// No room: the writer's waker, if given, is woken when there is.
    Full { drain: bool },
    /// The connection is gone.
    Failed,
}

/// What [`SendQueue::drain`] left.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Drained {
    /// Nothing queued, and no writer waiting for the socket to free room.
    Empty,
    /// Bytes still queued, or a writer waiting for room the socket has not yet freed.
    More,
    /// The socket refused the bytes; what was queued is dropped.
    Failed,
}

impl SendQueue {
    /// A queue for a socket whose send buffer holds `capacity` bytes.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            ring: spin::mutex::SpinMutex::new(Ring {
                bytes: vec![0; capacity.max(1)],
                head: 0,
                len: 0,
                in_socket: 0,
                draining: false,
                failed: false,
                waker: None,
            }),
        }
    }

    /// Copy as much of `bytes` in as the send buffer has room for. With `drain`, no
    /// drain is coming and the writer must ask for one.
    pub(crate) fn put(&self, bytes: &[u8], waker: Option<&Waker>) -> Put {
        let mut ring = self.ring.lock();
        if ring.failed {
            return Put::Failed;
        }
        let n = bytes.len().min(ring.room());
        if n == 0 {
            if let Some(waker) = waker {
                match &mut ring.waker {
                    Some(held) if held.will_wake(waker) => {}
                    held => *held = Some(waker.clone()),
                }
            }
            // The room may be held by the socket alone: a drain watches it free.
            return Put::Full { drain: ring.ask() };
        }
        let capacity = ring.bytes.len();
        let tail = (ring.head + ring.len) % capacity;
        let first = n.min(capacity - tail);
        ring.bytes[tail..tail + first].copy_from_slice(&bytes[..first]);
        ring.bytes[..n - first].copy_from_slice(&bytes[first..n]);
        ring.len += n;
        Put::Took {
            n,
            drain: ring.ask(),
        }
    }

    /// Hand the queued bytes, oldest first, to `send`, which takes what fits and says how
    /// much, or fails if the connection is gone; then note what the socket holds, from
    /// `in_socket`. Neither is called while nothing is queued and no writer waits.
    pub(crate) fn drain(
        &self,
        mut send: impl FnMut(&[u8]) -> Result<usize, ()>,
        mut in_socket: impl FnMut() -> usize,
    ) -> Drained {
        let mut ring = self.ring.lock();
        if ring.len == 0 && ring.waker.is_none() && !ring.failed {
            ring.draining = false;
            return Drained::Empty;
        }
        let capacity = ring.bytes.len();
        while ring.len > 0 && !ring.failed {
            let end = capacity.min(ring.head + ring.len);
            match send(&ring.bytes[ring.head..end]) {
                Ok(0) => break,
                Ok(n) => {
                    ring.head = (ring.head + n) % capacity;
                    ring.len -= n;
                }
                Err(()) => {
                    ring.failed = true;
                    ring.len = 0;
                }
            }
        }
        if !ring.failed {
            ring.in_socket = in_socket();
        }
        let waker = if ring.failed || ring.room() > 0 {
            ring.waker.take()
        } else {
            None
        };
        let left = if ring.failed {
            Drained::Failed
        } else if ring.len == 0 && ring.waker.is_none() {
            ring.draining = false;
            Drained::Empty
        } else {
            Drained::More
        };
        drop(ring);
        if let Some(waker) = waker {
            waker.wake();
        }
        left
    }

    /// Forget that a drain is coming, when the request for one could not be sent.
    pub(crate) fn drain_not_coming(&self) {
        self.ring.lock().draining = false;
    }

    /// Forget the waiting writer: the stream is going, and a drain must not keep
    /// watching a socket for it.
    pub(crate) fn writer_gone(&self) {
        self.ring.lock().waker = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_put_takes_what_fits_and_asks_for_one_drain() {
        let queue = SendQueue::new(8);
        assert_eq!(queue.put(b"hello", None), Put::Took { n: 5, drain: true });
        assert_eq!(queue.put(b"world", None), Put::Took { n: 3, drain: false });
        assert_eq!(queue.put(b"!", None), Put::Full { drain: false });
    }

    #[test]
    fn a_drain_hands_bytes_over_in_order_across_the_wrap() {
        let queue = SendQueue::new(8);
        queue.put(b"abcdef", None);
        let mut sent = Vec::new();
        // The socket has room for four bytes.
        let mut room = 4;
        let left = queue.drain(
            |bytes| {
                let n = bytes.len().min(room);
                room -= n;
                sent.extend_from_slice(&bytes[..n]);
                Ok(n)
            },
            || 0,
        );
        assert_eq!(left, Drained::More);
        assert_eq!(queue.put(b"ghijk", None), Put::Took { n: 5, drain: false });
        let left = queue.drain(
            |bytes| {
                sent.extend_from_slice(bytes);
                Ok(bytes.len())
            },
            || 0,
        );
        assert_eq!(left, Drained::Empty);
        assert_eq!(sent, b"abcdefghijk");
        assert_eq!(queue.put(b"l", None), Put::Took { n: 1, drain: true });
    }

    #[test]
    fn a_refused_send_fails_the_queue() {
        let queue = SendQueue::new(8);
        queue.put(b"abc", None);
        assert_eq!(queue.drain(|_| Err(()), || 0), Drained::Failed);
        assert_eq!(queue.put(b"d", None), Put::Failed);
    }

    #[test]
    fn the_queue_and_the_socket_together_hold_no_more_than_the_send_buffer() {
        let queue = SendQueue::new(8);
        assert_eq!(queue.put(b"abcdef", None), Put::Took { n: 6, drain: true });
        // The socket takes all six and is still holding them.
        assert_eq!(queue.drain(|bytes| Ok(bytes.len()), || 6), Drained::Empty);
        assert_eq!(queue.put(b"ghij", None), Put::Took { n: 2, drain: true });
        assert_eq!(queue.drain(|_| Ok(0), || 8), Drained::More);

        // A writer waits on the socket alone; the drain wakes it once the socket frees.
        let woken = alloc::sync::Arc::new(Woken(core::sync::atomic::AtomicBool::new(false)));
        let waker = Waker::from(woken.clone());
        assert_eq!(queue.put(b"k", Some(&waker)), Put::Full { drain: false });
        assert_eq!(queue.drain(|bytes| Ok(bytes.len()), || 8), Drained::More);
        assert!(!woken.0.load(core::sync::atomic::Ordering::SeqCst));
        assert_eq!(queue.drain(|bytes| Ok(bytes.len()), || 3), Drained::Empty);
        assert!(woken.0.load(core::sync::atomic::Ordering::SeqCst));
        assert_eq!(queue.put(b"klmnop", None), Put::Took { n: 5, drain: true });
    }

    struct Woken(core::sync::atomic::AtomicBool);

    impl alloc::task::Wake for Woken {
        fn wake(self: alloc::sync::Arc<Self>) {
            self.0.store(true, core::sync::atomic::Ordering::SeqCst);
        }
    }
}
