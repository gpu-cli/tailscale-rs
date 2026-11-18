use alloc::sync::Arc;
use core::{
    fmt::{Debug, Formatter},
    net::SocketAddr,
    task::{Context, Poll},
};

use bytes::Bytes;
use smoltcp::iface::SocketHandle;

use crate::{
    netcore,
    netcore::{
        DisplayExt, HasChannel, Request, Response, tcp,
        tcp::stream::{Put, SendQueue},
    },
    try_response_as,
};

#[cfg(any(feature = "tokio", feature = "futures-io"))]
type PinBoxFut<T> = core::pin::Pin<alloc::boxed::Box<dyn Future<Output = T> + Send>>;

/// A TCP stream.
pub struct TcpStream {
    sender: netcore::Channel,
    handle: SocketHandle,

    local: SocketAddr,
    remote: SocketAddr,

    #[cfg(any(feature = "tokio", feature = "futures-io"))]
    read_fut: Option<PinBoxFut<Result<Bytes, netcore::Error>>>,

    /// What has been written and not yet moved into the socket.
    queue: Arc<SendQueue>,
    /// Where the answers to drain requests go: nowhere, as a write never waits for one.
    unheard: flume::Sender<Response>,
    /// A drain request waiting for room in a full command channel.
    drain_request: Option<flume::r#async::SendFut<'static, Request>>,
}

impl TcpStream {
    pub(crate) fn new(
        sender: netcore::Channel,
        handle: SocketHandle,
        remote: SocketAddr,
        local: SocketAddr,
        send_buffer: usize,
    ) -> Self {
        let (unheard, _) = flume::bounded(1);

        Self {
            sender,
            handle,
            remote,
            local,

            #[cfg(any(feature = "tokio", feature = "futures-io"))]
            read_fut: None,

            queue: Arc::new(SendQueue::new(send_buffer)),
            unheard,
            drain_request: None,
        }
    }
}

// SAFETY: unsafe because of the contained futures which are not necessarily Sync. We know
// however that they're guaranteed to only be accessed or mutated via a &mut ref
// (in the Async{Read,Write} impls), implying no simultaneous cross-thread access is possible.
#[cfg(any(feature = "tokio", feature = "futures-io"))]
unsafe impl Sync for TcpStream {}

impl Debug for TcpStream {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpStream")
            .field("handle", &self.handle.as_display_debug())
            .field("local_endpoint", &self.local)
            .field("remote_endpoint", &self.remote)
            .finish()
    }
}

impl TcpStream {
    /// Report the local endpoint to which this stream is connected.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Report the remote endpoint to which this stream is connected.
    pub const fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// Send bytes to the remote.
    ///
    /// Blocks until at least one byte can be queued. The return value is the number of
    /// bytes actually queued.
    pub fn send_blocking(&self, b: &[u8]) -> Result<usize, netcore::Error> {
        if b.is_empty() {
            return Ok(0);
        }

        loop {
            match self.queue.put(b, None) {
                Put::Took { n, drain } => {
                    if drain {
                        let request = self.drain_request()?;
                        if self.upgrade()?.send(request).is_err() {
                            self.queue.drain_not_coming();
                            return Err(netcore::ChannelClosedError.into());
                        }
                    }
                    return Ok(n);
                }
                Put::Full => {
                    // Wait for the queue to empty: a drain is under way, and this one is
                    // answered when it is done.
                    let resp = self.request_blocking(tcp::stream::Command::Drain {
                        queue: self.queue.clone(),
                        close: false,
                    })?;
                    match resp {
                        Response::Ok => {}
                        Response::Error(e) => return Err(e),
                        _ => return Err(netcore::Error::wrong_type()),
                    }
                }
                Put::Failed => return Err(netcore::Error::invalid_socket_state()),
            }
        }
    }

    /// Send bytes to the remote.
    ///
    /// Waits until at least one byte can be queued. The return value is the number of
    /// bytes actually queued.
    pub async fn send(&self, b: &[u8]) -> Result<usize, netcore::Error> {
        if b.is_empty() {
            return Ok(0);
        }

        let (n, drain) = core::future::poll_fn(|cx| match self.queue.put(b, Some(cx.waker())) {
            Put::Took { n, drain } => Poll::Ready(Ok((n, drain))),
            Put::Full => Poll::Pending,
            Put::Failed => Poll::Ready(Err(netcore::Error::invalid_socket_state())),
        })
        .await?;

        if drain {
            let request = self.drain_request()?;
            if self.upgrade()?.send_async(request).await.is_err() {
                self.queue.drain_not_coming();
                return Err(netcore::ChannelClosedError.into());
            }
        }

        Ok(n)
    }

    fn upgrade(&self) -> Result<flume::Sender<Request>, netcore::ChannelClosedError> {
        self.sender.upgrade().ok_or(netcore::ChannelClosedError)
    }

    /// A request for the netstack to drain this stream's queue, answered to nobody.
    fn drain_request(&self) -> Result<Request, netcore::ChannelClosedError> {
        Ok(Request {
            handle: Some(self.handle),
            command: tcp::stream::Command::Drain {
                queue: self.queue.clone(),
                close: false,
            }
            .into(),
            resp: self.unheard.clone(),
            complete_if_channel_dropped: true,
        })
    }

    /// Queue as much of `buf` as fits without waiting on the netstack: pending only while
    /// the send buffer is full, and allocating nothing unless the command channel is.
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, netcore::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // A drain request still waiting on the command channel; bytes may be queued
        // behind it meanwhile, as it drains them too once sent.
        if let Some(request) = self.drain_request.as_mut() {
            match core::pin::Pin::new(request).poll(cx) {
                Poll::Pending => {}
                Poll::Ready(sent) => {
                    self.drain_request = None;
                    if sent.is_err() {
                        self.queue.drain_not_coming();
                        return Poll::Ready(Err(netcore::ChannelClosedError.into()));
                    }
                }
            }
        }

        let n = match self.queue.put(buf, Some(cx.waker())) {
            Put::Took { n, drain: false } => return Poll::Ready(Ok(n)),
            Put::Took { n, drain: true } => n,
            Put::Full => return Poll::Pending,
            Put::Failed => return Poll::Ready(Err(netcore::Error::invalid_socket_state())),
        };

        let request = self.drain_request()?;
        let sender = self.upgrade()?;
        match sender.try_send(request) {
            Ok(()) => {}
            Err(flume::TrySendError::Full(request)) => {
                let mut waiting = sender.into_send_async(request);
                if let Poll::Ready(Err(_)) = core::pin::Pin::new(&mut waiting).poll(cx) {
                    self.queue.drain_not_coming();
                    return Poll::Ready(Err(netcore::ChannelClosedError.into()));
                }
                self.drain_request = Some(waiting);
            }
            Err(flume::TrySendError::Disconnected(_)) => {
                self.queue.drain_not_coming();
                return Poll::Ready(Err(netcore::ChannelClosedError.into()));
            }
        }

        Poll::Ready(Ok(n))
    }

    /// Receive bytes from the remote.
    ///
    /// Returns the number of bytes actually received (blocks until there is at least one).
    pub fn recv_blocking(&self, b: &mut [u8]) -> Result<usize, netcore::Error> {
        let resp = self.request_blocking(tcp::stream::Command::Recv {
            max_len: Some(b.len()),
        })?;

        self._recv(resp, b)
    }

    /// Receive bytes from the remote into the supplied buffer.
    ///
    /// Returns the number of bytes actually received (blocks until there is at least one).
    pub async fn recv(&self, b: &mut [u8]) -> Result<usize, netcore::Error> {
        let resp = self
            .request(tcp::stream::Command::Recv {
                max_len: Some(b.len()),
            })
            .await?;

        self._recv(resp, b)
    }

    /// Receive bytes from the remote.
    ///
    /// Returns the number of bytes actually received (blocks until there is at least one).
    pub fn recv_bytes_blocking(&self) -> Result<Bytes, netcore::Error> {
        let resp = self.request_blocking(tcp::stream::Command::Recv { max_len: None })?;

        self._recv_bytes(resp)
    }

    /// Receive bytes from the remote.
    pub async fn recv_bytes(&self) -> Result<Bytes, netcore::Error> {
        let resp = self
            .request(tcp::stream::Command::Recv { max_len: None })
            .await?;

        self._recv_bytes(resp)
    }

    fn _recv(&self, resp: Response, b: &mut [u8]) -> Result<usize, netcore::Error> {
        let buf = self._recv_bytes(resp)?;

        let n = buf.len().min(b.len());
        b[..n].copy_from_slice(&buf[..n]);

        Ok(n)
    }

    fn _recv_bytes(&self, resp: Response) -> Result<Bytes, netcore::Error> {
        if matches!(resp, Response::TcpStream(tcp::stream::Response::Finished)) {
            return Ok(Bytes::new());
        }

        try_response_as!(resp, tcp::stream::Response::Recv { buf });
        Ok(buf)
    }

    #[cfg(any(feature = "tokio", feature = "futures-io"))]
    fn poll_read(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context,
        buf: &mut [u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        use netcore::HasChannel;

        let handle = self.handle;
        let cap = buf.len();

        loop {
            match self.read_fut.as_mut() {
                None => {
                    let sender = self.sender.clone();

                    let _ret = self.read_fut.insert(alloc::boxed::Box::pin(async move {
                        let resp = sender
                            .request(
                                Some(handle),
                                tcp::stream::Command::Recv { max_len: Some(cap) },
                            )
                            .await?;

                        match resp.try_into()? {
                            tcp::stream::Response::Recv { buf } => Ok(buf),
                            tcp::stream::Response::Finished => Ok(Bytes::new()),
                            _ => Err(netcore::Error::wrong_type()),
                        }
                    }));
                }

                Some(x) => {
                    let poll_result = x.as_mut().poll(cx);
                    let ret = core::task::ready!(poll_result)?;

                    buf[..ret.len()].copy_from_slice(&ret);

                    self.read_fut.take();

                    break core::task::Poll::Ready(Ok(ret.len()));
                }
            }
        }
    }

    socket_requestor_impl!();
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // Close once what was written is in the socket.
        if let Err(e) = self.sender.request_nonblocking(
            Some(self.handle),
            tcp::stream::Command::Drain {
                queue: self.queue.clone(),
                close: true,
            },
        ) {
            tracing::warn!(err = %e, "possible socket leak");
        }
    }
}

#[cfg(feature = "std")]
impl std::io::Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.recv_blocking(buf).map_err(netcore::Error::into)
    }
}

#[cfg(feature = "std")]
impl std::io::Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.send_blocking(buf).map_err(netcore::Error::into)
    }

    fn write_all(&mut self, mut buf: &[u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            let n = self.send_blocking(buf).map_err(std::io::Error::from)?;
            buf = &buf[n..];
        }

        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncRead for TcpStream {
    fn poll_read(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> core::task::Poll<tokio::io::Result<()>> {
        let n = core::task::ready!(self.poll_read(cx, buf.initialize_unfilled()))?;
        buf.advance(n);

        core::task::Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncWrite for TcpStream {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        self.get_mut()
            .poll_send(cx, buf)
            .map_err(netcore::Error::into)
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        // NOTE(npry): explicit shutdown semantics don't make sense for us because we have to
        // support closing the socket out-of-band anyway, since we can't rely on an async runtime
        // driving us. This creates this unfortunate situation where calling shutdown doesn't
        // actually confirm that we're closed, so any dependents using close for signaling (before
        // dropping the socket) could hang here.
        core::task::Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "futures-io")]
impl futures_io::AsyncRead for TcpStream {
    fn poll_read(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut [u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        self.poll_read(cx, buf)
    }
}

#[cfg(feature = "futures-io")]
impl futures_io::AsyncWrite for TcpStream {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        self.get_mut()
            .poll_send(cx, buf)
            .map_err(netcore::Error::into)
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        // See note above in poll_shutdown.
        core::task::Poll::Ready(Ok(()))
    }
}
