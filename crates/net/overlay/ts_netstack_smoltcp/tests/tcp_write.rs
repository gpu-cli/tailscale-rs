//! Writes to a TCP stream queue at once, without allocating, until the send buffer fills.

use core::{
    alloc::Layout,
    cell::Cell,
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
    time::Duration,
};
use std::{
    alloc::{GlobalAlloc, System},
    sync::{Arc, mpsc},
    task::Wake,
    thread,
};

use tokio::io::AsyncWrite;
use ts_netstack_smoltcp::{
    Netstack, WakingPipe, WakingPipeDev,
    netcore::{Config, HasChannel, NetstackControl},
    netsock::{CreateSocket, TcpStream},
};

/// Counts the allocations made on the thread that turned counting on.
struct Counting;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn count() {
    if COUNTING.try_with(Cell::get).unwrap_or(false) {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
    }
}

// SAFETY: forwards every call to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: the caller's contract is passed through.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract is passed through.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        // SAFETY: the caller's contract is passed through.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Allocations `f` makes on this thread.
fn allocations<T>(f: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATIONS.with(|n| n.set(0));
    COUNTING.with(|c| c.set(true));
    let out = f();
    COUNTING.with(|c| c.set(false));
    (out, ALLOCATIONS.with(Cell::get))
}

struct Woken(AtomicUsize);

impl Wake for Woken {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A connected client stream and the server's end of it, on two netstacks run on their own
/// threads.
fn connected() -> (TcpStream, TcpStream) {
    let client_ep: SocketAddr = "100.64.0.2:32768".parse().unwrap();
    let server_ep: SocketAddr = "100.64.0.1:80".parse().unwrap();
    let (p1, p2) = WakingPipe::new(None);
    let dev = |pipe| WakingPipeDev {
        pipe,
        mtu: 1500,
        medium: smoltcp::phy::Medium::Ip,
    };
    let mut client_stack = Netstack::new(dev(p1), Config::default());
    let mut server_stack = Netstack::new(dev(p2), Config::default());
    let (client_ch, server_ch) = (
        client_stack.command_channel(),
        server_stack.command_channel(),
    );
    thread::spawn(move || client_stack.run_blocking(Duration::from_millis(1)));
    thread::spawn(move || server_stack.run_blocking(Duration::from_millis(1)));
    client_ch.set_ips_blocking([client_ep.ip()]).unwrap();
    server_ch.set_ips_blocking([server_ep.ip()]).unwrap();

    let listener = server_ch.tcp_listen_blocking(server_ep).unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || tx.send(listener.accept_blocking().unwrap()).unwrap());
    let client = client_ch
        .tcp_connect_blocking(client_ep, server_ep)
        .unwrap();
    let server = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    (client, server)
}

/// Read `len` bytes on another thread, then the end of the stream if `to_end`.
fn read(server: TcpStream, len: usize, to_end: bool) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut got = Vec::new();
        let mut buf = [0; 4096];
        while got.len() < len || to_end {
            let n = server.recv_blocking(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        tx.send(got).unwrap();
    });
    rx
}

fn message(i: usize) -> [u8; 64] {
    let mut m = [0; 64];
    for (j, b) in m.iter_mut().enumerate() {
        *b = (i * 7 + j) as u8;
    }
    m
}

#[test]
fn a_write_allocates_nothing_once_warm() {
    let (mut client, server) = connected();
    const MESSAGES: usize = 2000;
    let got = read(server, MESSAGES * 64, false);

    let woken = Arc::new(Woken(AtomicUsize::new(0)));
    let waker = Waker::from(woken.clone());
    let mut cx = Context::from_waker(&waker);
    let mut sent = Vec::new();
    let mut pending = 0;
    let mut extra = 0;
    for i in 0..MESSAGES {
        let m = message(i);
        let mut at = 0;
        while at < m.len() {
            let (poll, n) = allocations(|| Pin::new(&mut client).poll_write(&mut cx, &m[at..]));
            if i >= 100 {
                extra += n;
            }
            match poll {
                Poll::Ready(Ok(n)) => at += n,
                Poll::Ready(Err(e)) => panic!("write failed: {e}"),
                Poll::Pending => {
                    pending += 1;
                    thread::sleep(Duration::from_micros(200));
                }
            }
        }
        sent.extend_from_slice(&m);
    }

    let got = got.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(got, sent, "the bytes arrive whole and in order");
    assert_eq!(
        extra, 0,
        "a write allocates nothing once warm, including the {pending} that waited"
    );
}

#[test]
fn a_write_waits_only_once_the_send_buffer_is_full_and_is_woken_when_it_drains() {
    let (mut client, server) = connected();
    let woken = Arc::new(Woken(AtomicUsize::new(0)));
    let waker = Waker::from(woken.clone());
    let mut cx = Context::from_waker(&waker);

    // Nobody reads: the bytes fill this stream's queue, its socket and the peer's window.
    let send_buffer = Config::default().tcp_buffer_size;
    let mut sent = Vec::new();
    let mut i = 0;
    loop {
        let m = message(i);
        match Pin::new(&mut client).poll_write(&mut cx, &m) {
            Poll::Ready(Ok(n)) => sent.extend_from_slice(&m[..n]),
            Poll::Ready(Err(e)) => panic!("write failed: {e}"),
            Poll::Pending => break,
        }
        i += 1;
        assert!(i < 100_000, "a write never waited");
    }
    assert!(
        sent.len() >= send_buffer,
        "waited after {} bytes, before the {send_buffer}-byte send buffer filled",
        sent.len()
    );

    // Reading drains the queue, which wakes the writer.
    let total = sent.len() + 64;
    let got = read(server, total, false);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while woken.0.load(Ordering::SeqCst) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the writer was never woken"
        );
        thread::sleep(Duration::from_millis(1));
    }
    let m = message(i);
    let mut at = 0;
    while at < m.len() {
        match Pin::new(&mut client).poll_write(&mut cx, &m[at..]) {
            Poll::Ready(Ok(n)) => at += n,
            Poll::Ready(Err(e)) => panic!("write failed: {e}"),
            Poll::Pending => thread::sleep(Duration::from_millis(1)),
        }
    }
    sent.extend_from_slice(&m);
    assert_eq!(got.recv_timeout(Duration::from_secs(10)).unwrap(), sent);
}

#[test]
fn a_dropped_stream_delivers_what_was_written_before_it_closes() {
    let (mut client, server) = connected();
    let woken = Arc::new(Woken(AtomicUsize::new(0)));
    let waker = Waker::from(woken.clone());
    let mut cx = Context::from_waker(&waker);

    let got = read(server, 0, true);
    let mut sent = Vec::new();
    for i in 0..200 {
        let m = message(i);
        let mut at = 0;
        while at < m.len() {
            match Pin::new(&mut client).poll_write(&mut cx, &m[at..]) {
                Poll::Ready(Ok(n)) => at += n,
                Poll::Ready(Err(e)) => panic!("write failed: {e}"),
                Poll::Pending => thread::sleep(Duration::from_millis(1)),
            }
        }
        sent.extend_from_slice(&m);
    }
    drop(client);

    assert_eq!(got.recv_timeout(Duration::from_secs(10)).unwrap(), sent);
}
