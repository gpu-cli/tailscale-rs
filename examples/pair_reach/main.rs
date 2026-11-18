//! Two devices in one process, joined one after the other, reach each other over TCP.
//!
//! The second device is new to the first through a map update while the first is
//! already running, the usual way two apps on one tailnet meet.
//!
//!     $ TS_AUTH_KEY=... cargo run --example pair_reach

use std::{error::Error, net::SocketAddr, time::Duration};

use tailscale::{Config, Device};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::filter::LevelFilter;

const PORT: u16 = 4747;

async fn device(name: &str, auth_key: Option<String>) -> Result<Device, Box<dyn Error>> {
    let mut config = Config::default_from_env();
    config.requested_hostname = Some(name.to_owned());
    config.ephemeral = true;
    Ok(Device::new(&config, auth_key).await?)
}

/// Serves one echo on `server` and dials it from `client`, retrying for up to a minute.
async fn reach(server: &Device, client: &Device) -> Result<Duration, Box<dyn Error>> {
    let addr: SocketAddr = (server.ipv4_addr().await?, PORT).into();
    let listener = server.tcp_listen(addr).await?;
    let serve = tokio::spawn(async move {
        let mut conn = listener.accept().await?;
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await?;
        conn.write_all(&buf).await?;
        Ok::<_, std::io::Error>(())
    });
    let start = tokio::time::Instant::now();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), client.tcp_connect(addr)).await {
            Ok(Ok(mut conn)) => {
                conn.write_all(b"ping").await?;
                let mut buf = [0u8; 4];
                tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut buf)).await??;
                serve.abort();
                return Ok(start.elapsed());
            }
            Ok(Err(e)) => tracing::warn!(%addr, error = %e, "connect failed"),
            Err(_) => tracing::warn!(%addr, "connect timed out"),
        }
        if start.elapsed() > Duration::from_secs(60) {
            serve.abort();
            return Err(format!("{addr} not reached within 60 s").into());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let auth_key = tailscale::config::auth_key_from_env().or_else(|| std::env::var("TS_AUTHKEY").ok());
    let suffix = std::process::id();
    let a = device(&format!("tsrs-pair-a-{suffix}"), auth_key.clone()).await?;
    tracing::info!(ip = %a.ipv4_addr().await?, "a is up");
    let b = device(&format!("tsrs-pair-b-{suffix}"), auth_key).await?;
    tracing::info!(ip = %b.ipv4_addr().await?, "b is up");

    let b_to_a = reach(&a, &b).await;
    println!("b reaches a: {b_to_a:?}");
    let a_to_b = reach(&b, &a).await;
    println!("a reaches b: {a_to_b:?}");

    a.shutdown(Some(Duration::from_secs(5))).await;
    b.shutdown(Some(Duration::from_secs(5))).await;
    if b_to_a.is_err() || a_to_b.is_err() {
        std::process::exit(1);
    }
    Ok(())
}
