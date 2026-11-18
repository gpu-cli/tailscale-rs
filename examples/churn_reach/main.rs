//! A device serving while others in the same process join and leave stays reachable.
//!
//! One host device serves TCP echo. Each round, a group of devices joins, each reaches the
//! host, then the whole group shuts down at once; a new device must then reach the host.
//!
//!     $ TS_AUTH_KEY=... cargo run --example churn_reach -- --rounds 6 --group 8

use std::{error::Error, net::SocketAddr, time::Duration};

use clap::Parser;
use tailscale::{Config, Device};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::filter::LevelFilter;

const PORT: u16 = 4747;

#[derive(clap::Parser)]
struct Args {
    /// Rounds of joining and leaving.
    #[arg(long, default_value_t = 6)]
    rounds: usize,
    /// Devices that join and leave together each round.
    #[arg(long, default_value_t = 8)]
    group: usize,
}

async fn device(name: String, auth_key: Option<String>) -> Result<Device, Box<dyn Error>> {
    let mut config = Config::default_from_env();
    config.requested_hostname = Some(name);
    config.ephemeral = true;
    Ok(Device::new(&config, auth_key).await?)
}

/// Dials `addr` from `client` and checks an echo, retrying for up to 30 s.
async fn reach(client: &Device, addr: SocketAddr) -> Result<Duration, String> {
    let start = tokio::time::Instant::now();
    loop {
        let attempt = async {
            let mut conn = client.tcp_connect(addr).await.map_err(|e| e.to_string())?;
            conn.write_all(b"ping").await.map_err(|e| e.to_string())?;
            let mut buf = [0u8; 4];
            conn.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
            Ok::<_, String>(())
        };
        match tokio::time::timeout(Duration::from_secs(10), attempt).await {
            Ok(Ok(())) => return Ok(start.elapsed()),
            Ok(Err(e)) => tracing::warn!(%addr, error = %e, "reach failed"),
            Err(_) => tracing::warn!(%addr, "reach timed out"),
        }
        if start.elapsed() > Duration::from_secs(30) {
            return Err(format!("{addr} not reached within 30 s"));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Whether `host` and `dev` have each other in their peer lists, to tell which side's view of
/// the tailnet fell behind.
async fn who_knows(host: &Device, dev: &Device) -> String {
    let knows = async |a: &Device, b: &Device| -> String {
        let Ok(ip) = b.ipv4_addr().await else {
            return "no address".into();
        };
        match a.peer_by_tailnet_ip(ip.into()).await {
            Ok(Some(_)) => "yes".into(),
            Ok(None) => "no".into(),
            Err(e) => format!("error: {e}"),
        }
    };
    format!(
        "host knows the device: {}, the device knows the host: {}",
        knows(host, dev).await,
        knows(dev, host).await
    )
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
    let args = Args::parse();
    let auth_key =
        tailscale::config::auth_key_from_env().or_else(|| std::env::var("TS_AUTHKEY").ok());
    let tag = std::process::id();

    let host = device(format!("tsrs-churn-host-{tag}"), auth_key.clone()).await?;
    let addr: SocketAddr = (host.ipv4_addr().await?, PORT).into();
    let listener = host.tcp_listen(addr).await?;
    tokio::spawn(async move {
        while let Ok(mut conn) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4];
                if conn.read_exact(&mut buf).await.is_ok()
                    && let Err(e) = conn.write_all(&buf).await
                {
                    tracing::warn!(error = %e, "echo failed");
                }
            });
        }
    });
    tracing::info!(%addr, "host serving");

    let mut failures = 0;
    for round in 0..args.rounds {
        let mut group = Vec::new();
        for i in 0..args.group {
            group.push(device(format!("tsrs-churn-{tag}-{round}-{i}"), auth_key.clone()).await?);
        }
        for (i, dev) in group.iter().enumerate() {
            match reach(dev, addr).await {
                Ok(t) => tracing::info!(round, i, ?t, "group device reached the host"),
                Err(e) => {
                    failures += 1;
                    println!(
                        "round {round}: group device {i}: {e}; {}",
                        who_knows(&host, dev).await
                    );
                }
            }
        }
        let mut leaving = tokio::task::JoinSet::new();
        for dev in group {
            leaving.spawn(dev.shutdown(Some(Duration::from_secs(5))));
        }
        leaving.join_all().await;

        let fresh = device(format!("tsrs-churn-{tag}-{round}-after"), auth_key.clone()).await?;
        match reach(&fresh, addr).await {
            Ok(t) => {
                println!("round {round}: a device after the group left reached the host in {t:?}")
            }
            Err(e) => {
                failures += 1;
                println!(
                    "round {round}: a device after the group left: {e}; {}",
                    who_knows(&host, &fresh).await
                );
            }
        }
        fresh.shutdown(Some(Duration::from_secs(5))).await;
    }

    host.shutdown(Some(Duration::from_secs(5))).await;
    println!("failures: {failures}");
    if failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}
