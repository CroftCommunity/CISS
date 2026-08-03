//! The runnable CISS (Croft Item Storage Server) binary.
//!
//! The library ([`ciss`]) holds the metered-boundary logic; this binary
//! is the deployable entry point — it cannot be `curl`'d or run from the lib
//! alone. It wires configuration from the environment, binds (or inherits) a
//! listening socket, serves the router with a SIGTERM graceful-shutdown path,
//! and checkpoints the metering WAL on exit.
//!
//! Configuration (all optional, dev defaults shown):
//! - `CISS_SEED` — provider key seed (`ciss-dev`). `SEAM:` a real deployment
//!   loads the provider key from a secret store / KMS, not an env seed.
//! - `CISS_BLOB_ROOT` — filesystem blob backend root (`./data/blocks`).
//! - `CISS_DB` — per-DID metering SQLite path (`./data/meter.sqlite`).
//! - `CISS_ADDR` — bind address when not socket-activated (`127.0.0.1:8080`).

use std::path::PathBuf;

use ciss::server::{inherit_fd_requested, App, Blobs, Db};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let seed = env_or("CISS_SEED", "ciss-dev");
    let blob_root = PathBuf::from(env_or("CISS_BLOB_ROOT", "./data/blocks"));
    let db_path = PathBuf::from(env_or("CISS_DB", "./data/meter.sqlite"));
    let addr = env_or("CISS_ADDR", "127.0.0.1:8080");

    // Provision the data directories the binary owns (fail loud if we cannot):
    // the SQLite path's parent must exist before the store opens, and the blob
    // root before the first write.
    std::fs::create_dir_all(&blob_root)?;
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let app = App::new(&seed, Blobs::Fs(blob_root), Db::File(db_path))?;

    let listener = listen(&addr).await?;
    tracing::info!(
        provider = %app.provider_id(),
        local = ?listener.local_addr().ok(),
        "CISS starting"
    );

    axum::serve(listener, app.router())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Drained: checkpoint the WAL so a restart opens a clean database (E87).
    app.checkpoint()?;
    tracing::info!("shutdown complete");
    Ok(())
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}

/// Bind the listening socket, or inherit a systemd socket-activation fd (E87).
async fn listen(addr: &str) -> std::io::Result<tokio::net::TcpListener> {
    if inherit_fd_requested(
        std::env::var("LISTEN_FDS").ok().as_deref(),
        std::env::var("LISTEN_PID").ok().as_deref(),
        std::process::id(),
    ) {
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            tracing::info!("inheriting systemd socket-activation fd 3 (E87 seam)");
            // SAFETY: per the systemd socket-activation protocol, LISTEN_FDS==1
            // and LISTEN_PID==our pid mean fd 3 is a listening socket passed to
            // and owned by this process; we convert it exactly once here.
            let std_listener = unsafe { std::net::TcpListener::from_raw_fd(3) };
            std_listener.set_nonblocking(true)?;
            return tokio::net::TcpListener::from_std(std_listener);
        }
    }
    tokio::net::TcpListener::bind(addr).await
}

/// Resolve when the process should begin a graceful shutdown: SIGTERM (systemd
/// stop) or SIGINT (Ctrl-C). Returning triggers axum's drain of in-flight
/// requests.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler at startup");
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        tokio::select! {
            _ = term.recv() => tracing::info!("SIGTERM received, draining in-flight requests"),
            () = ctrl_c => tracing::info!("SIGINT received, draining in-flight requests"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
