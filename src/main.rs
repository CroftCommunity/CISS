//! The runnable CISS (Croft Item Storage Server) binary.
//!
//! The library ([`ciss`]) holds the metered-boundary logic; this binary is the
//! deployable entry point — it cannot be `curl`'d or run from the lib alone. It
//! honours the croft-stack tenant contract (`CONTRACT.md`): it takes
//! `--data-dir <path>` and `--listen <host:port>`, keeps **all** state under the
//! data dir, serves `GET /healthz` → `ok`, runs unprivileged, and binds a port
//! ≥ 1024 (Caddy terminates TLS). It self-manages its layout under the data dir:
//!
//! - `<data-dir>/meter.sqlite` — the per-DID metering ledger (**canonical**;
//!   Litestream-backed). Also holds the persisted provider key seed, so the
//!   signing identity survives a backup/restore.
//! - `<data-dir>/blocks/` — content-addressed blob bytes (**blobs**;
//!   rclone-mirrored, `--immutable`).
//!
//! Both paths are created on start (contract: create every declared path), and
//! the binary installs a SIGTERM graceful-shutdown path that checkpoints the
//! metering WAL on exit (E87). A systemd socket-activation fd is inherited when
//! offered (E87 seam).

use std::path::PathBuf;

use ciss::server::{inherit_fd_requested, App, Blobs, Db};

/// Resolved runtime configuration from the command line.
struct Config {
    data_dir: PathBuf,
    listen: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let config = parse_args(std::env::args().skip(1))?;
    let db_path = config.data_dir.join("meter.sqlite");

    // Provision the layout the binary owns (fail loud if we cannot). The blob
    // backend is rooted at the data dir: FsBlobStore lays content out under
    // `<data-dir>/blocks/{did}/{cid}` with a sibling `<data-dir>/tmp/` staging
    // dir — so the rclone-mirrored `blocks/` holds only permanent content and
    // the transient staging path stays outside the mirror. Creating `blocks/`
    // (which also creates the data dir) satisfies the contract's "create every
    // declared path on start"; the store creates `meter.sqlite` on open.
    std::fs::create_dir_all(config.data_dir.join("blocks"))?;

    // The provider identity is persisted in the metering store (generated on
    // first start), so no seed/secret needs wiring into the unit.
    let app = App::with_persistent_provider(Blobs::Fs(config.data_dir.clone()), Db::File(db_path))?;

    let listener = listen(&config.listen).await?;
    tracing::info!(
        provider = %app.provider_id(),
        data_dir = %config.data_dir.display(),
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

/// Parse `--data-dir <path>` and `--listen <host:port>` from the arguments.
///
/// Dev defaults keep `cargo run` usable; the croft-stack generator always passes
/// both explicitly. Unknown arguments and value-less flags are loud errors.
fn parse_args(args: impl Iterator<Item = String>) -> Result<Config, String> {
    let mut data_dir = PathBuf::from("./data");
    let mut listen = String::from("127.0.0.1:8080");
    let mut args = args;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data-dir" => {
                data_dir = PathBuf::from(args.next().ok_or("--data-dir requires a value")?);
            }
            "--listen" => listen = args.next().ok_or("--listen requires a value")?,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Config { data_dir, listen })
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

#[cfg(test)]
mod tests {
    use super::parse_args;
    use std::path::PathBuf;

    fn parse(args: &[&str]) -> Result<(PathBuf, String), String> {
        let cfg = parse_args(args.iter().map(|s| (*s).to_owned()))?;
        Ok((cfg.data_dir, cfg.listen))
    }

    #[test]
    fn flags_set_data_dir_and_listen() {
        let (dir, listen) = parse(&["--data-dir", "/var/lib/ciss", "--listen", "127.0.0.1:8301"])
            .expect("valid flags");
        assert_eq!(dir, PathBuf::from("/var/lib/ciss"));
        assert_eq!(listen, "127.0.0.1:8301");
    }

    #[test]
    fn defaults_apply_when_flags_are_absent() {
        let (dir, listen) = parse(&[]).expect("no args uses dev defaults");
        assert_eq!(dir, PathBuf::from("./data"));
        assert_eq!(listen, "127.0.0.1:8080");
    }

    #[test]
    fn a_value_less_flag_is_a_loud_error() {
        assert!(parse(&["--data-dir"]).is_err(), "--data-dir needs a value");
        assert!(parse(&["--listen"]).is_err(), "--listen needs a value");
    }

    #[test]
    fn an_unknown_flag_is_a_loud_error() {
        assert!(
            parse(&["--wat", "x"]).is_err(),
            "unknown flags are rejected, not ignored",
        );
    }
}
