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
//!   Litestream-backed). Holds the provider's **public** key as a verification
//!   anchor; the private signing seed is supplied by the unit at start (a systemd
//!   credential), never persisted here, so it is safe to replicate off-box (I8).
//! - `<data-dir>/blocks/` — content-addressed blob bytes (**blobs**;
//!   rclone-mirrored, `--immutable`).
//!
//! Both paths are created on start (contract: create every declared path), and
//! the binary installs a SIGTERM graceful-shutdown path that checkpoints the
//! metering WAL on exit (E87). A systemd socket-activation fd is inherited when
//! offered (E87 seam).

use std::path::PathBuf;

use ciss::server::{inherit_fd_requested, App, Blobs, Db};

/// Top-level `--help` text.
const TOP_HELP: &str = "\
ciss — Croft Item Storage Server (metered PDS-like object store)

USAGE:
    ciss --data-dir <path> --listen <host:port>   run the metered-storage server
    ciss usage --data-dir <path> [--did <did>]    print a storage-usage report
    ciss --help                                   show this help

SERVER FLAGS:
    --data-dir <path>      state dir (meter.sqlite, blocks/, tmp/); default ./data
    --listen <host:port>   loopback bind (TLS is Caddy's); default 127.0.0.1:8080

ENVIRONMENT:
    CISS_PROVIDER_SEED     provider signing seed (hex). Normally a systemd
                           credential ($CREDENTIALS_DIRECTORY/provider-seed);
                           REQUIRED under systemd (the service fails closed).
    CISS_MAX_STORE_BYTES   whole-store distinct-bytes ceiling (default 50 GiB)
    CISS_MAX_DID_BYTES     optional per-DID cap; unset => opportunistic fill

See `ciss usage --help` for the report subcommand, and ciss(1) for the man page.
";

/// `ciss usage --help` text.
const USAGE_HELP: &str = "\
ciss usage — storage-usage report (read-only)

USAGE:
    ciss usage --data-dir <path> [--did <did>]

Prints the store ceiling (and its % of the partition the data dir is on) and each
DID's on-disk stored bytes alongside cumulative transferred bytes. With --did,
reports one DID. Reads the live database read-only — safe while the service runs.

OPTIONS:
    --data-dir <path>   the CISS data directory (contains meter.sqlite)
    --did <did>         report a single DID (default: all DIDs)
    -h, --help          show this help
";

/// Resolved runtime configuration from the command line.
struct Config {
    data_dir: PathBuf,
    listen: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Subcommand: `ciss usage [--did <did>] --data-dir <path>` is a sync, read-only
    // reporting tool over the same data dir; the bare form runs the service.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let has_help = |args: &[String]| args.iter().any(|a| a == "-h" || a == "--help");
    if argv.first().map(String::as_str) == Some("usage") {
        if has_help(&argv[1..]) {
            print!("{USAGE_HELP}");
            return Ok(());
        }
        return run_usage(&argv[1..]).map_err(Into::into);
    }
    if has_help(&argv) {
        print!("{TOP_HELP}");
        return Ok(());
    }

    init_tracing();

    let config = parse_args(argv.into_iter())?;
    let db_path = config.data_dir.join("meter.sqlite");

    // Provision the layout the binary owns (fail loud if we cannot). The blob
    // backend is rooted at the data dir: FsBlobStore lays content out under
    // `<data-dir>/blocks/{did}/{cid}` with a sibling `<data-dir>/tmp/` staging
    // dir — so the rclone-mirrored `blocks/` holds only permanent content and
    // the transient staging path stays outside the mirror. Creating `blocks/`
    // (which also creates the data dir) satisfies the contract's "create every
    // declared path on start"; the store creates `meter.sqlite` on open.
    std::fs::create_dir_all(config.data_dir.join("blocks"))?;

    // The provider signing key comes from a unit-supplied secret (systemd
    // credential or CISS_PROVIDER_SEED), never from the canonical database (I8);
    // only the public key is persisted, as a verification anchor.
    // Compose the production DID resolver (Model R): pinned admins → TTL cache →
    // hard timeout → plc.directory/did:web fetch. A malformed admin-pin file fails
    // startup loudly.
    let resolve_cfg = ciss::did_resolver::ResolveConfig::from_env()?;
    let service_did = resolve_cfg.service_did.clone();
    let admin_pin_count = resolve_cfg.admin_pins.len();
    // `du` lockdown (ADR 0003): `du` is always self-only; when CISS_ADMIN_ONLY_DU
    // is set, only a break-glass admin-pin DID may run it (still self-only).
    let admin_dids: std::collections::HashSet<String> =
        resolve_cfg.admin_pins.keys().cloned().collect();
    let admin_only_du = std::env::var("CISS_ADMIN_ONLY_DU")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let resolver = ciss::did_resolver::build_resolver(&resolve_cfg);

    let resolver_for_heartbeat = resolver.clone();
    let app = App::with_provider_from_secret(Blobs::Fs(config.data_dir.clone()), Db::File(db_path))?
        .with_did_resolver(resolver, service_did.clone())
        .with_admin_only_du(admin_dids, admin_only_du);

    // Resolver-cache heartbeat: a periodic INFO sample of cache condition for
    // ongoing monitoring via journald (not DEBUG — production stays out of debug).
    // It logs only when activity changed since the last tick, so an idle server
    // is quiet and rotation/retention is journald's job.
    tokio::spawn(cache_stats_heartbeat(resolver_for_heartbeat));

    // E83 stage 1: periodic compute-ledger flush, so `ciss usage` on a live
    // box reads compute data at most one interval stale (checkpoint also
    // flushes at graceful shutdown).
    let _compute_flush = app.spawn_compute_flush(std::time::Duration::from_secs(
        COMPUTE_FLUSH_INTERVAL_S,
    ));

    let listener = listen(&config.listen).await?;
    tracing::info!(
        provider = %app.provider_id(),
        data_dir = %config.data_dir.display(),
        local = ?listener.local_addr().ok(),
        %service_did,
        admin_pins = admin_pin_count,
        plc_url = %resolve_cfg.plc_url,
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

/// How often the resolver-cache heartbeat samples cache condition (seconds).
const CACHE_STATS_INTERVAL_S: u64 = 60;

/// How often the compute ledger flushes to `compute_usage` (seconds) — the
/// staleness bound on a live box's `ciss usage` compute section (E83 stage 1).
const COMPUTE_FLUSH_INTERVAL_S: u64 = 60;

/// Periodically log the DID-resolution cache condition at INFO for ongoing
/// monitoring. Emits only when activity (hits + misses) changed since the last
/// tick, so an idle server produces no noise. Runs for the process lifetime.
async fn cache_stats_heartbeat(resolver: std::sync::Arc<dyn ciss_resolve::DidResolver>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(CACHE_STATS_INTERVAL_S));
    let mut last_activity = 0u64;
    loop {
        tick.tick().await;
        if let Some(stats) = resolver.cache_stats() {
            let activity = stats.hits + stats.misses;
            if activity != last_activity {
                last_activity = activity;
                tracing::info!(
                    cache_size = stats.size,
                    hits = stats.hits,
                    misses = stats.misses,
                    hit_rate = stats.hit_rate(),
                    "DID resolution cache",
                );
            }
        }
    }
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

/// The `ciss usage [--did <did>] --data-dir <path>` subcommand: a read-only report
/// over the live metering store (the `did_usage` view + the persisted limits) plus
/// the data-dir partition size, so an operator can see the store ceiling as a % of
/// the partition and each DID's on-disk + cumulative-transferred bytes.
fn run_usage(args: &[String]) -> Result<(), String> {
    let mut data_dir: Option<PathBuf> = None;
    let mut did: Option<String> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--data-dir" => {
                data_dir = Some(PathBuf::from(it.next().ok_or("--data-dir requires a value")?));
            }
            "--did" => did = Some(it.next().ok_or("--did requires a value")?.clone()),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let data_dir = data_dir.ok_or("usage requires --data-dir")?;
    let db = data_dir.join("meter.sqlite");
    let store = ciss::persist::Store::open_readonly(db.to_str().ok_or("non-UTF-8 data-dir")?)
        .map_err(|e| format!("open store: {e}"))?;

    let meta_u64 = |key: &str| -> Result<Option<u64>, String> {
        Ok(store
            .get_meta(key)
            .map_err(|e| e.to_string())?
            .filter(|v| !v.is_empty())
            .and_then(|v| v.parse::<u64>().ok()))
    };
    let store_ceiling = meta_u64("store_ceiling")?;
    let did_cap = meta_u64("did_cap")?;
    let store_used = store.store_usage().map_err(|e| e.to_string())?;
    let rows = match &did {
        Some(d) => store
            .usage_for(d)
            .map_err(|e| e.to_string())?
            .into_iter()
            .collect::<Vec<_>>(),
        None => store.usage_all().map_err(|e| e.to_string())?,
    };
    let partition = partition_bytes(&data_dir);

    // E83 stage 1: the compute section (per caller × class). Under a --did
    // filter, show that caller only — same self-scoping the byte rows follow.
    let compute_rows: Vec<ciss::persist::ComputeUsageRow> = store
        .load_compute_usage()
        .map_err(|e| format!("load compute usage: {e}"))?
        .into_iter()
        .filter(|r| did.as_deref().is_none_or(|d| r.caller == d))
        .collect();

    print!(
        "{}{}",
        format_usage_report(
            &data_dir,
            store_ceiling,
            did_cap,
            store_used,
            partition,
            &rows,
            did.as_deref(),
        ),
        format_compute_section(&compute_rows),
    );
    Ok(())
}

/// Render the compute-observability section of the usage report (E83 stage 1) —
/// per caller × operation class, dispatched requests + total dispatch time.
/// Empty input renders nothing (a store predating the table, or a server that
/// has not flushed yet). Counters are since server start (in-memory ledger,
/// flushed periodically + at checkpoint); the table is derived, not billing.
fn format_compute_section(rows: &[ciss::persist::ComputeUsageRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "  compute (dispatched requests since server start; derived, not billing):\n",
    );
    for row in rows {
        out.push_str(&format!(
            "    {:<20} {:<16} {} req · {}\n",
            row.caller,
            row.class,
            row.requests,
            human_micros(row.micros),
        ));
    }
    out
}

/// Humanize a microsecond total for the usage report (display only).
#[allow(clippy::cast_precision_loss)] // display only
fn human_micros(micros: u64) -> String {
    if micros >= 1_000_000 {
        format!("{:.1}s", micros as f64 / 1_000_000.0)
    } else if micros >= 1_000 {
        format!("{:.1}ms", micros as f64 / 1_000.0)
    } else {
        format!("{micros}µs")
    }
}

/// A percentage of `whole` (0.0 when `whole` is 0).
#[allow(clippy::cast_precision_loss)] // display only
fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64 * 100.0
    }
}

/// A human-readable byte size (e.g. `1.2 GiB`).
#[allow(clippy::cast_precision_loss)] // display only
fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// `(total, available)` bytes of the filesystem `path` lives on, if resolvable.
#[cfg(unix)]
// statvfs field widths vary by platform; try_from is the portable choice.
#[allow(clippy::unnecessary_fallible_conversions, clippy::useless_conversion)]
fn partition_bytes(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c_path is a valid NUL-terminated path; stat is a valid out-param.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let frsize = u64::try_from(stat.f_frsize).unwrap_or(0);
    Some((
        u64::try_from(stat.f_blocks).unwrap_or(0) * frsize,
        u64::try_from(stat.f_bavail).unwrap_or(0) * frsize,
    ))
}

#[cfg(not(unix))]
fn partition_bytes(_path: &std::path::Path) -> Option<(u64, u64)> {
    None
}

/// Render the usage report (pure — the testable core of `run_usage`).
fn format_usage_report(
    data_dir: &std::path::Path,
    store_ceiling: Option<u64>,
    did_cap: Option<u64>,
    store_used: u64,
    partition: Option<(u64, u64)>,
    rows: &[ciss::persist::UsageRow],
    single_did: Option<&str>,
) -> String {
    let mut out = format!("CISS storage — data-dir {}\n", data_dir.display());
    if let Some((total, free)) = partition {
        out.push_str(&format!("  partition:     {} total, {} free\n", human(total), human(free)));
    }
    match store_ceiling {
        Some(ceiling) => {
            let of_part = partition
                .map(|(t, _)| format!("  ({:.1}% of partition)", pct(ceiling, t)))
                .unwrap_or_default();
            out.push_str(&format!("  store ceiling: {}{}\n", human(ceiling), of_part));
            let of_part_used = partition
                .map(|(t, _)| format!(" · {:.1}% of partition", pct(store_used, t)))
                .unwrap_or_default();
            out.push_str(&format!(
                "  store used:    {}  ({:.1}% of ceiling{})\n",
                human(store_used),
                pct(store_used, ceiling),
                of_part_used,
            ));
        }
        None => out.push_str(&format!("  store used:    {}  (ceiling not initialized)\n", human(store_used))),
    }
    match did_cap {
        Some(cap) => out.push_str(&format!("  per-DID cap:   {}\n", human(cap))),
        None => out.push_str("  per-DID cap:   (none — opportunistic)\n"),
    }
    out.push('\n');
    out.push_str(&format!(
        "  {:<46} {:>14} {:>18} {:>9}\n",
        "DID", "stored (disk)", "transferred (cum)", "receipts"
    ));
    for r in rows {
        out.push_str(&format!(
            "  {:<46} {:>14} {:>18} {:>9}\n",
            r.did,
            human(r.stored_bytes),
            human(r.transferred_bytes),
            r.receipt_count,
        ));
    }
    if rows.is_empty() {
        match single_did {
            Some(d) => out.push_str(&format!("  (no usage recorded for {d})\n")),
            None => out.push_str("  (no DIDs yet)\n"),
        }
    }
    out
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
    use super::{format_compute_section, format_usage_report, parse_args};
    use std::path::PathBuf;

    #[test]
    fn usage_report_includes_a_compute_section_per_caller_and_class() {
        let rows = vec![
            ciss::persist::ComputeUsageRow {
                caller: "anon".to_owned(),
                class: "object-read".to_owned(),
                requests: 9,
                micros: 120,
            },
            ciss::persist::ComputeUsageRow {
                caller: "id:abc".to_owned(),
                class: "manifest-write".to_owned(),
                requests: 3,
                micros: 4_500,
            },
        ];
        let out = format_compute_section(&rows);
        assert!(out.contains("compute"), "section is labeled: {out}");
        assert!(out.contains("id:abc"), "caller shown: {out}");
        assert!(out.contains("manifest-write"), "class shown: {out}");
        assert!(out.contains("3 req"), "request count shown: {out}");
        assert!(out.contains("4.5ms"), "dispatch time humanized: {out}");
        assert!(out.contains("anon"), "anonymous row shown: {out}");
    }

    #[test]
    fn an_empty_compute_table_renders_no_section() {
        assert_eq!(format_compute_section(&[]), "", "nothing to report");
    }

    #[test]
    fn usage_report_shows_ceiling_percent_and_per_did() {
        let rows = vec![ciss::persist::UsageRow {
            did: "id:abc".to_owned(),
            stored_bytes: 1_200_000_000,
            upload_bytes: 2_000_000_000,
            download_bytes: 1_400_000_000,
            transferred_bytes: 3_400_000_000,
            receipt_count: 412,
        }];
        let gib = 1024 * 1024 * 1024;
        let report = format_usage_report(
            std::path::Path::new("/var/lib/ciss"),
            Some(50 * gib),
            None,
            1_200_000_000,
            Some((99 * gib, 91 * gib)),
            &rows,
            None,
        );
        assert!(report.contains("store ceiling: 50.0 GiB"), "{report}");
        assert!(report.contains("% of partition"), "{report}");
        assert!(
            report.contains("per-DID cap:   (none — opportunistic)"),
            "{report}",
        );
        assert!(report.contains("id:abc"), "{report}");
        assert!(report.contains("stored (disk)"), "{report}");
    }

    #[test]
    fn usage_report_shows_a_configured_per_did_cap() {
        let report = format_usage_report(
            std::path::Path::new("/data"),
            Some(1000),
            Some(100),
            0,
            None,
            &[],
            None,
        );
        assert!(report.contains("per-DID cap:   100 B"), "{report}");
        assert!(report.contains("(no DIDs yet)"), "{report}");
    }

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
