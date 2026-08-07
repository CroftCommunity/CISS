//! `ciss-ctl` — the CISS client CLI: argument parsing and command dispatch.
//!
//! This binary is a thin front end over the `ciss_cli` library (client, config,
//! identity, the atproto relay, and the command implementations). It defines the
//! clap command surface — the global flags every subcommand shares and the
//! per-command arguments — and routes each parsed command to its handler,
//! branching on the active identity plane (`id:` vs `did:`) where the two paths
//! differ. All fallible work returns an error that surfaces as a non-zero exit;
//! nothing fails silently.

use std::path::Path;

use anyhow::Context as _;
use clap::{Args, CommandFactory, Parser, Subcommand};

use ciss_cli::client::Plane;
use ciss_cli::{atproto, client, commands, config, identity, sync};

/// Which identity plane the client acts under.
///
/// `id:` is a locally-held ed25519 key (self-signed session). `did:` is the
/// user's atproto account, whose key stays at the PDS (service-auth JWT relay).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum IdentityKind {
    /// Locally-held ed25519 key; the `id:` DID is `sha256(pubkey)`.
    Id,
    /// The user's atproto account; the signing key stays at the PDS.
    Did,
}

/// The read class for `acl set`, as a validated CLI value (mapped to
/// [`ciss::policy::ReadClass`] server-side).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ReadClassArg {
    /// Public: any caller may read.
    World,
    /// Restricted: the owner and the DIDs in `--readers` may read.
    Grantees,
    /// Owner-only: only the owner may read.
    Owner,
}

impl ReadClassArg {
    /// The wire tag the server expects (matches `ciss::policy::ReadClass`).
    fn as_str(self) -> &'static str {
        match self {
            ReadClassArg::World => "world",
            ReadClassArg::Grantees => "grantees",
            ReadClassArg::Owner => "owner",
        }
    }
}

/// Flags shared by every subcommand. Parsed once at the root, threaded down.
#[derive(Args, Debug)]
struct GlobalArgs {
    /// Base URL of the CISS server (e.g. `https://ciss.croft.ing`).
    #[arg(long, global = true, default_value = "http://127.0.0.1:8080")]
    server: String,

    /// Named profile whose identity/credentials to act under.
    #[arg(long, global = true, default_value = "default")]
    profile: String,

    /// Which identity plane to use.
    #[arg(long, global = true, value_enum, default_value_t = IdentityKind::Id)]
    identity: IdentityKind,

    /// For the `did:` plane: the CISS service DID to target as the token `aud`.
    /// Defaults to the value the server advertises at `/.well-known/did.json`.
    #[arg(long, global = true)]
    aud: Option<String>,

    /// Emit machine-readable JSON instead of human text.
    #[arg(long, global = true)]
    json: bool,

    /// Log each server request's outcome (status) to stderr. Secrets — the seed,
    /// the session signature, the app password, the access/service-auth JWTs — are
    /// never logged.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Parser, Debug)]
#[command(
    name = "ciss-ctl",
    version,
    about = "Client CLI for CISS (Croft Item Storage Server).",
    long_about = "Owns a client identity keypair, drives the S3 + atproto blob \
                  planes over one metered byte-path, and manages gated-read ACLs."
)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Manage the client identity keypair.
    #[command(subcommand)]
    Key(KeyCommand),

    /// Log in to your atproto PDS with an app password and save the credential
    /// for a `did:` profile (writes pds.json at mode 0600). The password is read
    /// from CISS_PDS_APP_PASSWORD if set, else prompted without echo.
    Login {
        /// Your PDS base URL.
        #[arg(long, default_value = "https://bsky.social")]
        pds: String,
        /// Your account handle or DID (e.g. you.bsky.social).
        #[arg(long)]
        identifier: String,
    },

    /// Print the DID of the active identity.
    Whoami,

    /// Upload a file over the atproto or S3 plane; prints the content id (cid)
    /// and the bytes transferred. Both planes land at the same backend digest.
    Put {
        /// Path to the file to upload.
        file: String,
        /// Byte-path to upload over: `pds` (atproto uploadBlob, the default) or
        /// `s3` (the S3-compat object PUT). Same resulting cid either way.
        #[arg(long, value_enum, default_value_t = Plane::Pds)]
        via: Plane,
    },

    /// Fetch a stored object by its content id (cid); the bytes are re-verified
    /// against the cid before being written.
    Get {
        /// The content id (cid) to fetch (sha256 hex).
        cid: String,
        /// Write the fetched bytes to this path. If omitted, the raw bytes go to
        /// stdout (as bytes, regardless of `--json`).
        #[arg(short, long)]
        output: Option<String>,
        /// The owning DID's namespace to read from (defaults to your own). Use
        /// this to fetch an object another owner has shared with you.
        #[arg(long)]
        owner: Option<String>,
        /// Byte-path to fetch over: `pds` (the default) or `s3` (both address
        /// the same digest).
        #[arg(long, value_enum, default_value_t = Plane::Pds)]
        via: Plane,
    },

    /// Show the running meter (receipts, bytes, postage) for your identity.
    /// Owner-only, `id:` plane.
    Meter,

    /// List the content ids stored under your identity (omitting any you may not
    /// read). `id:` plane.
    Ls,

    /// Show per-object sizes + total for **your own** namespace (`du`). Self-only:
    /// the server never reports another DID's usage. (An operator may lock `du` to
    /// admins via `CISS_ADMIN_ONLY_DU`.)
    Du,

    /// Manage a per-object read ACL (gated reads).
    #[command(subcommand)]
    Acl(AclCommand),

    /// Back up a directory to your namespace (chunked, dedup'd, keep-set
    /// committed) or restore it. File-sync M1; `id:` plane only — the keep-set
    /// manifest must be signed by the namespace key.
    #[command(subcommand)]
    Sync(SyncCommand),

    /// Emit a roff man page for `ciss-ctl` to stdout (used by packaging).
    #[command(hide = true)]
    Man,
}

#[derive(Subcommand, Debug)]
enum SyncCommand {
    /// Chunk `dir`, upload only the chunks the server lacks plus the
    /// fs-manifest blob, then commit the keep-set manifest (strictly newer
    /// seq). Uses a per-tree state root (scan fast-path + placeholders) so
    /// evicted files stay part of the committed tree. Set RUST_LOG=info to
    /// see the have/want and pricing lines.
    Backup {
        /// The directory to back up.
        dir: String,
        /// Override the state root (default: $XDG_DATA_HOME/ciss-ctl/sync/<tree-id>).
        #[arg(long)]
        state_dir: Option<String>,
        /// Run stateless: no scan index, no placeholder merge. An evicted
        /// file would fall out of the committed tree — refuse to combine
        /// with prior evictions.
        #[arg(long)]
        no_state: bool,
    },
    /// Drop a file's local bytes while keeping it in the backed-up tree.
    /// Refused unless every chunk is already on the server AND in the
    /// committed keep-set; chunks are spilled into the local cache (within
    /// its budget) for cheap re-hydration.
    Evict {
        /// The synced directory.
        dir: String,
        /// Manifest-relative paths to evict (e.g. `docs/big.bin`).
        #[arg(required = true)]
        paths: Vec<String>,
        /// Override the state root.
        #[arg(long)]
        state_dir: Option<String>,
    },
    /// Converge with the other devices of this account: commit local state,
    /// fold every device's head deterministically (conflicts preserved as
    /// `<path>.conflict-<device>` copies, never lost), materialize the folded
    /// tree, and publish it as this device's new head.
    Converge {
        /// The synced directory.
        dir: String,
        /// Override the state root.
        #[arg(long)]
        state_dir: Option<String>,
    },
    /// Bring evicted files' bytes back — from the local cache when it still
    /// holds them (no metered egress), from the server when it doesn't —
    /// verified either way. Refuses to overwrite a file that reappeared.
    Hydrate {
        /// The synced directory.
        dir: String,
        /// Manifest-relative paths to hydrate; omitted = every evicted file.
        paths: Vec<String>,
        /// Override the state root.
        #[arg(long)]
        state_dir: Option<String>,
    },
    /// Show the tree's sync state: present vs evicted files, cache usage
    /// against its budget, and the committed keep-set seq.
    Status {
        /// The synced directory.
        dir: String,
        /// Override the state root.
        #[arg(long)]
        state_dir: Option<String>,
    },
    /// Reconstruct a backed-up tree into `dir`, verifying every chunk against
    /// its content address before it is written. With no `--manifest`, the
    /// fs-manifest is discovered from the keep-set (cold restore).
    Restore {
        /// The directory to restore into.
        dir: String,
        /// The fs-manifest cid to restore from (from the backup report);
        /// omitted = cold-restore discovery.
        #[arg(long)]
        manifest: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum KeyCommand {
    /// Generate a fresh native ed25519 identity.
    Gen,
    /// List every profile that has an identity, with its DID/account (orient
    /// before key work). Read-only.
    List,
    /// Show the active identity's DID and public key.
    Show,
    /// Import an existing OpenSSH ed25519 private key as a CISS identity.
    Import {
        /// Path to the OpenSSH private key (e.g. `~/.ssh/id_ed25519`).
        path: String,
    },
}

#[derive(Subcommand, Debug)]
enum AclCommand {
    /// Set the read policy on an object.
    Set {
        /// The object's content id (cid).
        cid: String,
        /// Read class: who may read the object.
        #[arg(long, value_enum)]
        class: ReadClassArg,
        /// Grantee DIDs (comma-separated); used with `--class grantees` — an empty
        /// list grants no one but the owner. Must be empty for `world`/`owner`.
        #[arg(long, value_delimiter = ',')]
        readers: Vec<String>,
    },
    /// Read the current policy on an object.
    Get {
        /// The object's content id (cid).
        cid: String,
    },
}

/// Print a DID as plain text, or `{"did":…}` under `--json`.
fn print_did(did: &str, json: bool) {
    if json {
        println!("{}", serde_json::json!({ "did": did }));
    } else {
        println!("{did}");
    }
}

/// Build an HTTP client for the CISS server, carrying the `-v` verbosity so every
/// request's outcome is logged when asked.
fn server_client(global: &GlobalArgs) -> client::Client {
    client::Client::new(&global.server).with_verbose(global.verbose)
}

/// `ciss-ctl login`: read the app password (env `CISS_PDS_APP_PASSWORD` or a
/// no-echo prompt), verify it against the PDS with a real login (so a bad
/// credential fails now, not on first use), and persist it to the profile's
/// `pds.json` at 0600. The password never touches the CISS server — only the
/// PDS, and only to obtain the short-lived tokens the `did:` commands relay.
async fn login(
    global: &GlobalArgs,
    config: &config::Config,
    pds: &str,
    identifier: &str,
) -> anyhow::Result<()> {
    let app_password = match std::env::var("CISS_PDS_APP_PASSWORD") {
        Ok(p) if !p.is_empty() => p,
        _ => rpassword::prompt_password(format!("app password for {identifier} at {pds}: "))
            .context("read app password")?,
    };
    let cred = atproto::PdsCredential {
        pds_host: pds.to_owned(),
        identifier: identifier.to_owned(),
        app_password,
    };

    // Verify the credential (and learn the account DID) before storing it.
    let http = reqwest::Client::new();
    let session = atproto::create_session(&http, &cred).await?;
    atproto::save_credential(config, &cred)?;

    if global.json {
        println!(
            "{}",
            serde_json::json!({
                "did": session.did,
                "identifier": identifier,
                "profile": global.profile,
            })
        );
    } else {
        println!(
            "logged in as {identifier} ({}) — credential saved to profile '{}'.",
            session.did, global.profile
        );
        println!("run `did:` commands with:  ciss-ctl --identity did --profile {} …", global.profile);
    }
    Ok(())
}

/// The lexicon method uploadBlob binds a `did:` service-auth token to.
const UPLOAD_LXM: &str = "com.atproto.repo.uploadBlob";
/// The lexicon method listBlobs binds a `did:` service-auth token to.
const LISTBLOBS_LXM: &str = "com.atproto.sync.listBlobs";
/// The lexicon method usage inspection (`du`) binds a `did:` token to (ADR 0003).
const DU_LXM: &str = "ing.croft.ciss.du";
/// The lexicon methods a Model-C `did:` owner's policy set/read tokens bind to.
const SET_POLICY_LXM: &str = "ing.croft.ciss.setPolicy";
const GET_POLICY_LXM: &str = "ing.croft.ciss.getPolicy";

/// Resolve the token `aud`: the explicit `--aud`, else the service DID the server
/// advertises.
async fn resolve_aud(global: &GlobalArgs, http: &client::Client) -> anyhow::Result<String> {
    match &global.aud {
        Some(aud) => Ok(aud.clone()),
        None => http.discover_service_did().await,
    }
}

/// `--identity did put --via pds`: log in to the PDS, mint a service-auth JWT, and
/// upload the blob under it. `--via s3` is refused (no local signing key exists in
/// a `did:` profile) rather than silently mis-signed.
async fn did_put(
    global: &GlobalArgs,
    config: &config::Config,
    file: &Path,
    via: Plane,
) -> anyhow::Result<()> {
    if via == Plane::S3 {
        anyhow::bail!(
            "--via s3 needs an id: identity (a local signing key); a did: identity uses \
             the atproto plane — retry with --via pds"
        );
    }
    let cred = atproto::load_credential(config)?;
    let pds = reqwest::Client::new();
    let server = server_client(global);
    let aud = resolve_aud(global, &server).await?;
    let (token, _account_did) = atproto::mint_service_auth(&pds, &cred, &aud, UPLOAD_LXM).await?;
    let body = std::fs::read(file).with_context(|| format!("read {}", file.display()))?;
    let res = server.upload_blob_bearer(&token, &body).await?;
    if global.json {
        println!(
            "{}",
            serde_json::json!({"cid": res.cid, "cidv1": res.cidv1, "bytes": res.bytes, "via": "pds"})
        );
    } else {
        println!("uploaded via pds (did: service-auth)");
        println!("  cid:   {}", res.cid);
        println!("  cidv1: {}", res.cidv1);
        println!("  bytes: {}", res.bytes);
    }
    Ok(())
}

/// `--identity did get --via pds`: resolve the account DID (via login) and read
/// the blob back (public). `--via s3` is refused for symmetry with `did_put`.
async fn did_get(
    global: &GlobalArgs,
    config: &config::Config,
    cid: &str,
    output: Option<&Path>,
    owner: Option<String>,
    via: Plane,
) -> anyhow::Result<()> {
    if via == Plane::S3 {
        anyhow::bail!("a did: identity reads over the atproto plane — retry with --via pds");
    }
    // Read from an explicit --owner namespace if given; otherwise log in to learn
    // this account's own DID. A `did:` read over the atproto plane is public
    // (world) here; a gated `did:` read via a service-auth bearer is Model C.
    let namespace = match owner {
        Some(owner) => owner,
        None => {
            let cred = atproto::load_credential(config)?;
            let pds = reqwest::Client::new();
            atproto::create_session(&pds, &cred).await?.did
        }
    };
    let server = server_client(global);
    commands::object::get(&server, None, &namespace, cid, output, via, global.json).await
}

/// `--identity did acl set` (Model C): mint a getPolicy + setPolicy service-auth
/// JWT and have CISS provider-attest the policy for the account's own object.
async fn did_acl_set(
    global: &GlobalArgs,
    config: &config::Config,
    cid: &str,
    class: &str,
    readers: &[String],
) -> anyhow::Result<()> {
    let cred = atproto::load_credential(config)?;
    let pds = reqwest::Client::new();
    let server = server_client(global);
    let aud = resolve_aud(global, &server).await?;
    let (owner_did, tokens) =
        atproto::service_auth_tokens(&pds, &cred, &aud, &[GET_POLICY_LXM, SET_POLICY_LXM]).await?;
    commands::acl::set_model_c(
        &server,
        &owner_did,
        cid,
        class,
        readers,
        (&tokens[0], &tokens[1]),
        global.json,
    )
    .await
}

/// `--identity did acl get` (Model C): mint a getPolicy JWT and read the policy back.
async fn did_acl_get(
    global: &GlobalArgs,
    config: &config::Config,
    cid: &str,
) -> anyhow::Result<()> {
    let cred = atproto::load_credential(config)?;
    let pds = reqwest::Client::new();
    let server = server_client(global);
    let aud = resolve_aud(global, &server).await?;
    let (owner_did, tokens) =
        atproto::service_auth_tokens(&pds, &cred, &aud, &[GET_POLICY_LXM]).await?;
    commands::acl::get_model_c(&server, &owner_did, cid, &tokens[0], global.json).await
}

async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let config = config::Config::new(&cli.global.profile)?;
    match cli.command {
        Commands::Key(KeyCommand::Gen) => {
            let did = identity::generate(&config)?;
            print_did(&did, cli.global.json);
            Ok(())
        }
        Commands::Key(KeyCommand::List) => {
            commands::key::list(&config, &cli.global.profile, cli.global.json)
        }
        Commands::Key(KeyCommand::Show) => {
            let (did, public_key) = identity::show(&config)?;
            if cli.global.json {
                println!("{}", serde_json::json!({ "did": did, "public_key": public_key }));
            } else {
                println!("DID:        {did}");
                println!("public key: {public_key}");
            }
            Ok(())
        }
        Commands::Key(KeyCommand::Import { path }) => {
            let did = identity::import(&config, std::path::Path::new(&path))?;
            print_did(&did, cli.global.json);
            Ok(())
        }
        Commands::Login { pds, identifier } => {
            login(&cli.global, &config, &pds, &identifier).await
        }
        Commands::Whoami => {
            let did = identity::whoami(&config)?;
            print_did(&did, cli.global.json);
            Ok(())
        }
        Commands::Put { file, via } => match cli.global.identity {
            IdentityKind::Id => {
                let session = client::session_for(&identity::load_keypair(&config)?);
                let http = server_client(&cli.global);
                commands::object::put(&http, &session, Path::new(&file), via, cli.global.json).await
            }
            IdentityKind::Did => did_put(&cli.global, &config, Path::new(&file), via).await,
        },
        Commands::Get { cid, output, owner, via } => match cli.global.identity {
            IdentityKind::Id => {
                let keypair = identity::load_keypair(&config)?;
                let session = client::session_for(&keypair);
                let did = owner.unwrap_or_else(|| session.did.clone());
                let http = server_client(&cli.global);
                commands::object::get(
                    &http,
                    Some(&session),
                    &did,
                    &cid,
                    output.as_deref().map(Path::new),
                    via,
                    cli.global.json,
                )
                .await
            }
            IdentityKind::Did => {
                did_get(&cli.global, &config, &cid, output.as_deref().map(Path::new), owner, via)
                    .await
            }
        },
        Commands::Meter => {
            require_id_plane(cli.global.identity, "meter")?;
            let session = client::session_for(&identity::load_keypair(&config)?);
            let http = server_client(&cli.global);
            commands::object::meter(&http, &session, cli.global.json).await
        }
        Commands::Ls => match cli.global.identity {
            IdentityKind::Id => {
                let keypair = identity::load_keypair(&config)?;
                let session = client::session_for(&keypair);
                let http = server_client(&cli.global);
                commands::object::ls(&http, Some(&session), &session.did, cli.global.json).await
            }
            IdentityKind::Did => did_ls(&cli.global, &config).await,
        },
        Commands::Sync(SyncCommand::Backup { dir, state_dir, no_state }) => {
            match cli.global.identity {
                IdentityKind::Id => {
                    sync_backup(&cli.global, &config, &dir, state_dir.as_deref(), no_state).await
                }
                IdentityKind::Did => anyhow::bail!(
                    "sync uses the id: identity — the keep-set manifest must be signed by the namespace key"
                ),
            }
        }
        Commands::Sync(SyncCommand::Evict { dir, paths, state_dir }) => {
            match cli.global.identity {
                IdentityKind::Id => {
                    sync_evict(&cli.global, &config, &dir, &paths, state_dir.as_deref()).await
                }
                IdentityKind::Did => anyhow::bail!(
                    "sync uses the id: identity — the keep-set manifest must be signed by the namespace key"
                ),
            }
        }
        Commands::Sync(SyncCommand::Converge { dir, state_dir }) => match cli.global.identity {
            IdentityKind::Id => {
                sync_converge(&cli.global, &config, &dir, state_dir.as_deref()).await
            }
            IdentityKind::Did => anyhow::bail!(
                "sync uses the id: identity — the keep-set manifest must be signed by the namespace key"
            ),
        },
        Commands::Sync(SyncCommand::Hydrate { dir, paths, state_dir }) => {
            match cli.global.identity {
                IdentityKind::Id => {
                    sync_hydrate(&cli.global, &config, &dir, &paths, state_dir.as_deref()).await
                }
                IdentityKind::Did => anyhow::bail!(
                    "sync uses the id: identity — the keep-set manifest must be signed by the namespace key"
                ),
            }
        }
        Commands::Sync(SyncCommand::Status { dir, state_dir }) => match cli.global.identity {
            IdentityKind::Id => {
                sync_status(&cli.global, &config, &dir, state_dir.as_deref()).await
            }
            IdentityKind::Did => anyhow::bail!(
                "sync uses the id: identity — the keep-set manifest must be signed by the namespace key"
            ),
        },
        Commands::Sync(SyncCommand::Restore { dir, manifest }) => match cli.global.identity {
            IdentityKind::Id => sync_restore(&cli.global, &config, &dir, manifest.as_deref()).await,
            IdentityKind::Did => anyhow::bail!(
                "sync uses the id: identity — the keep-set manifest must be signed by the namespace key"
            ),
        },
        Commands::Du => match cli.global.identity {
            IdentityKind::Id => {
                let keypair = identity::load_keypair(&config)?;
                let session = client::session_for(&keypair);
                let http = server_client(&cli.global);
                let usage = http.du(Some(&session), &session.did).await?;
                commands::object::print_usage(&usage, cli.global.json);
                Ok(())
            }
            IdentityKind::Did => did_du(&cli.global, &config).await,
        },
        Commands::Acl(AclCommand::Set { cid, class, readers }) => match cli.global.identity {
            IdentityKind::Id => {
                let keypair = identity::load_keypair(&config)?;
                let http = server_client(&cli.global);
                commands::acl::set(&http, &keypair, &cid, class.as_str(), &readers, cli.global.json)
                    .await
            }
            IdentityKind::Did => {
                did_acl_set(&cli.global, &config, &cid, class.as_str(), &readers).await
            }
        },
        Commands::Acl(AclCommand::Get { cid }) => match cli.global.identity {
            IdentityKind::Id => {
                let keypair = identity::load_keypair(&config)?;
                let http = server_client(&cli.global);
                commands::acl::get(&http, &keypair, &cid, cli.global.json).await
            }
            IdentityKind::Did => did_acl_get(&cli.global, &config, &cid).await,
        },
        Commands::Man => emit_man_page(),
    }
}

/// Reject a `did:`-plane invocation of a command the **server** only exposes to an
/// `id:` session, with a clear message (rather than the confusing "no identity —
/// run key gen" a missing local key gives). Currently only `meter`: the server's
/// meter endpoint authenticates an `id:` session, so `did:` metering would need a
/// server change.
fn require_id_plane(identity: IdentityKind, command: &str) -> anyhow::Result<()> {
    if identity == IdentityKind::Did {
        anyhow::bail!(
            "`{command}` is not available for a did: identity — the server authenticates \
             this endpoint with an id: session. Run it under an id: profile (omit \
             `--identity did`)."
        );
    }
    Ok(())
}

/// `--identity did du`: relay a `du`-scoped service-auth JWT and report usage for
/// the account's own DID (self-only; the server never serves another DID's usage).
async fn did_du(global: &GlobalArgs, config: &config::Config) -> anyhow::Result<()> {
    let cred = atproto::load_credential(config)?;
    let pds = reqwest::Client::new();
    let server = server_client(global);
    let aud = resolve_aud(global, &server).await?;
    let (account_did, tokens) =
        atproto::service_auth_tokens(&pds, &cred, &aud, &[DU_LXM]).await?;
    let usage = server.du_bearer(&tokens[0], &account_did).await?;
    commands::object::print_usage(&usage, global.json);
    Ok(())
}

/// `--identity did ls`: relay a `listBlobs`-scoped service-auth JWT and list the
/// account's own blobs over the atproto plane.
async fn did_ls(global: &GlobalArgs, config: &config::Config) -> anyhow::Result<()> {
    let cred = atproto::load_credential(config)?;
    let pds = reqwest::Client::new();
    let server = server_client(global);
    let aud = resolve_aud(global, &server).await?;
    let (account_did, tokens) =
        atproto::service_auth_tokens(&pds, &cred, &aud, &[LISTBLOBS_LXM]).await?;
    let cids = server.list_blobs_bearer(&tokens[0], &account_did).await?;
    commands::object::print_cids(&cids, global.json);
    Ok(())
}

/// Render the clap command tree to a roff man page on stdout. Packaging installs
/// the result as `ciss-ctl.1`.
fn emit_man_page() -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut buf = Vec::new();
    clap_mangen::Man::new(Cli::command())
        .render(&mut buf)
        .context("render man page")?;
    std::io::stdout().write_all(&buf).context("write man page")?;
    Ok(())
}

/// Resolve the state root for a synced tree (explicit override, or the
/// per-tree default under the user's data dir).
fn resolve_state(
    global: &GlobalArgs,
    dir: &str,
    state_dir: Option<&str>,
) -> anyhow::Result<ciss_sync::SyncState> {
    let root = match state_dir {
        Some(p) => std::path::PathBuf::from(p),
        None => sync::default_state_dir(&global.profile, std::path::Path::new(dir))?,
    };
    Ok(ciss_sync::SyncState::open(root)?)
}

/// Run a backup for the active `id:` identity and print the report.
async fn sync_backup(
    global: &GlobalArgs,
    config: &config::Config,
    dir: &str,
    state_dir: Option<&str>,
    no_state: bool,
) -> anyhow::Result<()> {
    let keypair = identity::load_keypair(config)?;
    let server = sync::HttpCiss::new(server_client(global), keypair);
    if no_state {
        if let Ok(existing) = resolve_state(global, dir, state_dir) {
            anyhow::ensure!(
                existing.placeholders.all()?.is_empty(),
                "--no-state refused: this tree has evicted files; a stateless backup would drop \
                 them from the committed tree"
            );
        }
        // Stateless = the M1 path: no index, no placeholders, no frontier.
        let report = ciss_sync::backup(std::path::Path::new(dir), &server, None).await?;
        return print_backup_report(global, report.files, report.chunks_total,
            report.chunks_uploaded, report.bytes_uploaded, &report.fs_manifest_cid,
            report.manifest_seq, None);
    }
    // The frontier path (M3): publish this device's head, commit non-lossily.
    let mut state = resolve_state(global, dir, state_dir)?;
    let device = sync::device_id(config)?;
    let report =
        ciss_sync::backup_frontier(std::path::Path::new(dir), &server, &mut state, &device)
            .await?;
    print_backup_report(global, report.files, report.chunks_total, report.chunks_uploaded,
        report.bytes_uploaded, &report.fs_manifest_cid, report.manifest_seq,
        Some(&report.device_head_cid))
}

/// Shared report printer for the stateless and frontier backup paths.
#[allow(clippy::too_many_arguments)]
fn print_backup_report(
    global: &GlobalArgs,
    files: u64,
    chunks_total: u64,
    chunks_uploaded: u64,
    bytes_uploaded: u64,
    fs_manifest_cid: &str,
    manifest_seq: u64,
    device_head_cid: Option<&str>,
) -> anyhow::Result<()> {
    if global.json {
        println!(
            "{}",
            serde_json::json!({
                "files": files,
                "chunks_total": chunks_total,
                "chunks_uploaded": chunks_uploaded,
                "bytes_uploaded": bytes_uploaded,
                "fs_manifest_cid": fs_manifest_cid,
                "manifest_seq": manifest_seq,
                "device_head_cid": device_head_cid,
            })
        );
    } else {
        let head_note = device_head_cid
            .map(|c| format!(", device head {}", &c[..c.len().min(12)]))
            .unwrap_or_default();
        println!(
            "backed up {files} files: {chunks_uploaded}/{chunks_total} chunks uploaded \
             ({bytes_uploaded} bytes), fs-manifest {fs_manifest_cid}, keep-set seq {manifest_seq}{head_note}"
        );
    }
    Ok(())
}

/// Evict files for the active `id:` identity and print the report.
async fn sync_evict(
    global: &GlobalArgs,
    config: &config::Config,
    dir: &str,
    paths: &[String],
    state_dir: Option<&str>,
) -> anyhow::Result<()> {
    let keypair = identity::load_keypair(config)?;
    let server = sync::HttpCiss::new(server_client(global), keypair);
    let mut state = resolve_state(global, dir, state_dir)?;
    let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    let report =
        ciss_sync::evict(std::path::Path::new(dir), &mut state, &server, &path_refs).await?;
    if global.json {
        println!(
            "{}",
            serde_json::json!({
                "evicted": report.evicted,
                "bytes_freed": report.bytes_freed,
                "chunks_cached": report.chunks_cached,
            })
        );
    } else {
        println!(
            "evicted {} file(s): {} bytes freed, {} chunk(s) kept in the local cache",
            report.evicted, report.bytes_freed, report.chunks_cached,
        );
    }
    Ok(())
}

/// Converge with the account's other devices and print the report.
async fn sync_converge(
    global: &GlobalArgs,
    config: &config::Config,
    dir: &str,
    state_dir: Option<&str>,
) -> anyhow::Result<()> {
    let keypair = identity::load_keypair(config)?;
    let server = sync::HttpCiss::new(server_client(global), keypair);
    let mut state = resolve_state(global, dir, state_dir)?;
    let device = sync::device_id(config)?;
    let report =
        ciss_sync::converge(std::path::Path::new(dir), &mut state, &server, &device).await?;
    if global.json {
        println!(
            "{}",
            serde_json::json!({
                "files": report.files,
                "files_written": report.files_written,
                "files_deleted": report.files_deleted,
                "conflicts": report.conflicts,
                "fs_manifest_cid": report.fs_manifest_cid,
                "manifest_seq": report.manifest_seq,
            })
        );
    } else {
        println!(
            "converged: {} files ({} written, {} deleted), fs-manifest {}, seq {}",
            report.files,
            report.files_written,
            report.files_deleted,
            report.fs_manifest_cid,
            report.manifest_seq,
        );
        for c in &report.conflicts {
            println!("  conflict preserved: {c}");
        }
    }
    Ok(())
}

/// Hydrate evicted files for the active `id:` identity and print the report.
async fn sync_hydrate(
    global: &GlobalArgs,
    config: &config::Config,
    dir: &str,
    paths: &[String],
    state_dir: Option<&str>,
) -> anyhow::Result<()> {
    let keypair = identity::load_keypair(config)?;
    let server = sync::HttpCiss::new(server_client(global), keypair);
    let mut state = resolve_state(global, dir, state_dir)?;
    let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    let selection = if path_refs.is_empty() { None } else { Some(path_refs.as_slice()) };
    let report =
        ciss_sync::hydrate(std::path::Path::new(dir), &mut state, &server, selection).await?;
    if global.json {
        println!(
            "{}",
            serde_json::json!({
                "files": report.files,
                "chunks_from_cache": report.chunks_from_cache,
                "chunks_from_server": report.chunks_from_server,
                "bytes_written": report.bytes_written,
            })
        );
    } else {
        println!(
            "hydrated {} file(s): {} bytes ({} chunk(s) from cache, {} from the server)",
            report.files, report.bytes_written, report.chunks_from_cache, report.chunks_from_server,
        );
    }
    Ok(())
}

/// Count regular files under `dir` (symlinks and other non-files skipped).
fn count_files(dir: &std::path::Path) -> anyhow::Result<u64> {
    let mut n = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            n += count_files(&entry.path())?;
        } else if ft.is_file() {
            n += 1;
        }
    }
    Ok(n)
}

/// Show local sync state + the committed keep-set seq.
async fn sync_status(
    global: &GlobalArgs,
    config: &config::Config,
    dir: &str,
    state_dir: Option<&str>,
) -> anyhow::Result<()> {
    let keypair = identity::load_keypair(config)?;
    let server = sync::HttpCiss::new(server_client(global), keypair);
    let state = resolve_state(global, dir, state_dir)?;
    let placeholders = state.placeholders.all()?;
    let present = count_files(std::path::Path::new(dir))?;
    let cache_bytes = state.cache.total_bytes()?;
    let seq = server.client().get_manifest(server.did()).await?.map(|m| m.seq());
    if global.json {
        println!(
            "{}",
            serde_json::json!({
                "present_files": present,
                "evicted_files": placeholders.len(),
                "evicted_paths": placeholders.keys().collect::<Vec<_>>(),
                "cache_bytes": cache_bytes,
                "cache_budget": state.cache.budget(),
                "keep_set_seq": seq,
            })
        );
    } else {
        println!(
            "{present} file(s) present, {} evicted; cache {cache_bytes}/{} bytes; keep-set seq {}",
            placeholders.len(),
            state.cache.budget(),
            seq.map_or_else(|| "none".to_owned(), |s| s.to_string()),
        );
        for path in placeholders.keys() {
            println!("  evicted: {path}");
        }
    }
    Ok(())
}

/// Run a restore for the active `id:` identity and print the report.
async fn sync_restore(
    global: &GlobalArgs,
    config: &config::Config,
    dir: &str,
    manifest: Option<&str>,
) -> anyhow::Result<()> {
    let keypair = identity::load_keypair(config)?;
    let server = sync::HttpCiss::new(server_client(global), keypair);
    let report = ciss_sync::restore(std::path::Path::new(dir), &server, manifest).await?;
    if global.json {
        println!(
            "{}",
            serde_json::json!({
                "files": report.files,
                "chunks_fetched": report.chunks_fetched,
                "bytes_fetched": report.bytes_fetched,
                "fs_manifest_cid": report.fs_manifest_cid,
            })
        );
    } else {
        println!(
            "restored {} files: {} chunks fetched ({} bytes), fs-manifest {}",
            report.files, report.chunks_fetched, report.bytes_fetched, report.fs_manifest_cid,
        );
    }
    Ok(())
}

/// Engine diagnostics (`ciss-sync`'s tracing) surface via `RUST_LOG`, default
/// `warn` so plain CLI output stays clean — the server's `init_tracing`
/// convention (OQ6).
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    fmt().with_env_filter(filter).with_writer(std::io::stderr).init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    dispatch(Cli::parse()).await
}
