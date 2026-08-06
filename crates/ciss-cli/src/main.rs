//! `ciss-ctl` — the CISS client CLI.
//!
//! Phase 1 establishes the command surface: the clap root parser, the global
//! flags every subcommand shares, and explicit not-yet-implemented stubs that
//! each later phase replaces with real behaviour. Stubs fail loudly (a named
//! error, non-zero exit) rather than succeeding silently, so an unimplemented
//! path is never mistaken for a working one.

use std::path::Path;

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand};

use ciss_cli::{atproto, client, commands, config, identity};

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

use ciss_cli::client::Plane;

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

    /// Increase log verbosity (repeat for more: `-v` request lines, `-vv` bodies).
    /// Secrets (seed, session signature, app password, JWTs) are never logged.
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

    /// Print the DID of the active identity.
    Whoami,

    /// Upload a file and show the bytes transferred.
    Put {
        /// Path to the file to upload.
        file: String,
        /// Which plane to upload over.
        #[arg(long, value_enum, default_value_t = Plane::S3)]
        via: Plane,
    },

    /// Fetch a stored object by its content id (cid).
    Get {
        /// The content id (cid) to fetch.
        cid: String,
        /// Where to write the fetched bytes (stdout if omitted).
        #[arg(short, long)]
        output: Option<String>,
        /// The owning DID's namespace to read from (defaults to your own). Use
        /// this to fetch an object shared with you by another owner.
        #[arg(long)]
        owner: Option<String>,
        /// Which plane to fetch over.
        #[arg(long, value_enum, default_value_t = Plane::S3)]
        via: Plane,
    },

    /// Show the running meter (receipts, bytes, postage) for the active identity.
    Meter,

    /// List the blobs stored under the active identity.
    Ls,

    /// Manage a per-object read ACL (gated reads).
    #[command(subcommand)]
    Acl(AclCommand),
}

#[derive(Subcommand, Debug)]
enum KeyCommand {
    /// Generate a fresh native ed25519 identity.
    Gen,
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
        /// Read class: `world`, `grantees`, or `owner`.
        #[arg(long)]
        class: String,
        /// Grantee DIDs (comma-separated) when `--class grantees`.
        #[arg(long, value_delimiter = ',')]
        readers: Vec<String>,
    },
    /// Read the current policy on an object.
    Get {
        /// The object's content id (cid).
        cid: String,
    },
}

/// Print a DID as plain text or `{"did":…}` under `--json`. DIDs are `id:`/`did:`
/// + hex, so no JSON escaping is needed.
fn print_did(did: &str, json: bool) {
    if json {
        println!("{{\"did\":\"{did}\"}}");
    } else {
        println!("{did}");
    }
}

/// The lexicon method uploadBlob binds a `did:` service-auth token to.
const UPLOAD_LXM: &str = "com.atproto.repo.uploadBlob";
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
    let server = client::Client::new(&global.server);
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
    via: Plane,
) -> anyhow::Result<()> {
    if via == Plane::S3 {
        anyhow::bail!("a did: identity reads over the atproto plane — retry with --via pds");
    }
    let cred = atproto::load_credential(config)?;
    let pds = reqwest::Client::new();
    let account = atproto::create_session(&pds, &cred).await?;
    let server = client::Client::new(&global.server);
    // A `did:` read over the atproto plane is public (world) here; a gated `did:`
    // read via a service-auth bearer is Model C (Phase 8b).
    commands::object::get(&server, None, &account.did, cid, output, via, global.json).await
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
    let server = client::Client::new(&global.server);
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
    let server = client::Client::new(&global.server);
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
        Commands::Key(KeyCommand::Show) => {
            let (did, public_key) = identity::show(&config)?;
            if cli.global.json {
                println!("{{\"did\":\"{did}\",\"public_key\":\"{public_key}\"}}");
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
        Commands::Whoami => {
            let did = identity::whoami(&config)?;
            print_did(&did, cli.global.json);
            Ok(())
        }
        Commands::Put { file, via } => match cli.global.identity {
            IdentityKind::Id => {
                let session = client::session_for(&identity::load_keypair(&config)?);
                let http = client::Client::new(&cli.global.server);
                commands::object::put(&http, &session, Path::new(&file), via, cli.global.json).await
            }
            IdentityKind::Did => did_put(&cli.global, &config, Path::new(&file), via).await,
        },
        Commands::Get { cid, output, owner, via } => match cli.global.identity {
            IdentityKind::Id => {
                let keypair = identity::load_keypair(&config)?;
                let session = client::session_for(&keypair);
                let did = owner.unwrap_or_else(|| session.did.clone());
                let http = client::Client::new(&cli.global.server);
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
                did_get(&cli.global, &config, &cid, output.as_deref().map(Path::new), via).await
            }
        },
        Commands::Meter => {
            let session = client::session_for(&identity::load_keypair(&config)?);
            let http = client::Client::new(&cli.global.server);
            commands::object::meter(&http, &session, cli.global.json).await
        }
        Commands::Ls => {
            let keypair = identity::load_keypair(&config)?;
            let session = client::session_for(&keypair);
            let http = client::Client::new(&cli.global.server);
            commands::object::ls(&http, Some(&session), &session.did, cli.global.json).await
        }
        Commands::Acl(AclCommand::Set { cid, class, readers }) => match cli.global.identity {
            IdentityKind::Id => {
                let keypair = identity::load_keypair(&config)?;
                let http = client::Client::new(&cli.global.server);
                commands::acl::set(&http, &keypair, &cid, &class, &readers, cli.global.json).await
            }
            IdentityKind::Did => did_acl_set(&cli.global, &config, &cid, &class, &readers).await,
        },
        Commands::Acl(AclCommand::Get { cid }) => match cli.global.identity {
            IdentityKind::Id => {
                let keypair = identity::load_keypair(&config)?;
                let http = client::Client::new(&cli.global.server);
                commands::acl::get(&http, &keypair, &cid, cli.global.json).await
            }
            IdentityKind::Did => did_acl_get(&cli.global, &config, &cid).await,
        },
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dispatch(Cli::parse()).await
}
