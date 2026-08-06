//! `ciss-ctl` — the CISS client CLI.
//!
//! Phase 1 establishes the command surface: the clap root parser, the global
//! flags every subcommand shares, and explicit not-yet-implemented stubs that
//! each later phase replaces with real behaviour. Stubs fail loudly (a named
//! error, non-zero exit) rather than succeeding silently, so an unimplemented
//! path is never mistaken for a working one.

use clap::{Args, Parser, Subcommand};

mod config;
mod identity;

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

/// Which byte-path a transfer uses. Both land at the same backend digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Plane {
    /// S3-compatible metered plane (`PUT/GET /{did}/objects/{key}`).
    S3,
    /// atproto blob plane (`uploadBlob`/`getBlob`).
    Pds,
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

/// A subcommand whose implementation lands in a later phase. Fails loudly so an
/// unimplemented path can never be mistaken for a working one.
fn not_yet_implemented(what: &str, phase: &str) -> anyhow::Error {
    anyhow::anyhow!("`{what}` is not implemented yet (arrives in {phase})")
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

fn dispatch(cli: Cli) -> anyhow::Result<()> {
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
        Commands::Put { .. } => Err(not_yet_implemented("put", "Phase 4")),
        Commands::Get { .. } => Err(not_yet_implemented("get", "Phase 4")),
        Commands::Meter => Err(not_yet_implemented("meter", "Phase 4")),
        Commands::Ls => Err(not_yet_implemented("ls", "Phase 5")),
        Commands::Acl(AclCommand::Set { .. }) => Err(not_yet_implemented("acl set", "Phase 8a")),
        Commands::Acl(AclCommand::Get { .. }) => Err(not_yet_implemented("acl get", "Phase 8a")),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dispatch(Cli::parse())
}
