// SPDX-FileCopyrightText: 2025 blinry <mail@blinry.org>
// SPDX-FileCopyrightText: 2025 zormit <nt4u@kpvn.de>
// SPDX-FileCopyrightText: 2026 axelmartensson <axel.martensson@hotmail.com>
// SPDX-FileCopyrightText: 2026 TNG Technology Consulting GmbH <christoph.niehoff@tngtech.com>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

fn get_version() -> &'static str {
    let version = env!("CARGO_PKG_VERSION");
    let git_hash = option_env!("GIT_HASH");
    let commit_date = option_env!("GIT_COMMIT_DATE");
    let is_dirty = option_env!("GIT_DIRTY").unwrap_or("false") == "true";

    let version = match (git_hash, commit_date) {
        (Some(hash), Some(date)) if hash != "unknown" && date != "unknown" => {
            let dirty_suffix = if is_dirty { "-modified" } else { "" };
            format!("{version} ({hash}{dirty_suffix} {date})")
        }
        _ => version.to_string(),
    };
    Box::leak(version.into_boxed_str())
}

// TODO: Define these constants in the teamtype crate, and use them here.
#[derive(Parser)]
#[command(version=get_version(), about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    /// The shared directory. Defaults to current directory.
    #[arg(long, global = true)]
    pub directory: Option<PathBuf>,
}

#[derive(Args)]
pub struct ShareJoinFlags {
    /// EXPERIMENTAL: Also synchronize version-control directories like .git/ or .jj/, which are normally
    /// ignored. For Git, this will synchronize all branches, commits, etc. as well as your .git/config.
    /// This means that new commits will immediately appear at all peers, you can change branches together, etc.
    #[arg(long)]
    pub sync_vcs: bool,
    /// Use an alternative Magic Wormhole mailbox server relay url
    #[arg(long)]
    pub magic_wormhole_relay: Option<String>,
    /// Use an alternative iroh relay server URL for peer-to-peer connections.
    /// When set, replaces n0's default relay servers. Format: https://relay.example.com
    #[arg(long)]
    pub relay: Option<String>,
    /// Use an alternative pkarr discovery relay URL for node address publishing and resolving.
    /// When set, replaces n0's default discovery infrastructure. Format: https://discovery.example.com/pkarr
    #[arg(long)]
    pub discovery: Option<String>,
    #[arg(long)]
    /// The name that others see next to your cursor. Defaults to your Git username.
    pub username: Option<String>,
    /// JWT bearer token for authenticating with the host.
    /// Required when the host is configured with --allowed-users.
    #[arg(long)]
    pub auth_token: Option<String>,
    /// Create a new temporary directory and use it as the shared directory.
    /// The temporary directory is removed on exit.
    /// The temporary directory is created in `$XDG_CACHE_DIR/teamtype/`,
    /// or if `XDG_CACHE_DIR` is not set in `$HOME/.cache/teamtype/`,
    /// or if `HOME` is not set in `/home/$USER/.cache/teamtype/`.
    #[arg(short, long)]
    pub temporary_directory: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Share a directory with a new peer.
    Share {
        /// Re-initialize the history of the shared directory. You will loose previous history.
        #[arg(long)]
        init: bool,
        /// Do not generate a join code. To prevent unintended sharing or simply if you want to
        /// keep Magic Wormhole out of the loop.
        #[arg(long)]
        no_join_code: bool,
        /// Print the secret address. Useful for sharing with multiple people.
        #[arg(long)]
        show_secret_address: bool,
        /// Comma-separated list of allowed values for the JWT username claim.
        /// When set, joining peers must present a valid JWT whose username claim
        /// value is in this list. The claim checked is determined by --username-claim.
        /// Requires --jwks-url.
        #[arg(long, value_delimiter = ',')]
        allowed_users: Option<Vec<String>>,
        /// JWKS endpoint URL used to verify incoming JWT signatures.
        /// Example: https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs
        /// Required when --allowed-users is set.
        #[arg(long)]
        jwks_url: Option<String>,
        /// Name of the JWT claim to match against --allowed-users.
        /// Defaults to "sub".
        /// Common alternatives: preferred_username, email, azp.
        #[arg(long)]
        username_claim: Option<String>,
        #[command(flatten)]
        shared_flags: ShareJoinFlags,
    },
    /// Join a shared directory via a join code, or connect to the most recent one.
    Join {
        /// Specify to connect to a new peer. Otherwise, try to connect to the most recent peer.
        join_code: Option<String>,
        #[command(flatten)]
        shared_flags: ShareJoinFlags,
    },
    /// Open a JSON-RPC connection to the Teamtype daemon on stdin/stdout. Used by text editor plugins.
    Client,
}

#[test]
fn verify() {
    use clap::CommandFactory as _;
    Cli::command().debug_assert();
}
