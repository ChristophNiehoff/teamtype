// SPDX-FileCopyrightText: 2024 blinry <mail@blinry.org>
// SPDX-FileCopyrightText: 2024 zormit <nt4u@kpvn.de>
// SPDX-FileCopyrightText: 2026 TNG Technology Consulting GmbH <christoph.niehoff@tngtech.com>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! This module provides a [`ConnectionManager`], which can be used to connect to other daemons.

use self::sync::{Connection, PeerMessage, SyncActor};
use crate::auth::JwksCache;
use crate::daemon::DocumentActorHandle;
use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use iroh::discovery::{
    ConcurrentDiscovery,
    dns::DnsDiscovery,
    pkarr::{PkarrPublisher, PkarrResolver},
};
use iroh::endpoint::{RecvStream, RelayMode, SendStream};
use iroh::{NodeAddr, RelayMap, RelayUrl, SecretKey};
use postcard::{from_bytes, to_allocvec};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;
use tracing::{debug, info, warn};

mod sync;

const ALPN: &[u8] = b"/teamtype/0";

struct SecretAddress {
    node_addr: NodeAddr,
    passphrase: SecretKey,
}

impl FromStr for SecretAddress {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('#').collect();
        if parts.len() != 2 {
            bail!("Peer string must have format <node_id>#<passphrase>");
        }

        let node_addr = iroh::PublicKey::from_str(parts[0])?.into();
        let passphrase = SecretKey::from_str(parts[1])?;

        Ok(Self {
            node_addr,
            passphrase,
        })
    }
}

/// Sentinel error returned to the joiner when the host explicitly rejects the
/// connection due to a failed JWT check (wrong user, expired token, etc.).
/// Unlike transient network errors, this should not trigger a reconnect.
#[derive(Debug)]
struct AuthRejected;

impl std::fmt::Display for AuthRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Host rejected connection: JWT token missing, expired, or user not in allow list")
    }
}

impl std::error::Error for AuthRejected {}

enum PeerAuth {
    /// Accepting side: verify the passphrase and, when JWT auth is configured,
    /// also validate the JWT and check the subject against the allow list.
    MyPassphrase {
        passphrase: SecretKey,
        jwks: Option<Arc<JwksCache>>,
        allowed_users: Option<Arc<Vec<String>>>,
        username_claim: String,
        audience: Option<String>,
    },
    /// Connecting side: send the passphrase and, when an auth token is present,
    /// also send the JWT and wait for the host's accept/reject response.
    YourPassphrase {
        passphrase: SecretKey,
        auth_token: Option<String>,
    },
}

pub struct ConnectionManager {
    message_tx: mpsc::Sender<EndpointMessage>,
    secret_address: String,
}

impl ConnectionManager {
    pub async fn new(
        document_handle: DocumentActorHandle,
        base_dir: &Path,
        relay: Option<String>,
        discovery: Option<String>,
        allowed_users: Option<Vec<String>>,
        jwks_url: Option<String>,
        username_claim: Option<String>,
        audience: Option<String>,
    ) -> Result<Self> {
        let (message_tx, message_rx) = mpsc::channel(1);

        let (endpoint, my_passphrase) = Self::build_endpoint(base_dir, relay, discovery).await?;

        let secret_address = format!("{}#{}", endpoint.node_id(), my_passphrase);

        // If a JWKS URL is provided, fetch the keys eagerly so that startup fails
        // fast if the JWKS endpoint is unreachable.
        let jwks = if let Some(url) = jwks_url {
            let cache = Arc::new(JwksCache::new(url));
            cache
                .refresh()
                .await
                .context("Failed to fetch JWKS keys on startup")?;
            Some(cache)
        } else {
            None
        };
        let allowed_users = allowed_users.map(Arc::new);
        // Use the configured claim name, falling back to the default "sub".
        let username_claim = username_claim
            .unwrap_or_else(|| crate::auth::DEFAULT_USERNAME_CLAIM.to_owned());

        let mut actor = EndpointActor::new(
            endpoint,
            message_rx,
            message_tx.clone(),
            document_handle,
            my_passphrase,
            jwks,
            allowed_users,
            username_claim,
            audience,
        );

        tokio::spawn(async move { actor.run().await });

        Ok(Self {
            message_tx,
            secret_address,
        })
    }

    #[must_use]
    pub fn secret_address(&self) -> &str {
        &self.secret_address
    }

    pub async fn connect(&self, secret_address: String, auth_token: Option<String>) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();

        self.message_tx
            .send(EndpointMessage::Connect {
                secret_address: SecretAddress::from_str(&secret_address)?,
                response_tx: Some(response_tx),
                previous_attempts: 0,
                auth_token,
            })
            .await
            .expect("EndpointActor task has been killed");

        response_rx.await??;

        Ok(())
    }

    async fn build_endpoint(
        base_dir: &Path,
        relay: Option<String>,
        discovery: Option<String>,
    ) -> Result<(iroh::Endpoint, SecretKey)> {
        let (secret_key, my_passphrase) = Self::get_keypair(base_dir);

        let mut builder = iroh::Endpoint::builder()
            .secret_key(secret_key.clone())
            .alpns(vec![ALPN.to_vec()]);

        match (&relay, &discovery) {
            (None, None) => {
                // Default: use n0's infrastructure (current behavior).
                builder = builder.discovery_n0();
            }
            _ => {
                // Custom: configure relay and discovery separately.
                if let Some(relay_url) = &relay {
                    let url: RelayUrl = relay_url.parse()?;
                    let relay_map = RelayMap::from(url);
                    builder = builder.relay_mode(RelayMode::Custom(relay_map));
                    info!("Using custom iroh relay: {}", relay_url);
                }

                if let Some(discovery_url) = &discovery {
                    let pkarr_url: url::Url = discovery_url.parse()?;
                    let concurrent = ConcurrentDiscovery::from_services(vec![
                        Box::new(PkarrPublisher::new(secret_key.clone(), pkarr_url.clone())),
                        Box::new(PkarrResolver::new(pkarr_url)),
                    ]);
                    builder = builder.discovery(Box::new(concurrent));
                    info!("Using custom pkarr discovery: {}", discovery_url);
                } else {
                    // relay is set but discovery is not: keep n0's discovery services.
                    builder = builder
                        .add_discovery(|sk| Some(PkarrPublisher::n0_dns(sk.clone())))
                        .add_discovery(|_| Some(PkarrResolver::n0_dns()))
                        .add_discovery(|_| Some(DnsDiscovery::n0_dns()));
                }
            }
        }

        let endpoint = builder.bind().await?;
        Ok((endpoint, my_passphrase))
    }

    fn get_keypair(base_dir: &Path) -> (SecretKey, SecretKey) {
        let keyfile = base_dir.join(".teamtype").join("key");
        if keyfile.exists() {
            let metadata =
                fs::metadata(&keyfile).expect("Expected to have access to metadata of the keyfile");

            let current_permissions = metadata.permissions().mode();
            let allowed_permissions = 0o100_600;
            assert!(
                current_permissions == allowed_permissions,
                "For security reasons, please make sure to set the key file to user-readable only (set the permissions to 600)."
            );

            assert!(
                metadata.len() == 64,
                "Your keyfile is not 64 bytes long. This is a sign that it was created by a Teamtype version older than 0.7.0, which is not compatible. Please remove .teamtype/key, and try again."
            );

            debug!("Re-using existing keypair.");
            let mut file = File::open(keyfile).expect("Failed to open key file");

            let mut secret_key = [0; 32];
            file.read_exact(&mut secret_key)
                .expect("Failed to read from key file");

            let mut passphrase = [0; 32];
            file.read_exact(&mut passphrase)
                .expect("Failed to read from key file");

            (
                SecretKey::from_bytes(&secret_key),
                SecretKey::from_bytes(&passphrase),
            )
        } else {
            debug!("Generating new keypair.");
            let secret_key = SecretKey::generate(rand::rngs::OsRng);
            let passphrase = SecretKey::generate(rand::rngs::OsRng);

            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(keyfile)
                .expect("Should have been able to create key file that did not exist before");

            file.write_all(&secret_key.to_bytes())
                .expect("Failed to write to key file");
            file.write_all(&passphrase.to_bytes())
                .expect("Failed to write to key file");

            (secret_key, passphrase)
        }
    }
}

enum EndpointMessage {
    // Instruct the endpoint to connect to a new peer.
    Connect {
        // All information we need to connect to another peer.
        secret_address: SecretAddress,
        // On connection success, this channel will be pinged.
        // Used for the initial connection, where we want to fail if connecting fails.
        response_tx: Option<oneshot::Sender<Result<()>>>,
        // How many times have we already attempted to connect?
        previous_attempts: usize,
        // Optional JWT token to send to the host for allow-list authentication.
        auth_token: Option<String>,
    },
}

// Owns the Iroh endpoint, accepts incoming connections, and can be instructed to connect to
// another daemon.
struct EndpointActor {
    endpoint: iroh::Endpoint,
    message_rx: mpsc::Receiver<EndpointMessage>,
    message_tx: mpsc::Sender<EndpointMessage>,
    document_handle: DocumentActorHandle,
    my_passphrase: SecretKey,
    /// JWKS cache for validating incoming JWT tokens (host side, optional).
    jwks: Option<Arc<JwksCache>>,
    /// Allow list of permitted JWT username claim values (host side, optional).
    allowed_users: Option<Arc<Vec<String>>>,
    /// Name of the JWT claim to match against `allowed_users`.
    username_claim: String,
    /// Optional expected audience value. When `Some`, the JWT's `aud` claim
    /// must contain this string.
    audience: Option<String>,
}

impl EndpointActor {
    #[allow(clippy::too_many_arguments)]
    fn new(
        endpoint: iroh::Endpoint,
        message_rx: mpsc::Receiver<EndpointMessage>,
        message_tx: mpsc::Sender<EndpointMessage>,
        document_handle: DocumentActorHandle,
        my_passphrase: SecretKey,
        jwks: Option<Arc<JwksCache>>,
        allowed_users: Option<Arc<Vec<String>>>,
        username_claim: String,
        audience: Option<String>,
    ) -> Self {
        Self {
            endpoint,
            message_rx,
            message_tx,
            document_handle,
            my_passphrase,
            jwks,
            allowed_users,
            username_claim,
            audience,
        }
    }

    async fn handle_message(&self, message: EndpointMessage) -> Result<()> {
        match message {
            EndpointMessage::Connect {
                secret_address,
                response_tx,
                previous_attempts,
                auth_token,
            } => {
                let node_addr = secret_address.node_addr.clone();
                let connect_result = self.endpoint.connect(node_addr, ALPN).await;
                let conn = match connect_result {
                    Ok(conn) => conn,
                    Err(err) => {
                        if let Some(response_tx) = response_tx {
                            response_tx
                                .send(Err(err))
                                .expect("Connect receiver dropped");
                        }
                        Self::reconnect(
                            self.message_tx.clone(),
                            secret_address,
                            previous_attempts,
                            auth_token,
                        )
                        .await
                        .expect("Failed to initiate reconnection");
                        // Not really Ok, but Ok enough.
                        return Ok(());
                    }
                };

                info!(
                    "Connected to peer: {}",
                    conn.remote_node_id()
                        .expect("Connection should have a node ID")
                );

                let document_handle_clone = self.document_handle.clone();
                let message_tx_clone = self.message_tx.clone();
                tokio::spawn(async move {
                    let result = Self::handle_peer(
                        document_handle_clone,
                        conn,
                        PeerAuth::YourPassphrase {
                            passphrase: secret_address.passphrase.clone(),
                            auth_token: auth_token.clone(),
                        },
                    )
                    .await;

                    match result {
                        Err(ref err) if err.downcast_ref::<AuthRejected>().is_some() => {
                            // The host explicitly rejected our JWT. Retrying
                            // would fail for the same reason. Signal the initial
                            // connect() caller so the process exits via the
                            // normal error path, or exit directly if this is a
                            // reconnect attempt (no response_tx).
                            tracing::error!("{err}");
                            if let Some(tx) = response_tx {
                                let _ = tx.send(Err(anyhow!(AuthRejected)));
                            } else {
                                std::process::exit(1);
                            }
                        }
                        Err(err) => {
                            // Notify the initial caller of the transient failure,
                            // then schedule a reconnect.
                            if let Some(tx) = response_tx {
                                let _ = tx.send(Err(anyhow!("Connection failed: {err}")));
                            }
                            debug!("Error while handling a peer: {:?}", err);
                            Self::reconnect(message_tx_clone, secret_address, 0, auth_token)
                                .await
                                .expect("Failed to initiate reconnection");
                        }
                        Ok(()) => {
                            if let Some(tx) = response_tx {
                                tx.send(Ok(())).expect("Connect receiver dropped");
                            }
                            Self::reconnect(message_tx_clone, secret_address, 0, auth_token)
                                .await
                                .expect("Failed to initiate reconnection");
                        }
                    }
                });
            }
        }
        Ok(())
    }

    async fn reconnect(
        message_tx: mpsc::Sender<EndpointMessage>,
        secret_address: SecretAddress,
        previous_attempts: usize,
        auth_token: Option<String>,
    ) -> Result<()> {
        // Only log at "info" level if this is the first reconnection attempt.
        if previous_attempts == 0 {
            info!(
                "Connection to peer {} lost, will keep trying to reconnect...",
                secret_address.node_addr.node_id
            );
        } else {
            sleep(Duration::from_secs(10)).await;
            debug!(
                "Making another attempt to connect to peer {}...",
                secret_address.node_addr.node_id
            );
        }
        // We don't need to be notified, so we don't need to use the response channel.
        message_tx
            .send(EndpointMessage::Connect {
                secret_address,
                response_tx: None,
                previous_attempts: previous_attempts + 1,
                auth_token,
            })
            .await?;
        Ok(())
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                maybe_incoming = self.endpoint.accept() => {
                    match maybe_incoming {
                        Some(incoming) => {
                            match incoming.await {
                                Ok(conn) => {
                                    self.handle_incoming_connection(conn);
                                }
                                Err(err) => {
                                    debug!("Error while accepting peer connection: {err}");
                                }
                            }
                        }
                        None => {
                            // Endpoint was closed. Let's shut down.
                            break
                        }
                    }
                }
                maybe_message = self.message_rx.recv() => {
                    match maybe_message {
                        Some(message) => {
                            self.handle_message(message).await.expect("Failed to handle endpoint message");
                        }
                        None => {
                            // Our message channel was closed? Let's shut down.
                            break
                        }
                    }
                }
            }
        }
    }

    fn handle_incoming_connection(&self, conn: iroh::endpoint::Connection) {
        let node_id = conn
            .remote_node_id()
            .expect("Connection should have a node ID");

        info!("Peer connected: {}", &node_id);

        let my_passphrase_clone = self.my_passphrase.clone();
        let jwks_clone = self.jwks.clone();
        let allowed_users_clone = self.allowed_users.clone();
        let username_claim_clone = self.username_claim.clone();
        let audience_clone = self.audience.clone();
        let document_handle_clone = self.document_handle.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::handle_peer(
                document_handle_clone,
                conn,
                PeerAuth::MyPassphrase {
                    passphrase: my_passphrase_clone,
                    jwks: jwks_clone,
                    allowed_users: allowed_users_clone,
                    username_claim: username_claim_clone,
                    audience: audience_clone,
                },
            )
            .await
            {
                warn!("Incoming connection failed: {err}");
            }

            info!("Peer disconnected: {node_id}",);
        });
    }

    async fn handle_peer(
        document_handle: DocumentActorHandle,
        conn: iroh::endpoint::Connection,
        auth: PeerAuth,
    ) -> Result<()> {
        let connection = IrohConnection::new(conn, auth).await?;
        let syncer = SyncActor::new(document_handle, Box::new(connection));
        syncer.run().await
    }
}

// Sends/receives PeerMessages to/from and Iroh connection.
struct IrohConnection {
    send: SendStream,
    message_rx: mpsc::Receiver<Result<PeerMessage>>,
}

impl IrohConnection {
    async fn new(conn: iroh::endpoint::Connection, auth: PeerAuth) -> Result<Self> {
        let (send, receive) = match auth {
            PeerAuth::YourPassphrase {
                passphrase,
                auth_token,
            } => {
                let (mut send, mut recv) = conn.open_bi().await?;

                // Send passphrase (existing protocol).
                send.write_all(&passphrase.to_bytes()).await?;

                if let Some(token) = auth_token {
                    // Send JWT length + JWT bytes.
                    let jwt_bytes = token.as_bytes();
                    let jwt_len =
                        u32::try_from(jwt_bytes.len()).context("JWT token length overflows u32")?;
                    send.write_all(&jwt_len.to_be_bytes()).await?;
                    send.write_all(jwt_bytes).await?;

                    // Read the host's accept (0x01) or reject (0x00) response.
                    let mut response = [0u8; 1];
                    recv.read_exact(&mut response).await?;
                    if response[0] != 1 {
                        // Use a typed error so the caller can distinguish an
                        // explicit auth rejection from a transient network error
                        // and avoid attempting to reconnect.
                        return Err(anyhow!(AuthRejected));
                    }
                }

                (send, recv)
            }
            PeerAuth::MyPassphrase {
                passphrase,
                jwks,
                allowed_users,
                username_claim,
                audience,
            } => {
                let (mut send, mut recv) = conn.accept_bi().await?;

                // Read and verify passphrase (existing protocol).
                let mut received_passphrase = [0; 32];
                recv.read_exact(&mut received_passphrase).await?;

                // Guard against timing attacks.
                if !constant_time_eq::constant_time_eq(
                    &received_passphrase,
                    &passphrase.to_bytes(),
                ) {
                    // Send reject byte when JWT mode is active so the joiner doesn't
                    // hang waiting for a response that will never come.
                    if jwks.is_some() {
                        let _ = send.write_all(&[0u8]).await;
                    }
                    bail!("Peer provided incorrect passphrase.");
                }

                // JWT validation (only when allow-list is configured).
                if let (Some(jwks), Some(allowed_users)) = (&jwks, &allowed_users) {
                    // Read JWT length (4 bytes big-endian).
                    let mut jwt_len_buf = [0u8; 4];
                    recv.read_exact(&mut jwt_len_buf).await?;
                    let jwt_len = u32::from_be_bytes(jwt_len_buf) as usize;

                    // Sanity-check the length to avoid large allocations from a
                    // malicious/misconfigured peer.
                    const MAX_JWT_BYTES: usize = 16_384;
                    if jwt_len > MAX_JWT_BYTES {
                        let _ = send.write_all(&[0u8]).await;
                        bail!("JWT token too large ({jwt_len} bytes, max {MAX_JWT_BYTES})");
                    }

                    let mut jwt_bytes = vec![0u8; jwt_len];
                    recv.read_exact(&mut jwt_bytes).await?;
                    let jwt_str =
                        String::from_utf8(jwt_bytes).context("JWT token is not valid UTF-8")?;

                    // Validate signature + expiry + optional audience, then extract the configured claim.
                    let username = match jwks.validate_token(&jwt_str, &username_claim, audience.as_deref()).await {
                        Ok(u) => u,
                        Err(err) => {
                            let _ = send.write_all(&[0u8]).await;
                            bail!("JWT validation failed: {err}");
                        }
                    };

                    if !allowed_users.contains(&username) {
                        let _ = send.write_all(&[0u8]).await;
                        bail!("User '{username}' is not in the allow list (claim: {username_claim})");
                    }

                    info!("Authenticated peer: {username_claim}={username}");
                    send.write_all(&[1u8]).await?;
                }

                (send, recv)
            }
        };

        let (message_tx, message_rx) = mpsc::channel(1);

        tokio::spawn(async move {
            let _ = Self::read_loop(receive, message_tx).await;
        });

        Ok(Self { send, message_rx })
    }

    async fn read_loop(
        mut receive: RecvStream,
        message_tx: mpsc::Sender<Result<PeerMessage>>,
    ) -> Result<()> {
        loop {
            let result = Self::read_next(&mut receive).await;

            message_tx.send(result).await?;
        }
    }

    async fn read_next(receive: &mut RecvStream) -> Result<PeerMessage> {
        let mut message_len_buf = [0; 4];
        receive.read_exact(&mut message_len_buf).await?;
        let byte_count = u32::from_be_bytes(message_len_buf);

        let mut bytes = vec![0; byte_count as usize];
        receive.read_exact(&mut bytes).await?;
        from_bytes(&bytes).context("Failed to convert bytes to PeerMessage")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Create a temp dir with the `.teamtype/` subdirectory that `get_keypair` expects.
    fn make_temp_base_dir() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".teamtype")).unwrap();
        dir
    }

    // ── URL validation ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn build_endpoint_invalid_relay_url_returns_error() {
        let dir = make_temp_base_dir();
        let result =
            ConnectionManager::build_endpoint(dir.path(), Some("not-a-url".to_string()), None)
                .await;
        assert!(result.is_err(), "expected Err for invalid relay URL");
    }

    #[tokio::test]
    async fn build_endpoint_invalid_discovery_url_returns_error() {
        let dir = make_temp_base_dir();
        let result =
            ConnectionManager::build_endpoint(dir.path(), None, Some("not-a-url".to_string()))
                .await;
        assert!(result.is_err(), "expected Err for invalid discovery URL");
    }

    // ── successful builds ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn build_endpoint_default_succeeds_and_has_discovery() {
        let dir = make_temp_base_dir();
        let (endpoint, _passphrase) = ConnectionManager::build_endpoint(dir.path(), None, None)
            .await
            .expect("default build_endpoint should succeed");

        // n0's discovery_n0() always installs a discovery service.
        assert!(
            endpoint.discovery().is_some(),
            "default endpoint should have discovery configured"
        );
        endpoint.close().await;
    }

    #[tokio::test]
    async fn build_endpoint_custom_relay_succeeds_and_retains_discovery() {
        let dir = make_temp_base_dir();
        // Use an unreachable URL: bind() succeeds since relay connection is lazy.
        let (endpoint, _passphrase) = ConnectionManager::build_endpoint(
            dir.path(),
            Some("https://relay.example.com".to_string()),
            None,
        )
        .await
        .expect("custom-relay build_endpoint should succeed");

        // When only relay is custom, we manually re-add the three n0 discovery services.
        assert!(
            endpoint.discovery().is_some(),
            "custom-relay endpoint should still have discovery configured"
        );
        endpoint.close().await;
    }

    #[tokio::test]
    async fn build_endpoint_custom_discovery_succeeds_and_has_discovery() {
        let dir = make_temp_base_dir();
        let (endpoint, _passphrase) = ConnectionManager::build_endpoint(
            dir.path(),
            None,
            Some("https://discovery.example.com/pkarr".to_string()),
        )
        .await
        .expect("custom-discovery build_endpoint should succeed");

        assert!(
            endpoint.discovery().is_some(),
            "custom-discovery endpoint should have discovery configured"
        );
        endpoint.close().await;
    }

    #[tokio::test]
    async fn build_endpoint_both_custom_succeeds_and_has_discovery() {
        let dir = make_temp_base_dir();
        let (endpoint, _passphrase) = ConnectionManager::build_endpoint(
            dir.path(),
            Some("https://relay.example.com".to_string()),
            Some("https://discovery.example.com/pkarr".to_string()),
        )
        .await
        .expect("fully-custom build_endpoint should succeed");

        assert!(
            endpoint.discovery().is_some(),
            "fully-custom endpoint should have discovery configured"
        );
        endpoint.close().await;
    }

    // ── JWT handshake tests ────────────────────────────────────────────────────
    //
    // These tests spin up two real iroh QUIC endpoints in-process and exercise
    // the full auth handshake (passphrase + optional JWT) via `IrohConnection`.
    //
    // Because we need two endpoints to talk to each other directly (no relay),
    // we build them both with `discovery_n0()` but then connect via the node
    // address returned by `endpoint.node_addr()`, which includes direct socket
    // addresses and avoids any network dependency.

    use crate::auth::{DEFAULT_USERNAME_CLAIM, JwksCache};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rsa::pkcs1::EncodeRsaPrivateKey as _;
    use rsa::traits::PublicKeyParts as _;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    // ── shared JWT test helpers ────────────────────────────────────────────────

    fn generate_test_rsa_keypair() -> (RsaPrivateKey, RsaPublicKey) {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public = RsaPublicKey::from(&private);
        (private, public)
    }

    fn build_test_jwks_json(public: &RsaPublicKey, kid: Option<&str>) -> serde_json::Value {
        let n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
        let mut key = serde_json::json!({ "kty": "RSA", "n": n, "e": e });
        if let Some(kid) = kid {
            key["kid"] = serde_json::json!(kid);
        }
        serde_json::json!({ "keys": [key] })
    }

    async fn build_test_jwks_cache(public: &RsaPublicKey) -> Arc<JwksCache> {
        use crate::auth::tests_helpers::jwks_cache_from_value;
        let jwks_json = build_test_jwks_json(public, None);
        Arc::new(jwks_cache_from_value(jwks_json).await)
    }

    /// Sign a JWT placing `username_value` in the claim named `claim_name`.
    /// Uses `DEFAULT_USERNAME_CLAIM` ("sub") when `claim_name` is not supplied.
    fn sign_test_jwt(
        private: &RsaPrivateKey,
        username_value: &str,
        exp_offset_secs: i64,
    ) -> String {
        sign_test_jwt_with_claim(private, DEFAULT_USERNAME_CLAIM, username_value, exp_offset_secs)
    }

    fn sign_test_jwt_with_claim(
        private: &RsaPrivateKey,
        claim_name: &str,
        username_value: &str,
        exp_offset_secs: i64,
    ) -> String {
        use std::collections::HashMap;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut claims: HashMap<&str, serde_json::Value> = HashMap::new();
        claims.insert(claim_name, serde_json::json!(username_value));
        claims.insert("exp", serde_json::json!(now + exp_offset_secs));
        let der = private.to_pkcs1_der().unwrap();
        let key = EncodingKey::from_rsa_der(der.as_bytes());
        encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap()
    }

    /// Build two connected iroh endpoints. Returns (accepting_conn, connecting_conn).
    async fn make_connected_pair() -> (iroh::endpoint::Connection, iroh::endpoint::Connection) {
        // Acceptor endpoint
        let acceptor = iroh::Endpoint::builder()
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();

        // Connector endpoint
        let connector = iroh::Endpoint::builder()
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();

        let acceptor_addr = acceptor.node_addr().await.unwrap();

        // Accept and connect concurrently.
        let (accepting_conn, connecting_conn) = tokio::join!(
            async {
                acceptor
                    .accept()
                    .await
                    .unwrap()
                    .await
                    .unwrap()
            },
            async {
                connector
                    .connect(acceptor_addr, ALPN)
                    .await
                    .unwrap()
            }
        );

        (accepting_conn, connecting_conn)
    }

    // ── passphrase-only (legacy mode) ──────────────────────────────────────────

    #[tokio::test]
    async fn handshake_correct_passphrase_no_jwt_succeeds() {
        let passphrase = SecretKey::generate(rand::rngs::OsRng);
        let (accepting_conn, connecting_conn) = make_connected_pair().await;

        let host_auth = PeerAuth::MyPassphrase {
            passphrase: passphrase.clone(),
            jwks: None,
            allowed_users: None,
            username_claim: DEFAULT_USERNAME_CLAIM.to_owned(),
            audience: None,
        };
        let joiner_auth = PeerAuth::YourPassphrase {
            passphrase: passphrase.clone(),
            auth_token: None,
        };

        let (host_result, joiner_result) = tokio::join!(
            IrohConnection::new(accepting_conn, host_auth),
            IrohConnection::new(connecting_conn, joiner_auth),
        );

        assert!(host_result.is_ok(), "host should accept correct passphrase");
        assert!(joiner_result.is_ok(), "joiner should connect with correct passphrase");
    }

    #[tokio::test]
    async fn handshake_wrong_passphrase_no_jwt_rejected() {
        let passphrase = SecretKey::generate(rand::rngs::OsRng);
        let wrong_passphrase = SecretKey::generate(rand::rngs::OsRng);
        let (accepting_conn, connecting_conn) = make_connected_pair().await;

        let host_auth = PeerAuth::MyPassphrase {
            passphrase: passphrase.clone(),
            jwks: None,
            allowed_users: None,
            username_claim: DEFAULT_USERNAME_CLAIM.to_owned(),
            audience: None,
        };
        let joiner_auth = PeerAuth::YourPassphrase {
            passphrase: wrong_passphrase,
            auth_token: None,
        };

        let (host_result, _joiner_result) = tokio::join!(
            IrohConnection::new(accepting_conn, host_auth),
            IrohConnection::new(connecting_conn, joiner_auth),
        );

        assert!(host_result.is_err(), "host should reject wrong passphrase");
    }

    // ── JWT mode — default claim (sub) ─────────────────────────────────────────

    #[tokio::test]
    async fn handshake_jwt_valid_user_in_allow_list_succeeds() {
        let passphrase = SecretKey::generate(rand::rngs::OsRng);
        let (private, public) = generate_test_rsa_keypair();
        let token = sign_test_jwt(&private, "alice", 3600);
        let jwks = build_test_jwks_cache(&public).await;
        let allowed = Arc::new(vec!["alice".to_string()]);

        let (accepting_conn, connecting_conn) = make_connected_pair().await;

        let host_auth = PeerAuth::MyPassphrase {
            passphrase: passphrase.clone(),
            jwks: Some(jwks),
            allowed_users: Some(allowed),
            username_claim: DEFAULT_USERNAME_CLAIM.to_owned(),
            audience: None,
        };
        let joiner_auth = PeerAuth::YourPassphrase {
            passphrase: passphrase.clone(),
            auth_token: Some(token),
        };

        let (host_result, joiner_result) = tokio::join!(
            IrohConnection::new(accepting_conn, host_auth),
            IrohConnection::new(connecting_conn, joiner_auth),
        );

        assert!(host_result.is_ok(), "host should accept valid JWT for allowed user");
        assert!(joiner_result.is_ok(), "joiner should receive accept");
    }

    #[tokio::test]
    async fn handshake_jwt_user_not_in_allow_list_rejected() {
        let passphrase = SecretKey::generate(rand::rngs::OsRng);
        let (private, public) = generate_test_rsa_keypair();
        let token = sign_test_jwt(&private, "eve", 3600); // not in allow list
        let jwks = build_test_jwks_cache(&public).await;
        let allowed = Arc::new(vec!["alice".to_string()]);

        let (accepting_conn, connecting_conn) = make_connected_pair().await;

        let host_auth = PeerAuth::MyPassphrase {
            passphrase: passphrase.clone(),
            jwks: Some(jwks),
            allowed_users: Some(allowed),
            username_claim: DEFAULT_USERNAME_CLAIM.to_owned(),
            audience: None,
        };
        let joiner_auth = PeerAuth::YourPassphrase {
            passphrase: passphrase.clone(),
            auth_token: Some(token),
        };

        let (host_result, joiner_result) = tokio::join!(
            IrohConnection::new(accepting_conn, host_auth),
            IrohConnection::new(connecting_conn, joiner_auth),
        );

        assert!(host_result.is_err(), "host should reject user not in allow list");
        assert!(joiner_result.is_err(), "joiner should receive reject response");
    }

    #[tokio::test]
    async fn handshake_jwt_expired_token_rejected() {
        let passphrase = SecretKey::generate(rand::rngs::OsRng);
        let (private, public) = generate_test_rsa_keypair();
        let token = sign_test_jwt(&private, "alice", -3600); // expired
        let jwks = build_test_jwks_cache(&public).await;
        let allowed = Arc::new(vec!["alice".to_string()]);

        let (accepting_conn, connecting_conn) = make_connected_pair().await;

        let host_auth = PeerAuth::MyPassphrase {
            passphrase: passphrase.clone(),
            jwks: Some(jwks),
            allowed_users: Some(allowed),
            username_claim: DEFAULT_USERNAME_CLAIM.to_owned(),
            audience: None,
        };
        let joiner_auth = PeerAuth::YourPassphrase {
            passphrase: passphrase.clone(),
            auth_token: Some(token),
        };

        let (host_result, joiner_result) = tokio::join!(
            IrohConnection::new(accepting_conn, host_auth),
            IrohConnection::new(connecting_conn, joiner_auth),
        );

        assert!(host_result.is_err(), "host should reject expired token");
        assert!(joiner_result.is_err(), "joiner should receive reject response");
    }

    #[tokio::test]
    async fn handshake_jwt_wrong_passphrase_with_valid_jwt_rejected() {
        // Even with a valid JWT, a wrong passphrase must still be rejected.
        let passphrase = SecretKey::generate(rand::rngs::OsRng);
        let wrong_passphrase = SecretKey::generate(rand::rngs::OsRng);
        let (private, public) = generate_test_rsa_keypair();
        let token = sign_test_jwt(&private, "alice", 3600);
        let jwks = build_test_jwks_cache(&public).await;
        let allowed = Arc::new(vec!["alice".to_string()]);

        let (accepting_conn, connecting_conn) = make_connected_pair().await;

        let host_auth = PeerAuth::MyPassphrase {
            passphrase: passphrase.clone(),
            jwks: Some(jwks),
            allowed_users: Some(allowed),
            username_claim: DEFAULT_USERNAME_CLAIM.to_owned(),
            audience: None,
        };
        let joiner_auth = PeerAuth::YourPassphrase {
            passphrase: wrong_passphrase,
            auth_token: Some(token),
        };

        let (host_result, _) = tokio::join!(
            IrohConnection::new(accepting_conn, host_auth),
            IrohConnection::new(connecting_conn, joiner_auth),
        );

        assert!(host_result.is_err(), "host should reject wrong passphrase even with valid JWT");
    }

    // ── JWT mode — custom claim ────────────────────────────────────────────────

    #[tokio::test]
    async fn handshake_jwt_custom_claim_valid_user_succeeds() {
        let passphrase = SecretKey::generate(rand::rngs::OsRng);
        let (private, public) = generate_test_rsa_keypair();
        // Token carries the username in "preferred_username", not "sub".
        let token = sign_test_jwt_with_claim(&private, "preferred_username", "alice", 3600);
        let jwks = build_test_jwks_cache(&public).await;
        let allowed = Arc::new(vec!["alice".to_string()]);

        let (accepting_conn, connecting_conn) = make_connected_pair().await;

        let host_auth = PeerAuth::MyPassphrase {
            passphrase: passphrase.clone(),
            jwks: Some(jwks),
            allowed_users: Some(allowed),
            username_claim: "preferred_username".to_owned(),
            audience: None,
        };
        let joiner_auth = PeerAuth::YourPassphrase {
            passphrase: passphrase.clone(),
            auth_token: Some(token),
        };

        let (host_result, joiner_result) = tokio::join!(
            IrohConnection::new(accepting_conn, host_auth),
            IrohConnection::new(connecting_conn, joiner_auth),
        );

        assert!(host_result.is_ok(), "host should accept JWT with matching preferred_username");
        assert!(joiner_result.is_ok(), "joiner should receive accept");
    }

    #[tokio::test]
    async fn handshake_jwt_wrong_claim_name_rejected() {
        // Host expects "preferred_username", but token only has "sub".
        let passphrase = SecretKey::generate(rand::rngs::OsRng);
        let (private, public) = generate_test_rsa_keypair();
        let token = sign_test_jwt(&private, "alice", 3600); // puts value in "sub"
        let jwks = build_test_jwks_cache(&public).await;
        let allowed = Arc::new(vec!["alice".to_string()]);

        let (accepting_conn, connecting_conn) = make_connected_pair().await;

        let host_auth = PeerAuth::MyPassphrase {
            passphrase: passphrase.clone(),
            jwks: Some(jwks),
            allowed_users: Some(allowed),
            username_claim: "preferred_username".to_owned(), // mismatch
            audience: None,
        };
        let joiner_auth = PeerAuth::YourPassphrase {
            passphrase: passphrase.clone(),
            auth_token: Some(token),
        };

        let (host_result, joiner_result) = tokio::join!(
            IrohConnection::new(accepting_conn, host_auth),
            IrohConnection::new(connecting_conn, joiner_auth),
        );

        assert!(host_result.is_err(), "host should reject when claim name doesn't match");
        assert!(joiner_result.is_err(), "joiner should receive reject response");
    }

    // ── JWT mode — audience validation ────────────────────────────────────────

    /// Build a JWT that includes an `aud` claim (single string or array).
    fn sign_test_jwt_with_audience(
        private: &RsaPrivateKey,
        sub_value: &str,
        aud: serde_json::Value,
        exp_offset_secs: i64,
    ) -> String {
        use std::collections::HashMap;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut claims: HashMap<&str, serde_json::Value> = HashMap::new();
        claims.insert(DEFAULT_USERNAME_CLAIM, serde_json::json!(sub_value));
        claims.insert("aud", aud);
        claims.insert("exp", serde_json::json!(now + exp_offset_secs));
        let der = private.to_pkcs1_der().unwrap();
        let key = EncodingKey::from_rsa_der(der.as_bytes());
        encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap()
    }

    #[tokio::test]
    async fn handshake_jwt_audience_matches_accepted() {
        let passphrase = SecretKey::generate(rand::rngs::OsRng);
        let (private, public) = generate_test_rsa_keypair();
        let token = sign_test_jwt_with_audience(
            &private, "alice", serde_json::json!("my-app"), 3600,
        );
        let jwks = build_test_jwks_cache(&public).await;
        let allowed = Arc::new(vec!["alice".to_string()]);

        let (accepting_conn, connecting_conn) = make_connected_pair().await;

        let host_auth = PeerAuth::MyPassphrase {
            passphrase: passphrase.clone(),
            jwks: Some(jwks),
            allowed_users: Some(allowed),
            username_claim: DEFAULT_USERNAME_CLAIM.to_owned(),
            audience: Some("my-app".to_owned()),
        };
        let joiner_auth = PeerAuth::YourPassphrase {
            passphrase: passphrase.clone(),
            auth_token: Some(token),
        };

        let (host_result, joiner_result) = tokio::join!(
            IrohConnection::new(accepting_conn, host_auth),
            IrohConnection::new(connecting_conn, joiner_auth),
        );

        assert!(host_result.is_ok(), "host should accept token with matching audience");
        assert!(joiner_result.is_ok(), "joiner should receive accept");
    }

    #[tokio::test]
    async fn handshake_jwt_audience_mismatch_rejected() {
        let passphrase = SecretKey::generate(rand::rngs::OsRng);
        let (private, public) = generate_test_rsa_keypair();
        let token = sign_test_jwt_with_audience(
            &private, "alice", serde_json::json!("other-app"), 3600,
        );
        let jwks = build_test_jwks_cache(&public).await;
        let allowed = Arc::new(vec!["alice".to_string()]);

        let (accepting_conn, connecting_conn) = make_connected_pair().await;

        let host_auth = PeerAuth::MyPassphrase {
            passphrase: passphrase.clone(),
            jwks: Some(jwks),
            allowed_users: Some(allowed),
            username_claim: DEFAULT_USERNAME_CLAIM.to_owned(),
            audience: Some("my-app".to_owned()),
        };
        let joiner_auth = PeerAuth::YourPassphrase {
            passphrase: passphrase.clone(),
            auth_token: Some(token),
        };

        let (host_result, joiner_result) = tokio::join!(
            IrohConnection::new(accepting_conn, host_auth),
            IrohConnection::new(connecting_conn, joiner_auth),
        );

        assert!(host_result.is_err(), "host should reject token with wrong audience");
        assert!(joiner_result.is_err(), "joiner should receive reject response");
    }

    #[tokio::test]
    async fn handshake_jwt_audience_array_contains_required_accepted() {
        let passphrase = SecretKey::generate(rand::rngs::OsRng);
        let (private, public) = generate_test_rsa_keypair();
        let token = sign_test_jwt_with_audience(
            &private,
            "alice",
            serde_json::json!(["other-app", "my-app"]),
            3600,
        );
        let jwks = build_test_jwks_cache(&public).await;
        let allowed = Arc::new(vec!["alice".to_string()]);

        let (accepting_conn, connecting_conn) = make_connected_pair().await;

        let host_auth = PeerAuth::MyPassphrase {
            passphrase: passphrase.clone(),
            jwks: Some(jwks),
            allowed_users: Some(allowed),
            username_claim: DEFAULT_USERNAME_CLAIM.to_owned(),
            audience: Some("my-app".to_owned()),
        };
        let joiner_auth = PeerAuth::YourPassphrase {
            passphrase: passphrase.clone(),
            auth_token: Some(token),
        };

        let (host_result, joiner_result) = tokio::join!(
            IrohConnection::new(accepting_conn, host_auth),
            IrohConnection::new(connecting_conn, joiner_auth),
        );

        assert!(host_result.is_ok(), "host should accept token whose aud array contains required value");
        assert!(joiner_result.is_ok(), "joiner should receive accept");
    }
}

#[async_trait]
impl Connection<PeerMessage> for IrohConnection {
    async fn send(&mut self, message: PeerMessage) -> Result<()> {
        let bytes: Vec<u8> =
            to_allocvec(&message).context("Failed to convert PeerMessage to bytes")?;
        let byte_count =
            u32::try_from(bytes.len()).expect("Converting a length to u32 should work");

        self.send.write_all(&byte_count.to_be_bytes()).await?;
        self.send.write_all(&bytes).await?;

        Ok(())
    }

    async fn next(&mut self) -> Result<PeerMessage> {
        self.message_rx
            .recv()
            .await
            .context("Failed to await next peer message")?
    }
}
