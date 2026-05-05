// SPDX-FileCopyrightText: 2026 TNG Technology Consulting GmbH <christoph.niehoff@tngtech.com>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! JWT-based authentication for allow-list access control.
//!
//! Provides [`JwksCache`], which fetches a JWKS (JSON Web Key Set) from an OIDC
//! provider (e.g. Keycloak) and validates JWT tokens against those keys.
//!
//! Supported algorithms: RS256, RS384, RS512, PS256, PS384, PS512, ES256,
//! ES384, and EdDSA. The permitted algorithm set is derived exclusively from
//! the JWKS: if a JWK carries an `alg` field only that algorithm is allowed
//! for that key; if `alg` is absent all algorithms compatible with the key
//! type are permitted (per RFC 7517 §4.4). Any JWT whose `alg` header is not
//! represented in the JWKS is rejected before signature verification.

use anyhow::{Context, Result, anyhow, bail};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use tracing::debug;

/// The JWT claim name used when none is explicitly configured.
pub const DEFAULT_USERNAME_CLAIM: &str = "sub";

// ── Public API ─────────────────────────────────────────────────────────────────

/// Cached JWKS key set fetched from an OIDC provider.
///
/// Fetches once on startup (via [`JwksCache::refresh`]) and caches the keys
/// for all subsequent [`JwksCache::validate_token`] calls.
pub struct JwksCache {
    keys: RwLock<Option<JwkSet>>,
    url: String,
}

impl JwksCache {
    /// Create a new cache for the given JWKS URL (e.g.
    /// `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs`).
    #[must_use]
    pub fn new(url: String) -> Self {
        Self {
            keys: RwLock::new(None),
            url,
        }
    }

    /// Fetch (or re-fetch) the JWKS from the configured URL and update the cache.
    pub async fn refresh(&self) -> Result<()> {
        debug!("Fetching JWKS from {}", self.url);
        let jwks: JwkSet = reqwest::get(&self.url)
            .await
            .context("Failed to fetch JWKS")?
            .json()
            .await
            .context("Failed to parse JWKS response as JSON")?;
        *self.keys.write().await = Some(jwks);
        debug!("JWKS fetched successfully");
        Ok(())
    }

    /// Validate a JWT and return the value of `claim_name` on success.
    ///
    /// The signing algorithm is determined from the matching JWK's `alg` field.
    /// When that field is absent, the algorithm is inferred from the key type
    /// (RSA → RS256, EC P-256 → ES256, EC P-384 → ES384, OKP → EdDSA) and
    /// cross-checked against the JWT header's `alg` to prevent algorithm
    /// confusion attacks.
    ///
    /// - **`claim_name`**: The JWT claim whose value is returned (e.g. `"sub"`,
    ///   `"preferred_username"`). Returns an error if absent or not a string.
    /// - **`required_audience`**: When `Some`, the token's `aud` claim must
    ///   contain this value. The `aud` claim may be a single string or a list
    ///   of strings (RFC 7519 §4.1.3). Returns an error if the audience is
    ///   absent or does not contain the required value.
    ///
    /// If the JWKS cache is empty, this will call [`Self::refresh`] first.
    /// The token's `exp` claim is validated automatically.
    pub async fn validate_token(
        &self,
        token: &str,
        claim_name: &str,
        required_audience: Option<&str>,
    ) -> Result<String> {
        // Ensure the cache is populated.
        if self.keys.read().await.is_none() {
            self.refresh().await?;
        }

        let header = decode_header(token).context("Failed to decode JWT header")?;
        let kid = header.kid.as_deref();

        let keys = self.keys.read().await;
        let jwks = keys
            .as_ref()
            .expect("JWKS must be populated after refresh");

        // Reject any JWT whose algorithm is not advertised by any key in the
        // JWKS. The allowed set is derived exclusively from the JWKS — the JWT
        // header's `alg` field is never trusted to extend it.
        let allowed = allowed_algorithms_from_jwks(jwks);
        if !allowed.contains(&header.alg) {
            bail!(
                "JWT algorithm {:?} is not permitted by any key in the JWKS",
                header.alg
            );
        }

        // Find the matching JWK by `kid`, or fall back to the first key when
        // the JWT header carries no `kid`. Keys that are not supported by the
        // jsonwebtoken crate are skipped.
        let jwk = match kid {
            Some(kid) => jwks
                .keys
                .iter()
                .find(|k| k.common.key_id.as_deref() == Some(kid) && k.is_supported())
                .ok_or_else(|| anyhow!("No supported JWKS key found matching kid={kid}"))?,
            None => jwks
                .keys
                .iter()
                .find(|k| k.is_supported())
                .ok_or_else(|| anyhow!("JWKS contains no supported keys"))?,
        };

        // Determine which algorithm to use for this key.
        //
        // Strategy (in order):
        // 1. Use the JWK's own `alg` field if present.
        // 2. Infer a default algorithm from the key type.
        // 3. Cross-check against the JWT header's `alg` to prevent an attacker
        //    from substituting a different algorithm with the same key material.
        let algorithm = algorithm_for_jwk(jwk, header.alg)?;

        let decoding_key =
            DecodingKey::from_jwk(jwk).context("Failed to build decoding key from JWK")?;

        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true;

        // Audience validation is handled manually after decoding (see below)
        // because jsonwebtoken's built-in audience check does not reject tokens
        // that are entirely missing the `aud` claim. We disable the built-in
        // check and perform our own that correctly handles missing, single-string,
        // and array-of-strings forms per RFC 7519 §4.1.3.
        validation.validate_aud = false;

        // Decode into a generic map so we can look up any claim by name at
        // runtime without needing a statically-typed struct.
        let token_data =
            decode::<HashMap<String, Value>>(token, &decoding_key, &validation)
                .context("JWT validation failed")?;

        // jsonwebtoken's set_audience() only rejects aud mismatches; it does
        // not reject tokens that are missing the aud claim entirely. When an
        // audience is required, we enforce its presence manually.
        if let Some(required_aud) = required_audience {
            let aud_value = token_data
                .claims
                .get("aud")
                .ok_or_else(|| anyhow!("JWT is missing the required 'aud' claim"))?;

            let aud_matches = match aud_value {
                Value::String(s) => s == required_aud,
                Value::Array(arr) => arr
                    .iter()
                    .any(|v| v.as_str() == Some(required_aud)),
                _ => false,
            };

            if !aud_matches {
                bail!(
                    "JWT 'aud' claim does not contain the required audience '{required_aud}'"
                );
            }
        }

        let value = token_data
            .claims
            .get(claim_name)
            .ok_or_else(|| anyhow!("JWT does not contain the '{claim_name}' claim"))?;

        let username = value
            .as_str()
            .ok_or_else(|| anyhow!("JWT claim '{claim_name}' is not a string"))?
            .to_owned();

        Ok(username)
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Build the set of algorithms permitted by the JWKS.
///
/// For each key in the set:
/// - If the key has an `alg` field, only that algorithm is included.
/// - If the key has no `alg` field, all algorithms compatible with its key
///   type are included (per RFC 7517 §4.4 which makes `alg` optional).
///
/// Keys that are unsupported by the `jsonwebtoken` crate, or whose algorithm
/// maps to an encryption-only or HMAC operation, are silently skipped.
fn allowed_algorithms_from_jwks(jwks: &JwkSet) -> HashSet<Algorithm> {
    let mut allowed = HashSet::new();
    for jwk in &jwks.keys {
        if let Some(key_alg) = jwk.common.key_algorithm {
            // Key advertises a specific algorithm; only that one is permitted.
            if let Ok(alg) = key_algorithm_to_algorithm(key_alg) {
                allowed.insert(alg);
            }
        } else {
            // No `alg` field: accept all algorithms compatible with the key type.
            match &jwk.algorithm {
                AlgorithmParameters::RSA(_) => {
                    allowed.extend([
                        Algorithm::RS256,
                        Algorithm::RS384,
                        Algorithm::RS512,
                        Algorithm::PS256,
                        Algorithm::PS384,
                        Algorithm::PS512,
                    ]);
                }
                AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
                    EllipticCurve::P256 => {
                        allowed.insert(Algorithm::ES256);
                    }
                    EllipticCurve::P384 => {
                        allowed.insert(Algorithm::ES384);
                    }
                    EllipticCurve::Ed25519 | EllipticCurve::P521 => {
                        // P-521 is not supported; Ed25519 as EC is non-standard.
                        // Skip both.
                    }
                },
                AlgorithmParameters::OctetKeyPair(_) => {
                    allowed.insert(Algorithm::EdDSA);
                }
                AlgorithmParameters::OctetKey(_) => {
                    // Symmetric keys have no place in a public JWKS endpoint.
                }
            }
        }
    }
    allowed
}

/// Determine the [`Algorithm`] to use for a given JWK and the algorithm that
/// was declared in the JWT header.
///
/// The JWK's own `alg` field is authoritative when present. Otherwise the
/// algorithm is inferred from the key type and validated against the header's
/// `alg` to prevent algorithm confusion attacks.
fn algorithm_for_jwk(
    jwk: &jsonwebtoken::jwk::Jwk,
    header_alg: Algorithm,
) -> Result<Algorithm> {
    // If the JWK advertises a specific algorithm, use it and verify the JWT
    // header is consistent.
    if let Some(key_alg) = jwk.common.key_algorithm {
        let alg = key_algorithm_to_algorithm(key_alg)?;
        if alg != header_alg {
            bail!(
                "JWT header algorithm {header_alg:?} does not match the key's algorithm {alg:?}"
            );
        }
        return Ok(alg);
    }

    // No `alg` field in the JWK: infer a default from the key type and
    // accept the header algorithm only if it is compatible with that type.
    let inferred = infer_algorithm_from_key_type(jwk, header_alg)?;
    Ok(inferred)
}

/// Convert a [`KeyAlgorithm`] (the `alg` field in a JWK) to its corresponding
/// [`Algorithm`] for JWT signature verification. Encryption-only algorithms
/// (RSA1_5, RSA-OAEP, RSA-OAEP-256) are explicitly rejected.
fn key_algorithm_to_algorithm(key_alg: KeyAlgorithm) -> Result<Algorithm> {
    match key_alg {
        KeyAlgorithm::RS256 => Ok(Algorithm::RS256),
        KeyAlgorithm::RS384 => Ok(Algorithm::RS384),
        KeyAlgorithm::RS512 => Ok(Algorithm::RS512),
        KeyAlgorithm::PS256 => Ok(Algorithm::PS256),
        KeyAlgorithm::PS384 => Ok(Algorithm::PS384),
        KeyAlgorithm::PS512 => Ok(Algorithm::PS512),
        KeyAlgorithm::ES256 => Ok(Algorithm::ES256),
        KeyAlgorithm::ES384 => Ok(Algorithm::ES384),
        KeyAlgorithm::EdDSA => Ok(Algorithm::EdDSA),
        // HMAC keys are delivered as symmetric secrets, not as public keys in
        // a JWKS endpoint. Reject them here.
        KeyAlgorithm::HS256 | KeyAlgorithm::HS384 | KeyAlgorithm::HS512 => {
            bail!("HMAC algorithms (HS256/HS384/HS512) are not supported via JWKS")
        }
        // Encryption-only algorithms cannot be used for JWT signature
        // verification.
        KeyAlgorithm::RSA1_5 | KeyAlgorithm::RSA_OAEP | KeyAlgorithm::RSA_OAEP_256 => {
            bail!("Key algorithm {key_alg} is for encryption only and cannot verify JWT signatures")
        }
    }
}

/// When a JWK has no `alg` field, infer the algorithm from the key type and
/// validate the header's `alg` for compatibility.
///
/// The validation rules are:
/// - RSA key → header must be one of RS256/RS384/RS512/PS256/PS384/PS512.
/// - EC P-256 key → header must be ES256.
/// - EC P-384 key → header must be ES384.
/// - OKP key → header must be EdDSA.
fn infer_algorithm_from_key_type(
    jwk: &jsonwebtoken::jwk::Jwk,
    header_alg: Algorithm,
) -> Result<Algorithm> {
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => {
            // Any RSA signature algorithm is compatible with an RSA key.
            match header_alg {
                Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512 => Ok(header_alg),
                _ => bail!(
                    "JWT header algorithm {header_alg:?} is not compatible with an RSA key"
                ),
            }
        }
        AlgorithmParameters::EllipticCurve(ec) => {
            let expected = match ec.curve {
                EllipticCurve::P256 => Algorithm::ES256,
                EllipticCurve::P384 => Algorithm::ES384,
                EllipticCurve::P521 => {
                    bail!("EC P-521 keys are not supported by the jsonwebtoken crate")
                }
                EllipticCurve::Ed25519 => {
                    // Ed25519 is represented as OctetKeyPair in RFC 8037, not
                    // EllipticCurve. The jsonwebtoken crate may parse it as EC
                    // with Ed25519 curve; redirect to EdDSA in that case.
                    if header_alg != Algorithm::EdDSA {
                        bail!(
                            "JWT header algorithm {header_alg:?} is not compatible with an Ed25519 key"
                        );
                    }
                    return Ok(Algorithm::EdDSA);
                }
            };
            if header_alg != expected {
                bail!(
                    "JWT header algorithm {header_alg:?} is not compatible with EC {:?} key (expected {expected:?})",
                    ec.curve
                );
            }
            Ok(expected)
        }
        AlgorithmParameters::OctetKeyPair(_) => {
            if header_alg != Algorithm::EdDSA {
                bail!(
                    "JWT header algorithm {header_alg:?} is not compatible with an OKP/EdDSA key"
                );
            }
            Ok(Algorithm::EdDSA)
        }
        AlgorithmParameters::OctetKey(_) => {
            bail!("Symmetric octet keys (HMAC) are not supported via JWKS")
        }
    }
}

/// Check that `--allowed-users` and `--jwks-url` are used together, returning
/// a clear error if one is set without the other.
pub fn validate_auth_config(
    allowed_users: &Option<Vec<String>>,
    jwks_url: &Option<String>,
) -> Result<()> {
    match (allowed_users, jwks_url) {
        (Some(_), None) => bail!(
            "--allowed-users requires --jwks-url to be set as well"
        ),
        (None, Some(_)) => bail!(
            "--jwks-url requires --allowed-users to be set as well"
        ),
        _ => Ok(()),
    }
}

// ── Test helpers (available to other test modules) ─────────────────────────────

/// Test-only helpers for constructing pre-loaded `JwksCache` instances without
/// making any HTTP requests.
#[cfg(test)]
pub mod tests_helpers {
    use super::*;

    /// Build a `JwksCache` pre-loaded with the given JWKS JSON value.
    /// No HTTP request is made; useful for unit tests.
    pub async fn jwks_cache_from_value(jwks_json: Value) -> JwksCache {
        let jwks: JwkSet = serde_json::from_value(jwks_json).expect("Failed to parse test JWKS");
        let cache = JwksCache::new("http://unused-in-tests".to_string());
        *cache.keys.write().await = Some(jwks);
        cache
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rsa::pkcs1::EncodeRsaPrivateKey as _;
    use rsa::traits::PublicKeyParts as _;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    // ── RSA helpers ────────────────────────────────────────────────────────────

    /// Generate a fresh 2048-bit RSA key pair.
    fn generate_rsa_keypair() -> (RsaPrivateKey, RsaPublicKey) {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
        let public = RsaPublicKey::from(&private);
        (private, public)
    }

    /// Build a minimal in-memory JWKS JSON value from an RSA public key.
    fn build_rsa_jwks_json(public: &RsaPublicKey, kid: Option<&str>) -> Value {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let n = public.n().to_bytes_be();
        let e = public.e().to_bytes_be();
        let n_b64 = URL_SAFE_NO_PAD.encode(&n);
        let e_b64 = URL_SAFE_NO_PAD.encode(&e);

        let mut key = json!({
            "kty": "RSA",
            "n": n_b64,
            "e": e_b64,
            "alg": "RS256",
            "use": "sig"
        });
        if let Some(kid) = kid {
            key["kid"] = json!(kid);
        }
        json!({ "keys": [key] })
    }

    /// Sign a JWT placing `username_value` in the claim named `claim_name`.
    fn sign_rsa_jwt(
        private: &RsaPrivateKey,
        claim_name: &str,
        username_value: &str,
        exp_offset_secs: i64,
        kid: Option<&str>,
    ) -> String {
        use std::collections::HashMap;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut claims: HashMap<&str, Value> = HashMap::new();
        claims.insert(claim_name, json!(username_value));
        claims.insert("exp", json!(now + exp_offset_secs));

        let der = private
            .to_pkcs1_der()
            .expect("Failed to encode RSA private key as DER");
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());

        let mut header = Header::new(Algorithm::RS256);
        if let Some(kid) = kid {
            header.kid = Some(kid.to_string());
        }

        encode(&header, &claims, &encoding_key).expect("Failed to sign JWT")
    }

    /// Build a `JwksCache` pre-loaded with the given JWKS JSON (no HTTP needed).
    async fn cache_with_jwks(jwks_json: Value) -> JwksCache {
        let jwks: JwkSet = serde_json::from_value(jwks_json).expect("Failed to parse test JWKS");
        let cache = JwksCache::new("http://unused".to_string());
        *cache.keys.write().await = Some(jwks);
        cache
    }

    // ── EC helpers ─────────────────────────────────────────────────────────────

    /// Build a minimal in-memory ES256 JWKS JSON value from a P-256 key pair.
    ///
    /// Returns the JWKS JSON and the `EncodingKey` for signing test JWTs.
    fn build_es256_jwks_and_key(
        kid: Option<&str>,
    ) -> (Value, EncodingKey) {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        // Use ring to generate an EC P-256 key pair via the jsonwebtoken API.
        // We generate a PKCS#8 DER key using ring's SystemRandom.
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes =
            ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )
            .expect("Failed to generate EC P-256 key");

        let encoding_key =
            EncodingKey::from_ec_der(pkcs8_bytes.as_ref());

        // Extract the public key coordinates from the PKCS#8 DER. The public
        // key is the last 65 bytes of the SubjectPublicKeyInfo structure
        // (0x04 uncompressed point prefix + 32 bytes X + 32 bytes Y).
        // For PKCS#8, the public key bit string is at a well-known offset.
        // We use ring's EcdsaKeyPair to get the public key bytes.
        use ring::signature::KeyPair as _;
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8_bytes.as_ref(),
            &rng,
        )
        .expect("Failed to parse generated EC key pair");

        // ring's public_key().as_ref() returns the uncompressed point (65 bytes).
        let pub_bytes = key_pair.public_key().as_ref();
        assert_eq!(pub_bytes[0], 0x04, "Expected uncompressed point");
        let x_b64 = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
        let y_b64 = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);

        let mut key_obj = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64,
            "alg": "ES256",
            "use": "sig"
        });
        if let Some(kid) = kid {
            key_obj["kid"] = json!(kid);
        }

        (json!({ "keys": [key_obj] }), encoding_key)
    }

    // ── RSA tests ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_token_default_claim_returns_value() {
        let (private, public) = generate_rsa_keypair();
        let token = sign_rsa_jwt(&private, "sub", "alice", 3600, None);
        let cache = cache_with_jwks(build_rsa_jwks_json(&public, None)).await;

        let value = cache.validate_token(&token, "sub", None).await.unwrap();
        assert_eq!(value, "alice");
    }

    #[tokio::test]
    async fn valid_token_custom_claim_returns_value() {
        let (private, public) = generate_rsa_keypair();
        let token = sign_rsa_jwt(&private, "preferred_username", "alice", 3600, None);
        let cache = cache_with_jwks(build_rsa_jwks_json(&public, None)).await;

        let value = cache
            .validate_token(&token, "preferred_username", None)
            .await
            .unwrap();
        assert_eq!(value, "alice");
    }

    #[tokio::test]
    async fn missing_claim_is_rejected() {
        let (private, public) = generate_rsa_keypair();
        // Token only has "sub", not "preferred_username".
        let token = sign_rsa_jwt(&private, "sub", "alice", 3600, None);
        let cache = cache_with_jwks(build_rsa_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "preferred_username", None).await;
        assert!(result.is_err(), "Expected missing claim to be rejected");
    }

    #[tokio::test]
    async fn valid_token_with_kid_returns_value() {
        let (private, public) = generate_rsa_keypair();
        let token = sign_rsa_jwt(&private, "sub", "bob", 3600, Some("key-1"));
        let cache = cache_with_jwks(build_rsa_jwks_json(&public, Some("key-1"))).await;

        let value = cache.validate_token(&token, "sub", None).await.unwrap();
        assert_eq!(value, "bob");
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let (private, public) = generate_rsa_keypair();
        // exp well in the past (one hour ago), comfortably outside any leeway
        let token = sign_rsa_jwt(&private, "sub", "alice", -3600, None);
        let cache = cache_with_jwks(build_rsa_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "sub", None).await;
        assert!(result.is_err(), "Expected expired token to be rejected");
    }

    #[tokio::test]
    async fn wrong_kid_is_rejected() {
        let (private, _public) = generate_rsa_keypair();
        let (_other_private, other_public) = generate_rsa_keypair();
        // Token signed with `private`, JWKS contains `other_public` under different kid.
        let token = sign_rsa_jwt(&private, "sub", "alice", 3600, Some("key-1"));
        let cache = cache_with_jwks(build_rsa_jwks_json(&other_public, Some("key-2"))).await;

        let result = cache.validate_token(&token, "sub", None).await;
        assert!(result.is_err(), "Expected wrong-kid token to be rejected");
    }

    #[tokio::test]
    async fn wrong_signature_is_rejected() {
        let (private, _public) = generate_rsa_keypair();
        let (_other_private, other_public) = generate_rsa_keypair();
        // Token signed with `private`, but JWKS has `other_public` -- signature mismatch.
        let token = sign_rsa_jwt(&private, "sub", "alice", 3600, None);
        let cache = cache_with_jwks(build_rsa_jwks_json(&other_public, None)).await;

        let result = cache.validate_token(&token, "sub", None).await;
        assert!(result.is_err(), "Expected signature mismatch to be rejected");
    }

    // ── EC (ES256) tests ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn es256_valid_token_returns_value() {
        let (jwks_json, encoding_key) = build_es256_jwks_and_key(None);
        let cache = cache_with_jwks(jwks_json).await;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut claims = HashMap::new();
        claims.insert("sub", json!("carol"));
        claims.insert("exp", json!(now + 3600));

        let token = encode(&Header::new(Algorithm::ES256), &claims, &encoding_key)
            .expect("Failed to sign ES256 JWT");

        let value = cache.validate_token(&token, "sub", None).await.unwrap();
        assert_eq!(value, "carol");
    }

    #[tokio::test]
    async fn es256_valid_token_with_kid_returns_value() {
        let (jwks_json, encoding_key) = build_es256_jwks_and_key(Some("ec-key-1"));
        let cache = cache_with_jwks(jwks_json).await;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut claims = HashMap::new();
        claims.insert("sub", json!("dave"));
        claims.insert("exp", json!(now + 3600));

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("ec-key-1".to_string());
        let token = encode(&header, &claims, &encoding_key)
            .expect("Failed to sign ES256 JWT");

        let value = cache.validate_token(&token, "sub", None).await.unwrap();
        assert_eq!(value, "dave");
    }

    #[tokio::test]
    async fn es256_wrong_signature_is_rejected() {
        // Sign with one key, verify with a different key.
        let (_jwks_json1, encoding_key1) = build_es256_jwks_and_key(None);
        let (jwks_json2, _encoding_key2) = build_es256_jwks_and_key(None);
        let cache = cache_with_jwks(jwks_json2).await;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut claims = HashMap::new();
        claims.insert("sub", json!("eve"));
        claims.insert("exp", json!(now + 3600));

        let token = encode(&Header::new(Algorithm::ES256), &claims, &encoding_key1)
            .expect("Failed to sign ES256 JWT");

        let result = cache.validate_token(&token, "sub", None).await;
        assert!(result.is_err(), "Expected signature mismatch to be rejected");
    }

    // ── Mixed key set tests ────────────────────────────────────────────────────

    #[tokio::test]
    async fn mixed_jwks_selects_correct_key_by_kid() {
        // JWKS with both an RSA key (kid="rsa-1") and an EC key (kid="ec-1").
        // A JWT with kid="ec-1" and ES256 should succeed.
        let (private, _public) = generate_rsa_keypair();
        let _ = private; // suppress unused warning; we only need the EC path here

        let (ec_jwks, ec_encoding_key) = build_es256_jwks_and_key(Some("ec-1"));
        let (rsa_private, rsa_public) = generate_rsa_keypair();

        // Merge both key sets into one JWKS.
        let ec_key = ec_jwks["keys"][0].clone();
        let rsa_key = build_rsa_jwks_json(&rsa_public, Some("rsa-1"))["keys"][0].clone();
        let mixed_jwks = json!({ "keys": [rsa_key, ec_key] });
        let cache = cache_with_jwks(mixed_jwks).await;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut claims = HashMap::new();
        claims.insert("sub", json!("frank"));
        claims.insert("exp", json!(now + 3600));

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("ec-1".to_string());
        let token = encode(&header, &claims, &ec_encoding_key)
            .expect("Failed to sign ES256 JWT");

        let value = cache.validate_token(&token, "sub", None).await.unwrap();
        assert_eq!(value, "frank");

        // A JWT signed with the RSA key and kid="rsa-1" should also succeed.
        let rsa_token = sign_rsa_jwt(&rsa_private, "sub", "grace", 3600, Some("rsa-1"));
        let rsa_value = cache.validate_token(&rsa_token, "sub", None).await.unwrap();
        assert_eq!(rsa_value, "grace");
    }

    // ── audience validation ────────────────────────────────────────────────────

    /// Sign a JWT that includes an `aud` claim.
    fn sign_rsa_jwt_with_audience(
        private: &RsaPrivateKey,
        sub_value: &str,
        aud: Value, // either a string or array of strings
        exp_offset_secs: i64,
    ) -> String {
        use std::collections::HashMap;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut claims: HashMap<&str, Value> = HashMap::new();
        claims.insert("sub", json!(sub_value));
        claims.insert("aud", aud);
        claims.insert("exp", json!(now + exp_offset_secs));
        let der = private.to_pkcs1_der().unwrap();
        let key = EncodingKey::from_rsa_der(der.as_bytes());
        encode(&Header::new(Algorithm::RS256), &claims, &key).expect("Failed to sign JWT")
    }

    #[tokio::test]
    async fn audience_not_configured_token_without_aud_accepted() {
        // When no audience is required, tokens without `aud` are accepted.
        let (private, public) = generate_rsa_keypair();
        let token = sign_rsa_jwt(&private, "sub", "alice", 3600, None);
        let cache = cache_with_jwks(build_rsa_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "sub", None).await;
        assert!(result.is_ok(), "Token without aud should be accepted when no audience configured");
    }

    #[tokio::test]
    async fn audience_string_matches_accepted() {
        // Token with `aud` as a single string matching the required audience.
        let (private, public) = generate_rsa_keypair();
        let token = sign_rsa_jwt_with_audience(
            &private, "alice", serde_json::json!("my-client"), 3600,
        );
        let cache = cache_with_jwks(build_rsa_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "sub", Some("my-client")).await;
        assert!(result.is_ok(), "Matching single-string audience should be accepted");
    }

    #[tokio::test]
    async fn audience_array_contains_required_accepted() {
        // Token with `aud` as an array that includes the required audience.
        let (private, public) = generate_rsa_keypair();
        let token = sign_rsa_jwt_with_audience(
            &private,
            "alice",
            serde_json::json!(["other-client", "my-client"]),
            3600,
        );
        let cache = cache_with_jwks(build_rsa_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "sub", Some("my-client")).await;
        assert!(result.is_ok(), "Array audience containing required value should be accepted");
    }

    #[tokio::test]
    async fn audience_string_does_not_match_rejected() {
        // Token with `aud` as a single string that doesn't match.
        let (private, public) = generate_rsa_keypair();
        let token = sign_rsa_jwt_with_audience(
            &private, "alice", serde_json::json!("other-client"), 3600,
        );
        let cache = cache_with_jwks(build_rsa_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "sub", Some("my-client")).await;
        assert!(result.is_err(), "Non-matching single-string audience should be rejected");
    }

    #[tokio::test]
    async fn audience_array_does_not_contain_required_rejected() {
        // Token with `aud` array that doesn't include the required audience.
        let (private, public) = generate_rsa_keypair();
        let token = sign_rsa_jwt_with_audience(
            &private,
            "alice",
            serde_json::json!(["other-client", "another-client"]),
            3600,
        );
        let cache = cache_with_jwks(build_rsa_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "sub", Some("my-client")).await;
        assert!(result.is_err(), "Array audience not containing required value should be rejected");
    }

    #[tokio::test]
    async fn audience_required_but_token_has_no_aud_rejected() {
        // When audience is required, tokens without `aud` claim are rejected.
        let (private, public) = generate_rsa_keypair();
        let token = sign_rsa_jwt(&private, "sub", "alice", 3600, None); // no aud
        let cache = cache_with_jwks(build_rsa_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "sub", Some("my-client")).await;
        assert!(result.is_err(), "Token without aud should be rejected when audience is required");
    }

    // ── JWKS deserialization ───────────────────────────────────────────────────

    #[test]
    fn jwks_with_extra_fields_and_multiple_keys_deserializes() {
        // Mirrors the real Keycloak JWKS response shape, including fields we
        // don't use (x5c, x5t, x5t#S256, alg, use, kty).
        let raw = serde_json::json!({
            "keys": [
                {
                    "kid": "key-1",
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "x5c": ["MIIC..."],
                    "x5t": "abc123",
                    "x5t#S256": "def456",
                    "n": "sIwr2R0Z3xGxFEBrBmJfVVlyGSFmIRgpLLqDqv2lClSuTuFiXXFTe5X-YXjqWpO0m_hm5y3y1xMZ8hLY6nJxKb1yXpSv_g_sHg0U_RcuGYmByKcCk4yxb0kgPqcFM1pBbONkMFDo3-BHC9n0DqxJn6ykJhpFHBSByj7HWluMfTYBbxeUdAfMhbxfRNVhDFjGSAEBiLxHR4oxXKH9VhWx0iVJiY4kf1xtRFBf5nDBjLY0V5oU8vbHQN_LRG0EG0SKnPVDxIoqECl_eLFP5lWsxJkx1k8ikRj_KO9QcE6iJlb6G_DwqJ_JiIPqOTLzriFHMjX6cBvuHFv_sMRQ",
                    "e": "AQAB"
                },
                {
                    "kid": "key-2",
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "sIwr2R0Z3xGxFEBrBmJfVVlyGSFmIRgpLLqDqv2lClSuTuFiXXFTe5X-YXjqWpO0m_hm5y3y1xMZ8hLY6nJxKb1yXpSv_g_sHg0U_RcuGYmByKcCk4yxb0kgPqcFM1pBbONkMFDo3-BHC9n0DqxJn6ykJhpFHBSByj7HWluMfTYBbxeUdAfMhbxfRNVhDFjGSAEBiLxHR4oxXKH9VhWx0iVJiY4kf1xtRFBf5nDBjLY0V5oU8vbHQN_LRG0EG0SKnPVDxIoqECl_eLFP5lWsxJkx1k8ikRj_KO9QcE6iJlb6G_DwqJ_JiIPqOTLzriFHMjX6cBvuHFv_sMRQ",
                    "e": "AQAB"
                }
            ]
        });

        let jwks: JwkSet = serde_json::from_value(raw)
            .expect("Real-world Keycloak JWKS shape should deserialize without error");

        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].common.key_id.as_deref(), Some("key-1"));
        assert_eq!(jwks.keys[1].common.key_id.as_deref(), Some("key-2"));
    }

    #[test]
    fn jwks_key_without_kid_deserializes() {
        // Some providers omit the kid field entirely.
        let raw = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "n": "sIwr2R0Z3xGxFEBrBmJfVVlyGSFmIRgpLLqDqv2lClSuTuFiXXFTe5X-YXjqWpO0m_hm5y3y1xMZ8hLY6nJxKb1yXpSv_g_sHg0U_RcuGYmByKcCk4yxb0kgPqcFM1pBbONkMFDo3-BHC9n0DqxJn6ykJhpFHBSByj7HWluMfTYBbxeUdAfMhbxfRNVhDFjGSAEBiLxHR4oxXKH9VhWx0iVJiY4kf1xtRFBf5nDBjLY0V5oU8vbHQN_LRG0EG0SKnPVDxIoqECl_eLFP5lWsxJkx1k8ikRj_KO9QcE6iJlb6G_DwqJ_JiIPqOTLzriFHMjX6cBvuHFv_sMRQ",
                "e": "AQAB",
                "alg": "RS256"
            }]
        });
        let jwks: JwkSet =
            serde_json::from_value(raw).expect("Key without kid should deserialize");
        assert!(jwks.keys[0].common.key_id.is_none());
    }

    #[test]
    fn jwks_with_mixed_key_types_deserializes() {
        // Keycloak may include non-RSA keys (e.g. EC keys). The JwkSet should
        // deserialize all of them; the validation code selects the right one
        // via `kid` or by trying supported keys.
        let raw = serde_json::json!({
            "keys": [
                {
                    "kid": "ec-key",
                    "kty": "EC",
                    "alg": "ES256",
                    "use": "sig",
                    "crv": "P-256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                },
                {
                    "kid": "rsa-key",
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "sIwr2R0Z3xGxFEBrBmJfVVlyGSFmIRgpLLqDqv2lClSuTuFiXXFTe5X-YXjqWpO0m_hm5y3y1xMZ8hLY6nJxKb1yXpSv_g_sHg0U_RcuGYmByKcCk4yxb0kgPqcFM1pBbONkMFDo3-BHC9n0DqxJn6ykJhpFHBSByj7HWluMfTYBbxeUdAfMhbxfRNVhDFjGSAEBiLxHR4oxXKH9VhWx0iVJiY4kf1xtRFBf5nDBjLY0V5oU8vbHQN_LRG0EG0SKnPVDxIoqECl_eLFP5lWsxJkx1k8ikRj_KO9QcE6iJlb6G_DwqJ_JiIPqOTLzriFHMjX6cBvuHFv_sMRQ",
                    "e": "AQAB"
                }
            ]
        });

        let jwks: JwkSet = serde_json::from_value(raw)
            .expect("Mixed-type JWKS should deserialize without error");

        assert_eq!(jwks.keys.len(), 2, "both keys should be present after parsing");
        assert_eq!(jwks.keys[0].common.key_id.as_deref(), Some("ec-key"));
        assert_eq!(jwks.keys[1].common.key_id.as_deref(), Some("rsa-key"));
    }

    // ── allowed_algorithms_from_jwks unit tests ───────────────────────────────

    /// Convenience: parse a JWKS JSON value and return the allowed algorithm set.
    fn allowed_algs(raw: Value) -> HashSet<Algorithm> {
        let jwks: JwkSet = serde_json::from_value(raw).unwrap();
        allowed_algorithms_from_jwks(&jwks)
    }

    #[test]
    fn rsa_key_with_alg_rs256_allows_only_rs256() {
        let algs = allowed_algs(serde_json::json!({
            "keys": [{
                "kty": "RSA", "alg": "RS256", "use": "sig",
                "n": "sIwr2R0Z3xGxFEBrBmJfVVlyGSFmIRgpLLqDqv2lClSuTuFiXXFTe5X-YXjqWpO0m_hm5y3y1xMZ8hLY6nJxKb1yXpSv_g_sHg0U_RcuGYmByKcCk4yxb0kgPqcFM1pBbONkMFDo3-BHC9n0DqxJn6ykJhpFHBSByj7HWluMfTYBbxeUdAfMhbxfRNVhDFjGSAEBiLxHR4oxXKH9VhWx0iVJiY4kf1xtRFBf5nDBjLY0V5oU8vbHQN_LRG0EG0SKnPVDxIoqECl_eLFP5lWsxJkx1k8ikRj_KO9QcE6iJlb6G_DwqJ_JiIPqOTLzriFHMjX6cBvuHFv_sMRQ",
                "e": "AQAB"
            }]
        }));
        assert_eq!(algs, HashSet::from([Algorithm::RS256]));
    }

    #[test]
    fn rsa_key_without_alg_field_allows_all_rsa_algorithms() {
        let algs = allowed_algs(serde_json::json!({
            "keys": [{
                "kty": "RSA", "use": "sig",
                "n": "sIwr2R0Z3xGxFEBrBmJfVVlyGSFmIRgpLLqDqv2lClSuTuFiXXFTe5X-YXjqWpO0m_hm5y3y1xMZ8hLY6nJxKb1yXpSv_g_sHg0U_RcuGYmByKcCk4yxb0kgPqcFM1pBbONkMFDo3-BHC9n0DqxJn6ykJhpFHBSByj7HWluMfTYBbxeUdAfMhbxfRNVhDFjGSAEBiLxHR4oxXKH9VhWx0iVJiY4kf1xtRFBf5nDBjLY0V5oU8vbHQN_LRG0EG0SKnPVDxIoqECl_eLFP5lWsxJkx1k8ikRj_KO9QcE6iJlb6G_DwqJ_JiIPqOTLzriFHMjX6cBvuHFv_sMRQ",
                "e": "AQAB"
            }]
        }));
        assert_eq!(
            algs,
            HashSet::from([
                Algorithm::RS256, Algorithm::RS384, Algorithm::RS512,
                Algorithm::PS256, Algorithm::PS384, Algorithm::PS512,
            ])
        );
    }

    #[test]
    fn ec_p256_key_with_alg_allows_only_es256() {
        let algs = allowed_algs(serde_json::json!({
            "keys": [{
                "kty": "EC", "alg": "ES256", "use": "sig", "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
            }]
        }));
        assert_eq!(algs, HashSet::from([Algorithm::ES256]));
    }

    #[test]
    fn ec_p256_key_without_alg_allows_only_es256() {
        let algs = allowed_algs(serde_json::json!({
            "keys": [{
                "kty": "EC", "use": "sig", "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
            }]
        }));
        assert_eq!(algs, HashSet::from([Algorithm::ES256]));
    }

    #[test]
    fn mixed_jwks_rs256_and_es256_both_allowed() {
        let algs = allowed_algs(serde_json::json!({
            "keys": [
                {
                    "kty": "RSA", "alg": "RS256", "use": "sig",
                    "n": "sIwr2R0Z3xGxFEBrBmJfVVlyGSFmIRgpLLqDqv2lClSuTuFiXXFTe5X-YXjqWpO0m_hm5y3y1xMZ8hLY6nJxKb1yXpSv_g_sHg0U_RcuGYmByKcCk4yxb0kgPqcFM1pBbONkMFDo3-BHC9n0DqxJn6ykJhpFHBSByj7HWluMfTYBbxeUdAfMhbxfRNVhDFjGSAEBiLxHR4oxXKH9VhWx0iVJiY4kf1xtRFBf5nDBjLY0V5oU8vbHQN_LRG0EG0SKnPVDxIoqECl_eLFP5lWsxJkx1k8ikRj_KO9QcE6iJlb6G_DwqJ_JiIPqOTLzriFHMjX6cBvuHFv_sMRQ",
                    "e": "AQAB"
                },
                {
                    "kty": "EC", "alg": "ES256", "use": "sig", "crv": "P-256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                }
            ]
        }));
        assert_eq!(algs, HashSet::from([Algorithm::RS256, Algorithm::ES256]));
    }

    // ── algorithm_for_jwk unit tests ──────────────────────────────────────────

    #[test]
    fn algorithm_confusion_rsa_key_with_ec_header_rejected() {
        // Build a JWK with an RSA key and `alg: RS256`.
        let raw = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": "sIwr2R0Z3xGxFEBrBmJfVVlyGSFmIRgpLLqDqv2lClSuTuFiXXFTe5X-YXjqWpO0m_hm5y3y1xMZ8hLY6nJxKb1yXpSv_g_sHg0U_RcuGYmByKcCk4yxb0kgPqcFM1pBbONkMFDo3-BHC9n0DqxJn6ykJhpFHBSByj7HWluMfTYBbxeUdAfMhbxfRNVhDFjGSAEBiLxHR4oxXKH9VhWx0iVJiY4kf1xtRFBf5nDBjLY0V5oU8vbHQN_LRG0EG0SKnPVDxIoqECl_eLFP5lWsxJkx1k8ikRj_KO9QcE6iJlb6G_DwqJ_JiIPqOTLzriFHMjX6cBvuHFv_sMRQ",
                "e": "AQAB"
            }]
        });
        let jwks: JwkSet = serde_json::from_value(raw).unwrap();
        let jwk = &jwks.keys[0];

        // Simulate a JWT header claiming ES256 while the key is RSA/RS256.
        let result = algorithm_for_jwk(jwk, Algorithm::ES256);
        assert!(
            result.is_err(),
            "Algorithm confusion attack must be rejected"
        );
    }

    #[test]
    fn rsa_key_without_alg_field_accepts_rs256_header() {
        let raw = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                // no "alg" field
                "n": "sIwr2R0Z3xGxFEBrBmJfVVlyGSFmIRgpLLqDqv2lClSuTuFiXXFTe5X-YXjqWpO0m_hm5y3y1xMZ8hLY6nJxKb1yXpSv_g_sHg0U_RcuGYmByKcCk4yxb0kgPqcFM1pBbONkMFDo3-BHC9n0DqxJn6ykJhpFHBSByj7HWluMfTYBbxeUdAfMhbxfRNVhDFjGSAEBiLxHR4oxXKH9VhWx0iVJiY4kf1xtRFBf5nDBjLY0V5oU8vbHQN_LRG0EG0SKnPVDxIoqECl_eLFP5lWsxJkx1k8ikRj_KO9QcE6iJlb6G_DwqJ_JiIPqOTLzriFHMjX6cBvuHFv_sMRQ",
                "e": "AQAB"
            }]
        });
        let jwks: JwkSet = serde_json::from_value(raw).unwrap();
        let alg = algorithm_for_jwk(&jwks.keys[0], Algorithm::RS256).unwrap();
        assert_eq!(alg, Algorithm::RS256);
    }

    #[test]
    fn rsa_key_without_alg_field_rejects_es256_header() {
        let raw = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "n": "sIwr2R0Z3xGxFEBrBmJfVVlyGSFmIRgpLLqDqv2lClSuTuFiXXFTe5X-YXjqWpO0m_hm5y3y1xMZ8hLY6nJxKb1yXpSv_g_sHg0U_RcuGYmByKcCk4yxb0kgPqcFM1pBbONkMFDo3-BHC9n0DqxJn6ykJhpFHBSByj7HWluMfTYBbxeUdAfMhbxfRNVhDFjGSAEBiLxHR4oxXKH9VhWx0iVJiY4kf1xtRFBf5nDBjLY0V5oU8vbHQN_LRG0EG0SKnPVDxIoqECl_eLFP5lWsxJkx1k8ikRj_KO9QcE6iJlb6G_DwqJ_JiIPqOTLzriFHMjX6cBvuHFv_sMRQ",
                "e": "AQAB"
            }]
        });
        let jwks: JwkSet = serde_json::from_value(raw).unwrap();
        let result = algorithm_for_jwk(&jwks.keys[0], Algorithm::ES256);
        assert!(result.is_err(), "ES256 header with RSA key must be rejected");
    }

    // ── validate_token: algorithm not in JWKS ─────────────────────────────────

    #[tokio::test]
    async fn token_with_algorithm_not_in_jwks_is_rejected() {
        // JWKS advertises only RS256. A JWT signed with ES256 must be rejected
        // before signature verification — the algorithm is simply not permitted.
        let (jwks_json, es256_encoding_key) = build_es256_jwks_and_key(None);
        let (rsa_private, rsa_public) = generate_rsa_keypair();

        // Build a JWKS that only contains the RSA/RS256 key.
        let rs256_only_jwks = build_rsa_jwks_json(&rsa_public, None);
        let cache = cache_with_jwks(rs256_only_jwks).await;

        // Sign a valid JWT with the ES256 key — not present in the RS256-only JWKS.
        let _ = jwks_json; // EC JWKS not loaded into cache
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut claims = HashMap::new();
        claims.insert("sub", json!("mallory"));
        claims.insert("exp", json!(now + 3600));
        let es256_token = encode(
            &Header::new(Algorithm::ES256),
            &claims,
            &es256_encoding_key,
        )
        .expect("Failed to sign ES256 JWT");

        let result = cache.validate_token(&es256_token, "sub", None).await;
        assert!(
            result.is_err(),
            "ES256 JWT must be rejected when JWKS only contains RS256 keys"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not permitted"),
            "Error should mention the algorithm is not permitted, got: {err}"
        );

        // Sanity check: the matching RS256 token IS accepted.
        let rsa_token = sign_rsa_jwt(&rsa_private, "sub", "alice", 3600, None);
        assert!(cache.validate_token(&rsa_token, "sub", None).await.is_ok());
    }

    #[tokio::test]
    async fn token_with_rs384_rejected_when_jwks_only_has_rs256() {
        // A JWKS key carrying `alg: RS256` should not accept RS384 tokens,
        // even though both algorithms share the RSA key type.
        let (rsa_private, rsa_public) = generate_rsa_keypair();
        let cache = cache_with_jwks(build_rsa_jwks_json(&rsa_public, None)).await;

        // Sign a token with RS384 using the same private key.
        let der = rsa_private.to_pkcs1_der().unwrap();
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut claims = HashMap::new();
        claims.insert("sub", json!("mallory"));
        claims.insert("exp", json!(now + 3600));
        let rs384_token = encode(&Header::new(Algorithm::RS384), &claims, &encoding_key)
            .expect("Failed to sign RS384 JWT");

        let result = cache.validate_token(&rs384_token, "sub", None).await;
        assert!(
            result.is_err(),
            "RS384 JWT must be rejected when JWKS only advertises RS256"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not permitted"),
            "Error should mention the algorithm is not permitted, got: {err}"
        );
    }

    // ── validate_auth_config ───────────────────────────────────────────────────

    #[test]
    fn auth_config_both_none_ok() {
        assert!(validate_auth_config(&None, &None).is_ok());
    }

    #[test]
    fn auth_config_both_some_ok() {
        assert!(validate_auth_config(
            &Some(vec!["alice".to_string()]),
            &Some("https://example.com/certs".to_string())
        )
        .is_ok());
    }

    #[test]
    fn auth_config_users_without_jwks_url_errors() {
        assert!(validate_auth_config(&Some(vec!["alice".to_string()]), &None).is_err());
    }

    #[test]
    fn auth_config_jwks_url_without_users_errors() {
        assert!(
            validate_auth_config(&None, &Some("https://example.com/certs".to_string())).is_err()
        );
    }
}
