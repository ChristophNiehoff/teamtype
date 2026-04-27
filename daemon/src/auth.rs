// SPDX-FileCopyrightText: 2026 TNG Technology Consulting GmbH <christoph.niehoff@tngtech.com>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! JWT-based authentication for allow-list access control.
//!
//! Provides [`JwksCache`], which fetches a JWKS (JSON Web Key Set) from an OIDC
//! provider (e.g. Keycloak) and validates JWT tokens against those keys. Only
//! RS256-signed tokens are supported, matching standard Keycloak defaults.

use anyhow::{Context, Result, anyhow, bail};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::debug;

/// The JWT claim name used when none is explicitly configured.
pub const DEFAULT_USERNAME_CLAIM: &str = "sub";

#[derive(Debug, Deserialize)]
struct JwksKey {
    kid: Option<String>,
    /// RSA modulus (base64url-encoded). Only present on RSA keys.
    n: Option<String>,
    /// RSA public exponent (base64url-encoded). Only present on RSA keys.
    e: Option<String>,
    // All other JWKS fields (kty, alg, use, x5c, x5t, …) are intentionally
    // ignored; serde skips unknown fields by default.
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<JwksKey>,
}

// ── Public API ─────────────────────────────────────────────────────────────────

/// Cached JWKS key set fetched from an OIDC provider.
///
/// Fetches once on startup (via [`JwksCache::refresh`]) and caches the keys
/// for all subsequent [`JwksCache::validate_token`] calls.
pub struct JwksCache {
    keys: RwLock<Option<Jwks>>,
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
        let jwks: Jwks = reqwest::get(&self.url)
            .await
            .context("Failed to fetch JWKS")?
            .json()
            .await
            .context("Failed to parse JWKS response as JSON")?;
        *self.keys.write().await = Some(jwks);
        debug!("JWKS fetched successfully");
        Ok(())
    }

    /// Validate an RS256 JWT and return the value of `claim_name` on success.
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

        // Only consider RSA keys (those that have both `n` and `e`).
        // Non-RSA keys (e.g. EC keys used for encryption) lack these fields
        // and must be skipped; otherwise deserialization and key construction
        // would fail.
        let rsa_keys: Vec<&JwksKey> = jwks
            .keys
            .iter()
            .filter(|k| k.n.is_some() && k.e.is_some())
            .collect();

        // Find the matching RSA key by `kid`, or fall back to the first RSA key
        // when the JWT header carries no `kid`.
        let jwk = match kid {
            Some(kid) => rsa_keys
                .iter()
                .find(|k| k.kid.as_deref() == Some(kid))
                .copied()
                .ok_or_else(|| anyhow!("No RSA JWKS key found matching kid={kid}"))?,
            None => rsa_keys
                .first()
                .copied()
                .ok_or_else(|| anyhow!("JWKS contains no RSA keys"))?,
        };

        let decoding_key = DecodingKey::from_rsa_components(
            jwk.n.as_deref().unwrap(),
            jwk.e.as_deref().unwrap(),
        )
        .context("Failed to build RSA decoding key from JWKS")?;

        let mut validation = Validation::new(Algorithm::RS256);
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
    pub async fn jwks_cache_from_value(jwks_json: serde_json::Value) -> JwksCache {
        let jwks: Jwks = serde_json::from_value(jwks_json).expect("Failed to parse test JWKS");
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

    // ── helpers ────────────────────────────────────────────────────────────────

    /// Generate a fresh 2048-bit RSA key pair.
    fn generate_rsa_keypair() -> (RsaPrivateKey, RsaPublicKey) {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
        let public = RsaPublicKey::from(&private);
        (private, public)
    }

    /// Build a minimal in-memory JWKS JSON value from an RSA public key.
    fn build_jwks_json(public: &RsaPublicKey, kid: Option<&str>) -> serde_json::Value {
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
    fn sign_jwt(
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

        let mut claims: HashMap<&str, serde_json::Value> = HashMap::new();
        claims.insert(claim_name, serde_json::json!(username_value));
        claims.insert("exp", serde_json::json!(now + exp_offset_secs));

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
    async fn cache_with_jwks(jwks_json: serde_json::Value) -> JwksCache {
        let jwks: Jwks = serde_json::from_value(jwks_json).expect("Failed to parse test JWKS");
        let cache = JwksCache::new("http://unused".to_string());
        *cache.keys.write().await = Some(jwks);
        cache
    }

    // ── tests ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_token_default_claim_returns_value() {
        let (private, public) = generate_rsa_keypair();
        let token = sign_jwt(&private, "sub", "alice", 3600, None);
        let cache = cache_with_jwks(build_jwks_json(&public, None)).await;

        let value = cache.validate_token(&token, "sub", None).await.unwrap();
        assert_eq!(value, "alice");
    }

    #[tokio::test]
    async fn valid_token_custom_claim_returns_value() {
        let (private, public) = generate_rsa_keypair();
        let token = sign_jwt(&private, "preferred_username", "alice", 3600, None);
        let cache = cache_with_jwks(build_jwks_json(&public, None)).await;

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
        let token = sign_jwt(&private, "sub", "alice", 3600, None);
        let cache = cache_with_jwks(build_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "preferred_username", None).await;
        assert!(result.is_err(), "Expected missing claim to be rejected");
    }

    #[tokio::test]
    async fn valid_token_with_kid_returns_value() {
        let (private, public) = generate_rsa_keypair();
        let token = sign_jwt(&private, "sub", "bob", 3600, Some("key-1"));
        let cache = cache_with_jwks(build_jwks_json(&public, Some("key-1"))).await;

        let value = cache.validate_token(&token, "sub", None).await.unwrap();
        assert_eq!(value, "bob");
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let (private, public) = generate_rsa_keypair();
        // exp well in the past (one hour ago), comfortably outside any leeway
        let token = sign_jwt(&private, "sub", "alice", -3600, None);
        let cache = cache_with_jwks(build_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "sub", None).await;
        assert!(result.is_err(), "Expected expired token to be rejected");
    }

    #[tokio::test]
    async fn wrong_kid_is_rejected() {
        let (private, _public) = generate_rsa_keypair();
        let (_other_private, other_public) = generate_rsa_keypair();
        // Token signed with `private`, JWKS contains `other_public` under different kid.
        let token = sign_jwt(&private, "sub", "alice", 3600, Some("key-1"));
        let cache = cache_with_jwks(build_jwks_json(&other_public, Some("key-2"))).await;

        let result = cache.validate_token(&token, "sub", None).await;
        assert!(result.is_err(), "Expected wrong-kid token to be rejected");
    }

    #[tokio::test]
    async fn wrong_signature_is_rejected() {
        let (private, _public) = generate_rsa_keypair();
        let (_other_private, other_public) = generate_rsa_keypair();
        // Token signed with `private`, but JWKS has `other_public` -- signature mismatch.
        let token = sign_jwt(&private, "sub", "alice", 3600, None);
        let cache = cache_with_jwks(build_jwks_json(&other_public, None)).await;

        let result = cache.validate_token(&token, "sub", None).await;
        assert!(result.is_err(), "Expected signature mismatch to be rejected");
    }

    // ── audience validation ────────────────────────────────────────────────────

    /// Sign a JWT that includes an `aud` claim.
    fn sign_jwt_with_audience(
        private: &RsaPrivateKey,
        sub_value: &str,
        aud: serde_json::Value, // either a string or array of strings
        exp_offset_secs: i64,
    ) -> String {
        use std::collections::HashMap;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut claims: HashMap<&str, serde_json::Value> = HashMap::new();
        claims.insert("sub", serde_json::json!(sub_value));
        claims.insert("aud", aud);
        claims.insert("exp", serde_json::json!(now + exp_offset_secs));
        let der = private.to_pkcs1_der().unwrap();
        let key = EncodingKey::from_rsa_der(der.as_bytes());
        encode(&Header::new(Algorithm::RS256), &claims, &key).expect("Failed to sign JWT")
    }

    #[tokio::test]
    async fn audience_not_configured_token_without_aud_accepted() {
        // When no audience is required, tokens without `aud` are accepted.
        let (private, public) = generate_rsa_keypair();
        let token = sign_jwt(&private, "sub", "alice", 3600, None);
        let cache = cache_with_jwks(build_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "sub", None).await;
        assert!(result.is_ok(), "Token without aud should be accepted when no audience configured");
    }

    #[tokio::test]
    async fn audience_string_matches_accepted() {
        // Token with `aud` as a single string matching the required audience.
        let (private, public) = generate_rsa_keypair();
        let token = sign_jwt_with_audience(
            &private, "alice", serde_json::json!("my-client"), 3600,
        );
        let cache = cache_with_jwks(build_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "sub", Some("my-client")).await;
        assert!(result.is_ok(), "Matching single-string audience should be accepted");
    }

    #[tokio::test]
    async fn audience_array_contains_required_accepted() {
        // Token with `aud` as an array that includes the required audience.
        let (private, public) = generate_rsa_keypair();
        let token = sign_jwt_with_audience(
            &private,
            "alice",
            serde_json::json!(["other-client", "my-client"]),
            3600,
        );
        let cache = cache_with_jwks(build_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "sub", Some("my-client")).await;
        assert!(result.is_ok(), "Array audience containing required value should be accepted");
    }

    #[tokio::test]
    async fn audience_string_does_not_match_rejected() {
        // Token with `aud` as a single string that doesn't match.
        let (private, public) = generate_rsa_keypair();
        let token = sign_jwt_with_audience(
            &private, "alice", serde_json::json!("other-client"), 3600,
        );
        let cache = cache_with_jwks(build_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "sub", Some("my-client")).await;
        assert!(result.is_err(), "Non-matching single-string audience should be rejected");
    }

    #[tokio::test]
    async fn audience_array_does_not_contain_required_rejected() {
        // Token with `aud` array that doesn't include the required audience.
        let (private, public) = generate_rsa_keypair();
        let token = sign_jwt_with_audience(
            &private,
            "alice",
            serde_json::json!(["other-client", "another-client"]),
            3600,
        );
        let cache = cache_with_jwks(build_jwks_json(&public, None)).await;

        let result = cache.validate_token(&token, "sub", Some("my-client")).await;
        assert!(result.is_err(), "Array audience not containing required value should be rejected");
    }

    #[tokio::test]
    async fn audience_required_but_token_has_no_aud_rejected() {
        // When audience is required, tokens without `aud` claim are rejected.
        let (private, public) = generate_rsa_keypair();
        let token = sign_jwt(&private, "sub", "alice", 3600, None); // no aud
        let cache = cache_with_jwks(build_jwks_json(&public, None)).await;

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
                    "n": "modulus-1",
                    "e": "AQAB"
                },
                {
                    "kid": "key-2",
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "modulus-2",
                    "e": "AQAB"
                }
            ]
        });

        let jwks: Jwks = serde_json::from_value(raw)
            .expect("Real-world Keycloak JWKS shape should deserialize without error");

        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].kid.as_deref(), Some("key-1"));
        assert_eq!(jwks.keys[0].n.as_deref(), Some("modulus-1"));
        assert_eq!(jwks.keys[1].kid.as_deref(), Some("key-2"));
        assert_eq!(jwks.keys[1].n.as_deref(), Some("modulus-2"));
    }

    #[test]
    fn jwks_key_without_kid_deserializes() {
        // Some providers omit the kid field entirely.
        let raw = serde_json::json!({
            "keys": [{ "kty": "RSA", "n": "modulus", "e": "AQAB" }]
        });
        let jwks: Jwks =
            serde_json::from_value(raw).expect("Key without kid should deserialize");
        assert!(jwks.keys[0].kid.is_none());
    }

    #[test]
    fn jwks_with_mixed_key_types_deserializes_and_filters_to_rsa() {
        // Keycloak may include non-RSA keys (e.g. EC keys used for encryption).
        // Those keys lack `n` and `e` and must be silently skipped.
        let raw = serde_json::json!({
            "keys": [
                {
                    "kid": "ec-key",
                    "kty": "EC",
                    "alg": "ES256",
                    "use": "enc",
                    "crv": "P-256",
                    "x": "some-x",
                    "y": "some-y"
                    // no `n` or `e`
                },
                {
                    "kid": "rsa-key",
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "modulus",
                    "e": "AQAB"
                }
            ]
        });

        let jwks: Jwks = serde_json::from_value(raw)
            .expect("Mixed-type JWKS should deserialize without error");

        assert_eq!(jwks.keys.len(), 2, "both keys should be present after parsing");

        // Only the RSA key has n+e set.
        let rsa_keys: Vec<&JwksKey> = jwks
            .keys
            .iter()
            .filter(|k| k.n.is_some() && k.e.is_some())
            .collect();
        assert_eq!(rsa_keys.len(), 1);
        assert_eq!(rsa_keys[0].kid.as_deref(), Some("rsa-key"));
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
