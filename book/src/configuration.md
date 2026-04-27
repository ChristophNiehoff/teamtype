<!--
SPDX-FileCopyrightText: 2024 blinry <mail@blinry.org>
SPDX-FileCopyrightText: 2024 zormit <nt4u@kpvn.de>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Configuration

You can put the following options into a configuration file at `.teamtype/config`:

```ini
username = <string>
peer = <secret_address>
emit_join_code = <true/false>
emit_secret_address = <true/false>
magic_wormhole_relay = <magic_wormhole_mailbox_relay_url>
relay = <iroh_relay_url>
discovery = <pkarr_discovery_relay_url>
auth_token = <jwt_bearer_token>
```

After a successful `teamtype join`, the peer's secret address is automatically stored in your `.teamtype/config`.
In the future, you can then use `teamtype join` without a join code to reconnect to the same peer.

## JWT allow-list authentication

By default any peer that knows the secret address can connect to a Teamtype host. For deployments that need to restrict access to specific users, the host can enable JWT-based allow-list authentication.

### Host side

Start the host with `--allowed-users` and `--jwks-url`:

```bash
teamtype share \
  --allowed-users alice,bob,charlie \
  --jwks-url https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs
```

- **`--allowed-users`**: Comma-separated list of permitted values for the username claim. Which claim is read from the token is controlled by `--username-claim` (default: `sub`). Joining peers whose token's claim value is not in this list are rejected.
- **`--jwks-url`**: URL of the JWKS endpoint used to verify JWT signatures. Keycloak exposes this at `<realm-url>/protocol/openid-connect/certs`. Both flags must be set together.
- **`--username-claim`**: Name of the JWT claim to match against `--allowed-users`. Defaults to `sub`. Set to `preferred_username` (or `email`, `azp`, etc.) if your identity provider uses a different claim.
- **`--audience`**: Expected audience value. When set, the token's `aud` claim must contain this string, otherwise the connection is rejected. The `aud` claim may be a single string or a list of strings (RFC 7519). Omit this flag to skip audience validation.

Example using Keycloak's `preferred_username` and enforcing an audience:

```bash
teamtype share \
  --allowed-users alice,bob \
  --jwks-url https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs \
  --username-claim preferred_username \
  --audience my-teamtype-client
```

The host fetches the JWKS keys on startup and uses them to verify every incoming connection. RS256 tokens are supported.

### Joiner side

Pass `--auth-token` with a valid JWT obtained from your identity provider:

```bash
teamtype join --auth-token eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

Alternatively, store the token in `.teamtype/config` so it is used automatically:

```ini
auth_token = eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### How it works

When JWT auth is enabled:

1. The joiner sends the passphrase (existing authentication) followed by the JWT token.
2. The host verifies the JWT signature against the JWKS keys.
3. The host checks that the token's username claim (configured via `--username-claim`, default `sub`) is in the allow list.
4. The host sends back an accept or reject byte. The joiner is informed if the connection is rejected.

When `--allowed-users` is **not** set on the host, no JWT is expected and the old passphrase-only protocol is used unchanged (backward compatible).

### Notes

- Tokens are only checked at connection time. A token that expires mid-session does not interrupt an existing connection.
- Both peers must agree on the authentication mode: a joiner without `--auth-token` cannot connect to a host that requires it, and vice versa.
- Use short-lived tokens from your identity provider for easy revocation: remove the user from `--allowed-users` and restart the host.
