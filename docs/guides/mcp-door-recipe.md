# Protect an MCP endpoint with an external issuer

Use `mcp_door` to admit one enrolled caller to a self-hosted app's HTTP MCP endpoint. Your OpenID Connect issuer issues the access token. Pipelock verifies it and consumes it at the listener. Restrict direct access to the upstream to trusted callers, such as the Pipelock host.

In this example, the public MCP URL is `https://mcp.vendor.example/mcp` and the upstream is `https://app.example.com/mcp`. At your TLS frontend, route `/mcp` and `/.well-known/oauth-protected-resource/mcp` on `mcp.vendor.example` to the Pipelock listener. Use the exact public URL as the token audience, including the path.

## JWT verification

Use this option with an issuer that emits RFC 9068 access tokens. Give the caller an RS256-signed access token with a JOSE header type of `at+jwt` or `application/at+jwt`. The token must carry `iss`, `aud`, `sub`, `client_id`, `iat`, `exp`, and `jti`.

Save your issuer's public RSA signing keys as a pinned JSON Web Key Set (JWKS) at `/etc/pipelock/issuer-public.jwks.json`. Keep the key IDs intact. Copy this example to `door.yaml` and replace the issuer, audience, subject, and client ID with your values. The enrollment must match the token's `sub` and `client_id` exactly.

```yaml
mcp_door:
  enabled: true
  mode: jwt
  issuer: https://idp.example.com/realms/example
  audience: https://mcp.vendor.example/mcp
  jwks_file: /etc/pipelock/issuer-public.jwks.json
  enrollments:
    - subject: caller-subject
      client_id: mcp-caller
```

## Introspection with Keycloak

Use this option with a Keycloak realm whose access tokens don't match the JWT profile above. Keycloak allows introspection only when the confidential client's client ID is in the access token's `aud` claim. Pipelock also requires the public MCP URL in the introspection response's `aud`.

Add two Audience protocol mappers to a client scope assigned to the caller's client. On the first mapper, leave **Included Client Audience** empty and set **Included Custom Audience** to `https://mcp.vendor.example/mcp`. Keycloak uses a custom audience only when the client audience is empty, so the second mapper is separate. Set **Included Client Audience** to `mcp-introspector` and leave **Included Custom Audience** empty. On both mappers, leave **Add to access token** and **Add to token introspection** on. Assign the client scope to the caller's client as a **Default** client scope. Keycloak runs an **Optional** client scope's mappers only when the token request names that scope in its `scope` parameter, so a caller that omits it gets a token without either audience and Pipelock rejects it.

Use a confidential client named `mcp-introspector` for Pipelock to call the realm's introspection endpoint. Save its secret to `/etc/pipelock/introspection-client.secret`, with owner-only permissions (`0600` on Unix), readable by the account running Pipelock. For an enrolled caller's access token, check that the endpoint returns `active: true`, both audience values in `aud`, a future `exp`, and the enrolled `sub` and `client_id`. The enrollment's client ID is the **caller's** client ID. The top-level `client_id` under `mcp_door` identifies the confidential client that Pipelock uses for introspection.

Save this version as `door.yaml` if you're using introspection.

```yaml
mcp_door:
  enabled: true
  mode: introspection
  issuer: https://idp.example.com/realms/example
  audience: https://mcp.vendor.example/mcp
  introspection_url: https://idp.example.com/realms/example/protocol/openid-connect/token/introspect
  client_id: mcp-introspector
  client_secret_file: /etc/pipelock/introspection-client.secret
  timeout_seconds: 10
  enrollments:
    - subject: caller-subject
      client_id: mcp-caller
```

## Start the listener

```bash
pipelock mcp proxy --listen localhost:8889 --upstream https://app.example.com/mcp --config door.yaml
```

Point your MCP client at the public MCP URL and send its access token in `Authorization: Bearer <access-token>`. Pipelock removes the door token before sending the request upstream. Startup refuses static upstream `Authorization` and `Proxy-Authorization` from `--header`, `--header-file`, or `--header-carrier`. Startup also refuses a username or password in the `--upstream` URL. Remove those settings when you enable the door.

| Response | Meaning |
| --- | --- |
| Upstream MCP response | The issuer's token matched the enrolled caller and the request passed Pipelock policy. |
| `401 Unauthorized` | The token was missing, invalid, or incomplete. Pipelock sends a `WWW-Authenticate: Bearer` challenge with the door's `resource_metadata` URL. |
| `403 Forbidden` | The verified caller lacks an enrollment or a required scope, or an enforcing tool policy denied the call. |
| `503 Service Unavailable` | The verifier timed out or returned an invalid response, or verifier keys or credentials became unavailable. Pipelock makes zero upstream dials for this request. |
| `400 Bad Request` | The token presentation was malformed, for example multiple `Authorization` values or an `access_token` query parameter. |

Missing verifier material at startup prevents the listener from starting. Restart the proxy after editing `door.yaml`, including changes to enrollment. See [OAuth caller verification](../configuration.md#oauth-caller-verification-mcp_door) for claim validation, scopes, and verifier file rotation.
