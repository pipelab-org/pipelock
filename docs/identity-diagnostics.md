# Inspect the caller's resolved identity

`pipelock status --identity-url` adds a live identity check to the local status report. Run it from the same environment, source address and listener as the traffic you want to understand. A check from the host reports the host caller; it doesn't establish the identity of a contained process or a different client.

```bash
pipelock status --identity-url http://127.0.0.1:8888
pipelock status --identity-url http://127.0.0.1:8888 --json
pipelock status --identity-url http://127.0.0.1:8888 --identity-agent sample-client
```

The command connects directly to the chosen listener, as the command-launch readiness check does. It doesn't follow redirects, has a bounded timeout, and uses normal HTTPS certificate verification. `--identity-agent` sends a synthetic `X-Pipelock-Agent` header to show how that request resolves; supplying a name doesn't authenticate it. No credentials are needed. Without `--identity-url`, status only reads local configuration and doesn't contact the running proxy.

The equivalent read-only API is `GET /health?identity=1` on the proxy listener. Plain `/health` retains its usual response. Identity diagnostics use the running edition's request resolver, including per-agent listener and source-CIDR bindings. The `identity` object reports only this caller, with no identity name, client address, credentials, session key, listener address or list of other agents. Responses carry `Cache-Control: no-store`.

| Field | Meaning |
| --- | --- |
| `runtime_source` | `loaded-runtime`: this check used the running proxy's loaded configuration and resolver. |
| `available` | Whether the runtime resolved this request using an available policy and entitlement. |
| `actor_auth` | The actual request grade: `bound`, `config-default`, `matched`, `self-declared`, or `unknown`. |
| `trusted_for_identity` | True only for `bound` and `config-default`, following the envelope identity contract. |
| `default_identity_configured` | An operator default identity exists in this request's effective loaded configuration. |
| `bind_default_agent_identity` | The effective loaded setting that ignores self-declared names in favor of the configured default. |
| `tls_interception_enabled` | TLS interception is enabled in the effective loaded policy. |
| `request_body_scan_enabled` | Request-body scanning is enabled in that policy. |
| `scan_headers` | Request-header scanning is enabled in that policy. |
| `issuer_bound_session_cookies` | The effective issuer-evidence feature switch. |
| `issuer_id_evidence_eligible` | This request has a trusted actual grade and all four issuer prerequisites above are enabled. |

`bound` comes from infrastructure binding, such as a dedicated listener or source-CIDR mapping. `config-default` is an operator assignment. On a shared listener, a configured default doesn't authenticate individual processes or separate callers sharing that assignment. A header matching a profile is `matched`; an arbitrary header or anonymous fallback is `self-declared`. Neither qualifies as a trusted identity. Unavailable or unrecognized provenance fails closed as `unknown`.

The diagnostic never substitutes a detection-state bucket's identity for the actual request grade. Cross-request tracking can place an untrusted request in the configured default's bucket to prevent header rotation from splitting state; that placement doesn't prove identity binding.

Eligibility describes prerequisites for issuer-bound identifier evidence. It doesn't assert that an identifier was observed, that evidence exists, or that a future request will pass its other checks. Only mediated, intercepted HTTPS traffic can supply that evidence. This HTTP diagnostic doesn't establish MCP identity or inspect other transports' sessions.

The live `identity` section and the remaining status fields have different sources. JSON reports `configuration_source: "local-configuration"` alongside the live section. The identity section reads loaded runtime state, including reloads; the other fields describe the local configuration file or built-in defaults selected for the status command. Editing a file doesn't prove the running service loaded it. Missing, malformed, unavailable, unhealthy or inconsistent live diagnostics cause a probe error instead of a locally inferred identity grade. The command omits remote bodies and sensitive connection details from those errors.
