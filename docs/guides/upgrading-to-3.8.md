<!--
Copyright 2026 Pipelock contributors
SPDX-License-Identifier: Apache-2.0
-->

# Upgrading to 3.8

This guide covers operator actions when moving from the 3.7 release line. Install the new binary before loading configuration that uses new fields. The [changelog](../../CHANGELOG.md) covers the release's features and fixes. If you're upgrading from an earlier release, also read the [3.7 upgrade guide](upgrading-to-3.7.md).

## Move metrics scrapers to a dedicated listener

The agent-facing proxy no longer serves `/metrics` or `/stats`. Counters still collect internally, but neither route is exposed unless `metrics_listen` names a dedicated listener. Omitted, null and blank values disable the listener at startup. This also applies to sandbox proxy listeners. Managed containment rejects a reload that removes or blanks the setting: the existing listener stays bound, `/metrics` returns `403` until a valid reload clears the denial, and `/stats` keeps serving loopback clients. Restart with the setting removed or blank to disable that listener.

For a scraper on the proxy host, add this field to the existing configuration:

```yaml
metrics_listen: "127.0.0.1:9091"
```

Restart Pipelock and point the scraper at that port. Address changes require restart. The listener has no authentication. Loopback alone doesn't separate same-host processes; keep agents off it using the operating-system or container network boundary. A non-loopback listener in managed containment also requires a current `containment.metrics_exposure` policy. That policy permits only `/metrics`; `/stats` remains loopback-only. See the [metrics guide](../metrics.md) and [managed metrics invariant](../contain-cli.md#managed-metrics-invariant).

## Update image and chart repositories

This release publishes images and Helm charts under `ghcr.io/pipelab-org`. Update registry allowlists, image repository overrides and Helm OCI references. The image names remain `pipelock`, `pipelock-init` and `pipelock-license-service`; the chart remains `charts/pipelock`. A retained `image.digest` selects that exact older artifact even after `image.tag` or the chart version changes, so choose the intended release digest explicitly.

After publication, download and verify the release's `release-images.json`, then use its repository and digest pairs. The [release integrity instructions](../../README.md#verify-release-integrity) explain archive verification, and the [Kubernetes image guide](kubernetes-image-upgrades.md) demonstrates digest pinning and rollback using a verified historical release. Don't substitute a new version into historical digest or attestation evidence. New attestations use `pipelab-org/pipelock` as repository and workflow signer; older releases keep their original identity. The Go module path and Homebrew tap are unchanged.

Regenerate Compose and sidecar output to pick up the new image defaults. For `init sidecar`, `--image` can still select an explicit image reference. Helm users with an explicit `image.repository` must update it themselves.

## Review temporary exceptions and URL limits

Valid expired scanner exceptions now lapse with a warning instead of refusing an otherwise-valid configuration. Normal scanning resumes for the expired scope, while valid siblings remain active. Malformed declarations still refuse even if their date is expired. Running scanners enforce expiry without a reload; warnings are emitted during startup or reload, with no separate clock-triggered warning. Review expiry warnings during upgrade and renew only exceptions you still intend to grant. See [temporary expiry behavior](../configuration.md#hot-reload).

The default `fetch_proxy.monitoring.max_url_length` increases from 2048 to 8000 octets, following RFC 9110's URI-size recommendation. Explicit values and presets with their own lower limits retain those limits. Set the field explicitly if you need the previous ceiling. DLP, entropy and the other URL checks continue to run.

Floating-point settings must now be finite. If an existing configuration contains NaN or infinity, replace it with a finite value inside the setting's supported range before upgrading. Invalid values refuse configuration loading and reload; the error names the field.

## Review effective scanning and regenerated presets

The new `prompt_injection_detection` policy controls supported regex wording checks. Leave it omitted to retain legacy behavior; review the [configuration contract](../configuration.md#prompt-injection-wording-detection) before selecting warn or off. Those settings don't turn off DLP or other independent security controls. Wording detection set to off grants no traffic-based recovery credit. Warn-only matches don't create hostile taint or earn clean-assessment credit; assessed-clean traffic in warn-only mode still supports recovery.

For legacy MCP sections, `enabled: false` with an empty action can still mean scanning is active. Startup and doctor diagnostics name the action needed for an intentional disable; use the documented explicit action and review immutable protections rather than relying on the boolean alone.

`mode: audit` alone keeps the default `enforce: true`, so ordinary URL findings still block. Use the bundled `audit` preset for an observation trial. The mode name alone doesn't change scanning actions or the independent core and transport refusals. Startup and check warnings, status and dashboard output now report that effective behavior.

Generated configurations now preserve bundled policy. The audit preset keeps explicit tool-policy blocks, warns on ordinary findings and disables adaptive escalation. Regenerated strict configurations retain their strict actions, taint policy and tool-chain detection. Compare generated output with your existing policy before replacing it. See [configuration generation](../configuration.md) and [MCP diagnostics](../cli/doctor.md).

The `claude-code`, `cursor`, `generic-agent`, and `hostile-model` presets and the quickstart example also retain built-in response patterns alongside their supplemental expressions. Regenerated YAML uses `Preset` names for the supplemental expressions. Review name-based alerts and suppressions before replacing an older configuration: an old rule name doesn't cover its supplemental `Preset` counterpart. Existing saved configurations keep their names until edited or replaced. See [preset migration](../configuration.md#presets).

Tool policy rules also match a bounded reading of shell expansions the command text decides, such as unset parameters, brace items and literal brackets. A word past the expansion bound reports an incomplete check, which `on_incomplete_check` turns into a warning or a block. Review rules for commands that legitimately use these forms. See [MCP tool policy](../configuration.md#mcp-tool-policy).

## Check what upload inspection covers

Request scanning reads the text inside ZIP uploads and ZIP-based Office files such as `.docx`, `.xlsx` and `.pptx`, within extraction limits. Legacy `.doc` and `.xls` files sent on their own aren't opened for text extraction; other checks still apply to them. Files it can't open, or that go over the limits, keep their stated refusal or limits. With the built-in `warn` action an unreadable archive is still delivered; with `action: block` and `enforce: true` it's withheld.

HTTPS through the forward proxy (CONNECT) needs TLS interception, which is off in defaults and all 7 presets. Plain-HTTP forward proxy and reverse proxy bodies are scanned without it. WebSocket client text is scanned when traffic goes through the WebSocket proxy (`websocket_proxy`, off by default); WSS carried in an ordinary CONNECT tunnel stays opaque without interception. PDF text isn't extracted yet; PDF uploads only get the existing raw-byte scan. See [request body scanning](../configuration.md#request-body-scanning).

## Review repository-scan suppressions

`pipelock git scan-diff`, `pipelock audit`, and the GitHub Action apply the core DLP floor even when configured defaults are disabled or a custom pattern reuses a built-in name. Inline `pipelock:ignore` markers and rule suppressions can't silence core findings. Synthetic fixtures can therefore produce findings after upgrading. Construct synthetic values from fragments where possible; path exclusions remove every finding for that path, including core findings, so review them narrowly. Generated pre-push hooks don't expose an exclusion option. See the [suppression guide](suppression.md).

## Reinstall and verify managed containment units

After replacing the binary, rerun `pipelock contain install` with the same intended configuration and deployment options, then run `pipelock contain verify` and `pipelock contain doctor`. Binary upgrade alone doesn't replace every forwarder definition. The new forwarders report ready only after their listener binds. Install verifies the doorway from inside the managed namespace and rolls back a failed activation.

Install now refuses runtime write paths the managed service can't use. Keep the recorder and other mutable state under the managed data directory as the diagnostics specify. A service-aware configuration check validates supported systemd environment and identity inputs; it doesn't recreate the service's mount namespace or prove that every file is accessible there. See [`check --service`](../cli/check.md#validate-for-the-local-service) and [host containment](../contain-cli.md).

Strict sandbox cross-directory renames and hard links require a kernel that reports Landlock erratum 3 fixed. Otherwise they remain denied with `EXDEV`; don't interpret that as a failed proxy connection. Guard records the withheld permission, and older typed Guard proof readers can reject a proof carrying that field. See [sandbox limits](sandbox.md) and [Guard](../cli/guard.md).

## Query reload results instead of assuming activation

Use [`pipelock reload`](../cli/reload.md) when automation needs a synchronous activation verdict. It uses the authenticated admin API and the daemon's configured file. `reload --status --json` reports active policy identity and settings still awaiting restart. Rejected candidates leave the active policy in place. An uncertain result denies traffic until recovered; a cancelled client request doesn't prove that the daemon stopped processing it.

`systemctl reload` retains its systemd-specific semantics. Even on a notify-reload unit, a successful command means the evaluation completed, not that a rejected candidate became active. File-watcher reloads remain asynchronous. Inspect the activation result and pending restart fields.

## Export Codex MCP environment variables at runtime

`pipelock codex install` registers server environment variables by name in Codex's `env_vars` list instead of placing values on the registration command line. Export the required variables in the environment that launches Codex, including after a service or desktop restart. Install prints the required names and refuses missing values before changing registrations. See the [Codex guide](codex.md).

## Keep inspection and evidence limits visible

Oversized complete JSON on forward HTTP, intercepted HTTPS and reverse proxy paths can now receive bounded partial inspection without a host exception. The body stays withheld until policy permits delivery, and evidence labels the inspection as partial. Field and adjacent-pair checks don't establish whole-document safety; fetch and MCP retain their ordinary caps. Existing fully scanned size-exempt routes retain their separate behavior. See [response scanning](../configuration.md#response-scanning).

Fleet receipt reports now default to v2 and distinguish recorder runs across follower restarts. Update report consumers and retain the full evidence and trusted keys. The [fleet verification contract](../specs/fleet-receipt-v2-verification.md) and [receipt guide](receipt-verification.md) describe integrity, completeness and end-proof limits. Independently versioned verifier packages must be selected from the publication matrix; a source version isn't proof that the package is published.

Discovery now marks file-only MCP wrappers as `unconfirmed`; an integration entry doesn't prove the client actually used it. Doctor and explain also show request-local or missing taint history. Review the reported boundary instead of treating discovery success or a clean content verdict as complete runtime coverage.

## Update evidence consumers and inspection expectations

A valid evidence prefix without a proven end reports `VALID PREFIX, END UNPROVEN` and exits 3. Audit packets, fleet reports, coverage certificates, AARP chains and dashboard trust views distinguish that result from complete evidence. Update scripts that previously treated signature validity or exit 0 as sufficient, and use `--allow-prefix` only where deliberately accepting a supported open prefix. Single-receipt signature verification keeps its existing exit contract. Sequence endpoint pins now accept ASCII decimal digits only, interpreted in base ten. See the [verification guide](receipt-verification.md) for format-specific flags and proof limits.

Signed HTTP and WebSocket URL targets retain only destination scheme, host and port; request userinfo, paths, queries and fragments are removed. Invalid or hostless web URL targets are redacted. Audit logs also drop userinfo, queries and fragments, retaining paths only for supported path-traversal and CRLF diagnostics. Update downstream lookups that depended on request paths in signed targets. MCP server targets retain their operator-chosen server spelling.

Outbound inspection now refuses supported encoded content when a decoding depth or work bound leaves a new view uninspected, including under audit or warn policy. Large single-layer content can still be inspected within its transport limit; nested encodings can exhaust the recursive budget. Inbound text retains its partial-view policy. These refusals don't establish detection of every encoding or repair every split-token reassembly limit. Review the [documented decoding boundary](../bypass-resistance.md) before relying on it.

Install the new binary before adding `request_policy.rules[].except.requests` or `fetch_proxy.monitoring.issued_redirect_delegations`; older binaries reject those fields. Exact-request entries grant only the reviewed URL, method and JSON body digest until expiry, and can be reused while active. Redirect delegations grant supported entropy relief only to exact issued URLs on declared origins. Keep these optional policies absent unless you intend their documented trust and scope. See [request-policy exceptions](request-policy.md#rolling-out-safely) and [redirect delegation](../configuration.md#fetch-proxy).

Provider credential relief now checks the supported endpoint and carrier, including redirect handling, rather than accepting a broad provider-like host. Previously allowed calls can therefore block after upgrade. Check the [credential audience reference](../security/provider-key-dlp-coverage.md) and keep credentials in their documented header or query carrier on the intended endpoint. `Api-Key` also joins the default sensitive-header set. The built-in policy hash changes; refresh consumers that pin the old hash when republishing fleet policy. These changes don't grant a general provider-host exemption.

WebSocket cross-message inspection has a configurable `websocket_proxy.cross_message_field_limit`. A message that cannot be joined within that field budget closes the connection; review the [WebSocket reference](../configuration.md#websocket-proxy) before raising it for large tool schemas. A positive MCP `response_timeout_seconds` now also limits the A2A response and Agent Card scan in each MCP proxy mode; an incomplete scan blocks its response.
