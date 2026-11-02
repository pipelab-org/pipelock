<!--
Copyright 2026 Pipelock contributors
SPDX-License-Identifier: Apache-2.0
-->

# Upgrading to 3.8

This guide covers operator actions when moving from the 3.7 release line. Install the new binary before loading configuration that uses new fields. The [changelog](../../CHANGELOG.md) covers the release's features and fixes. If you're upgrading from an earlier release, also read the [3.7 upgrade guide](upgrading-to-3.7.md).

## Move metrics scrapers to a dedicated listener

The agent-facing proxy no longer serves `/metrics` or `/stats`. Counters still collect internally, but neither route is exposed unless `metrics_listen` names a dedicated listener. Omitted, null and blank values leave it disabled. This also applies to sandbox proxy listeners.

For a scraper on the proxy host, add this field to the existing configuration:

```yaml pipelock-fragment
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

## Review effective scanning and regenerated presets

The new `prompt_injection_detection` policy controls supported regex wording checks. Leave it omitted to retain legacy behavior; review the [configuration contract](../configuration.md#prompt-injection-wording-detection) before selecting warn or off. Those settings don't turn off DLP or other independent security controls. Wording detection set to off grants no traffic-based recovery credit. Warn-only matches don't create hostile taint or earn clean-assessment credit; assessed-clean traffic in warn-only mode still supports recovery.

For legacy MCP sections, `enabled: false` with an empty action can still mean scanning is active. Startup and doctor diagnostics name the action needed for an intentional disable; use the documented explicit action and review immutable protections rather than relying on the boolean alone.

Generated configurations now preserve bundled policy. The audit preset keeps explicit tool-policy blocks, warns on ordinary findings and disables adaptive escalation. Regenerated strict configurations retain their strict actions, taint policy and tool-chain detection. Compare generated output with your existing policy before replacing it. See [configuration generation](../configuration.md) and [MCP diagnostics](../cli/doctor.md).

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
