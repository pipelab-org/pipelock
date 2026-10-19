# `pipelock reload`

Reload the running daemon's configured file and receive that request's activation result. The daemon loads the file under its own environment. Rejected candidates keep the working configuration and security downgrade checks remain enforced.

```bash
export PIPELOCK_API_URL=http://127.0.0.1:9090
# Set PIPELOCK_KILLSWITCH_API_TOKEN through your normal secret provisioning.
pipelock reload
pipelock reload --status --json
```

The command uses the existing authenticated admin API. Configure `kill_switch.api_token` or the daemon's `PIPELOCK_KILLSWITCH_API_TOKEN`. Without an API token there is no unauthenticated fallback. Routes use `kill_switch.api_listen` when configured, otherwise the shared proxy listener. For a shared listener, supply its base URL explicitly.

| Flag | Purpose |
|---|---|
| `--api-url` | Admin base URL; overrides `PIPELOCK_API_URL`. |
| `--api-token` | Bearer token; overrides `PIPELOCK_KILLSWITCH_API_TOKEN`. Prefer the environment or protected configuration over command-line credentials. |
| `--config` | Protected local file used only to resolve API connection credentials. It cannot choose the daemon's reload source. |
| `--status` | Query live identity and the last transaction without initiating a reload. |
| `--json` | Print the daemon snapshot as JSON. |

Explicit or environment URL **and** token bypass local configuration loading. This permits recovery queries after the candidate YAML becomes invalid or disappears. Config-based connection resolution uses the same permission checks as `pipelock session`.

The API accepts `POST /api/v1/config/reload` and `GET /api/v1/config/status`. Both require the current bearer token, accept no body or query parameters, and return no configuration bytes or credential values. Token rotation takes effect through the existing admin authentication mechanism.

| Result | Meaning |
|---|---|
| `accepted` | The transaction applied its reloadable configuration. |
| `unchanged` | The completed attempt did not change runtime configuration or activation generation. |
| `rejected` | The candidate was refused before proxy publication; active identity is retained. |
| `restart_required` | Reloadable settings applied, but listed fields remain pending. The result may include both live changes and preserved settings. |
| `uncertain` | A failure occurred after publication or live/durable agreement could not be established. Traffic is denied through the uncertainty gate. Inspect daemon logs before recovery. |
| `compensated` | A Conductor transaction failed and restored the previous policy. |
| `unavailable` | The daemon has no reloadable configuration source. |

Exit zero requires `accepted` or `unchanged` with no pending restart fields. Rejection, partial application, uncertainty, compensation, unavailable service, unknown verdicts and malformed responses exit nonzero. A status query also exits nonzero when its reported state needs attention. There is no offline-validation fallback. A client timeout means the caller did not obtain a verdict; it does not prove that the daemon stopped processing the request.

Each snapshot includes a process `instance_id`, an `activation_generation`, the trigger, candidate raw `candidate_source_hash` when available, `last_accepted_source_hash`, `canonical_policy_hash`, verdict/reason, `pending_restart`, and `restart_required_fields`. It separately reports `reload_available` for synchronous file reload and `watcher_state` for automatic file/signal reload. Proxy readiness does not establish watcher availability.

Generation starts at one and advances when a publication changes the runtime configuration. Rejected attempts, identical retries and comment-only changes do not invent an activation. A restart creates a new process identity. Compensation can advance generation while restoring an earlier policy hash.

Raw source hashes identify file bytes, including comments. The last accepted source hash remains historical after partial application; it must not be interpreted as an effective whole-file identity. The canonical hash identifies the existing policy-semantic view, which excludes listener addresses and some operational settings. Neither hash proves that every candidate setting is live. Conductor bundles are enforcement-only input; their final snapshot is published after durable activation or compensation, and the whole-file accepted source hash is cleared. Their follower-local omissions do not create new restart drift.

Restart drift is recorded where the daemon preserves startup-bound settings. Pending fields remain visible across a rejected attempt. Reverting preserved settings to their live values and reloading clears that drift. Some containment fields instead require their documented install or firewall reconciliation command. The daemon cannot observe external firewall reconciliation, so its containment service fields remain pending until restart, including across repeated reloads. A restart resets this observation; it does not attest that external reconciliation succeeded. External file changes are observed when a reload attempt reads them; status is not a continuous comparison against disk.

Sentry client settings remain bound until restart, including disabling crash reporting. Live DLP changes still apply to traffic scanning. When the active crash-report scrubber differs from those DLP inputs, `sentry.scrubber` remains pending until restart or a reload restores matching inputs. This also covers changed contents at the same secrets-file path. A pending scrubber field means crash reports still use the startup redaction inputs.

Signal and filesystem reloads update the same snapshot. A queued signal remains attached to the newest coalesced candidate. systemd `STATUS` shows concise identity and verdict, but `READY=1` completes its notify-reload handshake even when the candidate is rejected. This command does not change installed units, `Type`, `ExecReload`, or `systemctl reload` exit semantics. Use `pipelock reload` when automation needs a synchronous activation verdict. See [systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) and [sd_notify](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html).
