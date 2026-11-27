# Incident response and rollback

This guide is the order of operations when an agent may have misbehaved through Pipelock, or when a Pipelock change needs to be undone. Each step names the command, who consumes its output, and what it can't tell you. The linked reference pages have the full flags and edge cases.

Commands assume `pipelock run` unless a step says otherwise. Pipelock only sees traffic routed through it, so nothing here covers an agent that reached the network another way. Containment (`pipelock contain`) is what blocks that path on supported Linux hosts.

## 1. Stop agent traffic

The kill switch denies normal traffic while any one of its sources is active. Use whichever source you can reach fastest:

| Source | How to activate | Notes |
|---|---|---|
| API | `curl -X POST http://<api_listen>/api/v1/killswitch -H "Authorization: Bearer $KILL_SWITCH_TOKEN" -H "Content-Type: application/json" -d '{"active": true}'` | Needs `kill_switch.api_token` or `api_token_file`. Set `kill_switch.api_listen` so the agent can't reach the API on the proxy port. |
| Signal | `kill -USR1 <pipelock pid>` | Toggles the signal source. Sending it again turns that source off. |
| Sentinel file | Create the file named by `kill_switch.sentinel_file` | Removing the file clears that source. |
| Config | Set `kill_switch.enabled: true` and reload | Denies all traffic from that point. |

Standalone `pipelock mcp proxy` supports only the config and sentinel-file sources. The API and SIGUSR1 belong to `pipelock run`.

Check the result with `curl http://<api_listen>/api/v1/killswitch/status -H "Authorization: Bearer $KILL_SWITCH_TOKEN"`, which lists every source and whether it's active.

Limits: configured exemptions (`health_exempt`, `api_exempt`, `allowlist_ips`) still apply on the HTTP front door. A deferred MCP call that already claimed its upstream send can't be recalled. See [Kill Switch](../configuration.md#kill-switch) for the exemption rules and the Conductor-driven sources.

## 2. Preserve evidence

Don't delete, rotate or rewrite the flight recorder directory (`flight_recorder.dir`) or the audit log (`logging.file`) until you've copied them somewhere safe.

- `pipelock evidence doctor DIR` reads a flight-recorder directory without changing it and reports structural damage such as chain gaps, forked hashes and missing genesis records. It exits nonzero when it finds damage.
- `pipelock verify-receipt --chain DIR` checks the receipt signatures and chain. A valid result shows the receipts were signed by the recorder's key and the chain is unbroken. It says nothing about traffic that didn't pass through Pipelock. See [verify-receipt](../cli/verify-receipt.md) and [Receipt verification](receipt-verification.md) for key pinning and per-run chains.
- `pipelock support bundle --config <config>` writes a secret-redacted diagnostics archive for a bug report or support request. It's built for sharing, so it omits raw config and file contents. It isn't evidence of what happened; keep the recorder and audit log for that. See [support bundle](../cli/support.md).

## 3. Find out what happened

- `pipelock logs --file <audit log> --filter blocked` shows the blocked events. `--filter` also takes `allowed`, `error` and `anomaly`.
- `pipelock explain <url>` replays a URL through the scanner with your config and names the scanner that blocked it and the setting that applies. See [explain](../cli/explain.md).
- `pipelock session list`, `pipelock session inspect` and `pipelock session explain` show which sessions adaptive enforcement escalated and why. `pipelock adaptive status` shows the escalation state. These use the admin API and need the API token, passed with `--api-token` or `PIPELOCK_KILLSWITCH_API_TOKEN`. See [session](../cli/session.md) and [adaptive](../cli/adaptive.md).

## 4. Recover

- Fix the config, then run `pipelock reload`. It reloads the daemon's configured file and reports the activation verdict the daemon actually reached. See [reload](../cli/reload.md).
- `pipelock session recover` walks through one session interactively. `pipelock session release` lowers a session's airlock tier, and `pipelock session terminate` tears a session down. Terminate is destructive. `pipelock adaptive flush` resets adaptive state without a config reload.
- Turn the kill switch off by clearing every source you activated: send `{"active": false}` to the API, send SIGUSR1 again, remove the sentinel file, or set `kill_switch.enabled: false` and reload. Traffic stays denied while any source is still active, so check the status endpoint afterward.

## 5. Roll back Pipelock

- `pipelock update --rollback` restores the previous binary that `pipelock update` saved as `<binary>.bak`. `pipelock update --version vX.Y.Z` downloads and verifies a specific release instead, and aborts without changing the binary if verification fails. See [update](../cli/update.md), including what to do if a rollback stops partway on Windows.
- After a rollback on a contained host, run `sudo pipelock contain verify` and `sudo pipelock contain doctor` to confirm the boundary is installed and usable. See [contain](../contain-cli.md).
- For an Enterprise fleet managed by Conductor, follow [Conductor recovery](../cli/conductor-recovery.md) and the [Conductor operator runbook](conductor-operator-runbook.md). A fleet policy rollback has its own signing and versioning rules.
