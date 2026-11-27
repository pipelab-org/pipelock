# Incident response and rollback

Use this guide when an agent may have misbehaved through Pipelock or when a Pipelock change needs to be undone. The linked references cover command options and deployment-specific remedies.

Commands assume `pipelock run` unless a step says otherwise. Pipelock only sees traffic routed through it. On supported Linux hosts, configured and verified [host containment](../contain-cli.md) can block direct egress for managed agent workloads.

## 1. Stop agent traffic

The kill switch denies normal traffic while any source is active. Use a source you can reach:

| Source | How to activate | Notes |
|---|---|---|
| API | Send an authenticated `POST /api/v1/killswitch` with JSON `{"active": true}`. See [Kill Switch API](siem-integration.md#kill-switch-api). | Requires a configured bearer token. The API uses the proxy listener unless `kill_switch.api_listen` was set at startup. Restrict a dedicated listener to operators. |
| Signal | On Unix, send `kill -USR1` to the running daemon's PID. | This toggles the signal source. Use it only when you know that source is off. |
| Sentinel file | Create the file named by `kill_switch.sentinel_file`. | Removing the file clears that source. |
| Config | Set `kill_switch.enabled: true` and reload the daemon. | Check that the reload applied the setting. HTTP exemptions still apply. |

Standalone `pipelock mcp proxy` supports the config and sentinel-file sources. Use an already configured sentinel for a running instance. The kill-switch API and SIGUSR1 toggle belong to `pipelock run`. A standalone proxy reads its configuration at startup.

When the API is available, check for HTTP 200 and `active: true` from authenticated `GET /api/v1/killswitch/status`. Its `sources` map reports each source. The POST response reports only the API source. Send the bearer token over a trusted admin connection and load the Authorization header from a protected file, for example with `curl --header @/path/to/admin-headers`. Avoid putting the token in command arguments or shell history.

Check that a harmless request through the affected agent's route is denied by the kill switch. A status response reports the controller's state. HTTP front-door exemptions (`health_exempt`, `api_exempt`, `allowlist_ips`) can still apply. Calls already sent upstream can have effects, and a deferred MCP call that already claimed its upstream send can't be recalled. If you can't confirm the affected path is blocked, or the agent has a direct path, stop or isolate the workload at its supervisor or network boundary. See [Kill Switch](../configuration.md#kill-switch) for the exemption rules and the Conductor-driven sources.

## 2. Preserve evidence

Preserve a restricted copy of the configured flight recorder directory (`flight_recorder.dir`) and audit logs. Use `logging.file` for file output or the service's log collector for stdout. Copy what you can before restarting, rotating or changing the deployment. Record when and where you collected it. If a writer was active during collection, capture the final tail after it stops and treat the earlier copy as potentially incomplete.

- `pipelock evidence doctor DIR` gives investigators a read-only structural check for chain gaps, forked hashes and missing genesis records. Damage or an incomplete scan exits nonzero. A clean report can't establish signer trust or show that every run or restart link was retained.
- `pipelock verify-receipt --chain DIR --session SESSION --key TRUSTED_SIGNER.pub` lets investigators check the selected receipt chain against an independently trusted public key. Select the affected run or session base and supply trusted keys for rotated signers as needed. Exit 3 means the prefix verified and the endpoint remains unproven. Use `--whole-recorder` to verify recorder entries as well as receipts. Even a proven endpoint covers only what was recorded in the selected scope. See [verify-receipt](../cli/verify-receipt.md) and [Receipt verification](receipt-verification.md).
- `pipelock support bundle --config CONFIG` writes a redacted diagnostics archive for support. It includes a configuration summary and may include a redacted audit-log tail. Keep the original recorder data and logs separately, and review the bundle before sharing it. See [support bundle](../cli/support.md).

## 3. Find out what happened

- `pipelock logs --file AUDIT_LOG --filter blocked` finds blocked entries in a JSONL audit log. For a historical request ID, use `pipelock explain event REQUEST_ID --config CONFIG --log AUDIT_LOG` to read the recorded outcome. A missing terminal event can leave the outcome unknown.
- `pipelock explain --config CONFIG URL` evaluates the URL against the offline scanning layers using the supplied config. It doesn't fetch the URL, resolve DNS or reproduce the historical decision. Without `--config` it uses built-in defaults. See [explain](../cli/explain.md).
- `pipelock session list`, `pipelock session inspect KEY` and `pipelock session explain KEY` let the operator inspect current session enforcement and its recorded reasons. `pipelock adaptive status` shows current escalation state and requires session profiling. These use the authenticated admin API. Resolve its URL and token using protected configuration or the environment. See [session](../cli/session.md) and [adaptive](../cli/adaptive.md).

## 4. Recover

- Fix the daemon's configured file, then use the authenticated `pipelock reload` command to check its activation verdict. A restart-required verdict can leave some changes pending. If the connection fails or the request is cancelled, query `pipelock reload --status` before retrying. See [reload](../cli/reload.md).
- Use [session recovery](../cli/session.md#typical-airlock-recovery-workflow) to repair one session. `pipelock session recover KEY` walks through inspection and an action. Use `reset` when a destination score or `block_all` is still denying traffic, and `release` to lower the airlock tier. `terminate` cuts the session's in-flight connections and resets enforcement state. Preserve diagnostics before clearing state. `pipelock adaptive flush` resets shared burst tracking and adaptive state across identity sessions, skipping ephemeral MCP invocation sessions.

## 5. Roll back Pipelock

- Keep affected workloads stopped or independently isolated during a restart. The API and signal sources belong to the old process. Ensure the replacement starts with the intended config and any kill source you still need.
- `pipelock update --rollback` restores the local `<binary>.bak`. Use it only if you trust that backup. `pipelock update --version vX.Y.Z` verifies a downloaded release before replacement. See [update](../cli/update.md) for backup rotation and Windows recovery. Check the deployed executable's `--version`, restart the service that uses it, and check the running instance before resuming workloads. The version line identifies the executable and doesn't authenticate it.
- For a contain-managed host, follow [contain upgrade](../contain-cli.md#pipelock-contain-upgrade) to install a verified release and reconcile the integrity pin, or follow the documented `contain install --pipelock-binary` path for an independently verified local binary. [Contain rollback](../contain-cli.md#pipelock-contain-rollback) removes the installed containment controls. Preserve evidence and keep workloads isolated before using it to undo a containment install.
- For an Enterprise fleet managed by Conductor, follow [Conductor recovery](../cli/conductor-recovery.md) and the [Conductor operator runbook](conductor-operator-runbook.md#recovery-operations). A fleet policy rollback has its own signing and versioning rules.

## 6. Resume traffic

While the affected workloads are stopped or independently isolated, clear only the kill sources you intended to release. Send `{"active": false}` to clear the API source, send SIGUSR1 only if the signal source is active, remove the sentinel file to clear that source, or apply `kill_switch.enabled: false` by reload or standalone proxy restart. Check the status endpoint where available. An active source keeps the switch engaged.

On a contain-managed host, run `sudo pipelock contain verify` and `sudo pipelock contain doctor` with the deployed port to check the boundary and the live runtime. Doctor needs to exercise traffic through the proxy. Keep workloads isolated if verification fails or is incomplete. Before resuming workloads, confirm expected behavior with harmless allowed and denied requests through the affected path.
