# Pipelock plugin for Hermes Agent

Installed by `pipelock hermes install`. Registers five hooks:

| Hook | Purpose |
|------|---------|
| `pre_tool_call` | DLP + prompt-injection scan on tool arguments; can block |
| `transform_tool_result` | DLP + response-injection scan on tool output; masks eligible AWS spans or blocks |
| `pre_gateway_dispatch` | DLP + injection scan on inbound messaging-gateway text |
| `on_session_start` | Observer — surfaces session start to the pipelock audit channel |
| `on_session_end` | Observer — surfaces session end + completion flags |

## Wire protocol

Each hook subprocess-execs `pipelock hermes hook` with the same JSON-over-
stdin/stdout schema Hermes uses for its native shell hooks. The command loads
pipelock's scanner configuration, runs the relevant scan pipeline, and emits
one of these objects on stdout:

- `{}`: allow the original input.
- `{"decision":"block","reason":"..."}`: replace a tool result with a block
  notice, or skip gateway dispatch.
- `{"decision":"transform","result":"<masked string>","reason":"..."}`:
  return the replacement string from `transform_tool_result`, or return
  `{"action":"rewrite","text":"<masked string>"}` from `pre_gateway_dispatch`.

The plugin sends `capabilities: ["transform"]` only for inbound string results
and gateway text. Gateway `tool_input` is `{"text": "<message>", "sender": "<sender>"}`,
which is the envelope every pipelock release scans. A sender copy under
`extra.sender`, if a caller also sends one, is scanned block-only and is never
masked. Structured tool results don't advertise the capability.
The hook never emits a transform without it. `result` and a nonempty `reason`
must be strings; malformed transforms and unknown decisions block/skip instead
of returning `None`. `{}` and explicit `{"decision":"allow"}` remain accepted.

Only plain `AWS Access ID` spans with identity DLP normalization are eligible.
The placeholder is `[pipelock:masked:aws-access-id]`. The hook re-scans the entire
replacement; remaining DLP/injection findings, errors, or incomplete inspection
block delivery. Other credential patterns and structured results retain their
block policy. The reason and stderr identify masked findings without their bytes.
Older plugins advertise no capability, so the hook keeps blocking for them.

Fail-closed: timeout, missing binary, malformed response, empty stdout,
non-zero exit, or stdin larger than the 4 MiB payload cap all become block
decisions. This matches pipelock's invariant that ambiguity must not unblock
the agent.

## Config resolution

The hook uses, in order: the `pipelock.conf` sidecar written next to this
module by `pipelock hermes install`, then `PIPELOCK_HERMES_HOOK_CONFIG`, then
pipelock's built-in defaults. The sidecar is the reliable path because it does
not depend on Hermes' runtime environment.

## Environment overrides

- `PIPELOCK_BIN` — full path to the `pipelock` binary. Required if `pipelock`
  is not on `PATH`.
- `PIPELOCK_HERMES_HOOK_CONFIG` — pipelock config file path, used when no
  `pipelock.conf` sidecar is present.

## Reinstalling

Re-run `pipelock hermes install`. The installer is idempotent: existing files
are rotated to `.bak` before being overwritten.
