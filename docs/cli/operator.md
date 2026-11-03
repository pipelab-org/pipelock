# Operator convenience commands

These commands are read-only and are meant for setup, triage, and local
inspection. They do not contact a running proxy unless their help text says so,
and they do not mutate runtime state.

## `pipelock quickstart`

Prints a concrete getting-started walkthrough using shipped commands:

```bash
pipelock quickstart
```

Use this when an operator has installed the binary and wants the shortest path
from no config to a local smoke test.

## `pipelock status`

Loads the effective local config and prints mode, listeners, scanner switches,
license state, and kill-switch sources. It stats a configured kill-switch
sentinel file so the report reflects that source, but it does not change the
sentinel, contact the proxy, or reload anything.

```bash
pipelock status --config /etc/pipelock/pipelock.yaml
pipelock status --config /etc/pipelock/pipelock.yaml --json
```

The JSON form shows local config and scanner settings. Its ordinary URL and DLP action labels report `warn` for `mode: audit` even when `enforce` is `true`. Check the top-level `enforce` value. `mode: audit` alone still blocks ordinary URL findings. Use the [audit preset](../configuration.md#presets) for an observation trial; independent safety controls can still block.

## `pipelock presets`

Lists every built-in config preset accepted by
`pipelock generate config --preset NAME`, including mode, default action, and
reachability posture.

```bash
pipelock presets
pipelock generate config --list
pipelock generate config --preset balanced > pipelock.yaml
```

Use `pipelock presets` before choosing a preset for a new deployment; use
`generate config --list` when you are already in the config-generation flow.
