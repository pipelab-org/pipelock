# Securing OpenAI Codex with Pipelock

Codex is the coding agent you hand a real repository. It can review PRs,
trace large codebases, research dependencies, and operate MCP tools. That
means it sees secrets, calls tools, and follows links in untrusted content.

Pipelock sits between Codex and those surfaces when MCP servers are wrapped
and HTTP clients are routed through the proxy. It scans mediated outbound
requests, inbound content, and tool traffic before anything reaches the model
or leaves your machine.

## Why Codex Needs an Agent Firewall

Codex workflows touch high-value targets:

| Workflow | What Codex accesses | What could go wrong |
|----------|--------------------|--------------------|
| PR review | Source code, diffs, commit messages | Secrets in diffs exfiltrated via tool calls |
| Large codebase tracing | Full repo access, dependency trees | Prompt injection in docs, READMEs, or issue templates |
| Web research | URLs, documentation pages, API docs | Injected instructions in fetched content |
| MCP tool use | External tools, databases, APIs | Tool poisoning, rug-pull attacks, data exfiltration via arguments |
| Shell commands | System access within sandbox | Shell obfuscation, persistence attempts |

Codex has its own sandbox (bubblewrap on Linux, Seatbelt on macOS) that
restricts filesystem and process access. Pipelock adds the layer Codex's
sandbox doesn't cover: **content inspection on egress and ingress.** A
sandboxed agent can still send credentials through an allowed HTTPS
connection.

## Quick Start

```bash
# 1. Install pipelock (requires Go 1.26+)
git clone --branch v3.7.0 --depth 1 https://github.com/pipelab-org/pipelock.git
make -C pipelock install
# or (macOS): brew install luckyPipewrench/tap/pipelock

# 2. Generate a config before installing wrappers
pipelock generate config --preset balanced -o pipelock.yaml

# 3. Preview, then wrap every registered Codex MCP server
pipelock codex install --config "$PWD/pipelock.yaml" --dry-run
pipelock codex install --config "$PWD/pipelock.yaml"

# 4. Restart Codex, then inspect the registered MCP servers
codex mcp list

# 5. Run an assessment before first use
pipelock assess init --config pipelock.yaml
pipelock assess run assessment-*/
pipelock assess finalize assessment-*/
```

`pipelock codex install` discovers Codex's MCP server entries in `~/.codex/config.toml`, rewrites each one to launch through `pipelock mcp proxy`, and is idempotent — re-running it on an already-installed setup is a no-op. Add or remove an MCP server via `codex mcp add/remove` as usual, then re-run `pipelock codex install` to wrap any new entries.

The installer registers stdio environment variables by name in Codex's `mcp_servers.<name>.env_vars` list and forwards those names with Pipelock's `--env KEY`. Export each variable in the environment running setup and Codex. For an existing literal `env` entry, the exported value must match the configured value; otherwise installation refuses that server before changing it. This applies to ordinary settings as well as credentials. Removal and rollback also use names only. A server whose `env_vars` list has any entry other than a name or `{ name = "...", source = "local" }`, such as a remote source or an object without a source, is left unchanged: installation skips it with a reason and removal refuses it when it is wrapped, so wrap or unwrap that server in `config.toml` by hand. Environment values are never passed to `codex mcp add`. When Codex is launched from an IDE, desktop launcher or systemd, put those names and their values in that launcher's environment using its profile or an EnvironmentFile. Load values from a secret store or file rather than typing them on a command line, where shell history can retain them.

The name-only list is defined in the [Codex configuration reference](https://developers.openai.com/codex/config-reference/). The installer updates `config.toml` atomically with private file permissions (`0600` on Unix). Updating a whitelist preserves unrelated TOML settings but normalizes formatting and removes comments. `CODEX_HOME` selects the Codex configuration directory when set.

Run `pipelock discover` to inventory the MCP entries in that TOML file and see which configured commands are wrapped. With `--home`, it reads `.codex/config.toml` under the selected home directory. When `CODEX_HOME` is set, Codex keeps its servers in `$CODEX_HOME/config.toml`, and `discover` reads that file too, unless `--home` is given. Entries with `enabled = false` are still listed and counted: Codex merges config layers, so a trusted project's `.codex/config.toml` setting `enabled = true`, or a `-c mcp_servers.<name>.enabled=true` override, starts them again. `pipelock codex install` skips disabled entries, so wrap one by hand from `pipelock discover --generate` or remove it. Discovery reads `.codex/config.toml` for registered trusted projects and applies those fields over the user configuration. Untrusted project files are ignored. Use `--project /absolute/project/path` for a specific working directory, including nested project layers. Project views carry `project_path`; the user-file view remains listed for launches elsewhere. Profiles, plugins, managed settings, and CLI overrides are not resolved. Wrapped entries are **unconfirmed**, because finding a wrapper in these files cannot establish what a client launches. See [discovery coverage](../cli/discover.md).

The installer validates and embeds an absolute Pipelock config path when you pass
`--config`, or when a secure config is discovered through `PIPELOCK_CONFIG`,
`$XDG_CONFIG_HOME/pipelock/pipelock.yaml`, `~/.config/pipelock/pipelock.yaml`,
or `/etc/pipelock/pipelock.yaml`. It prints the selected config source during
install so the wrapped MCP servers do not depend on Codex's later working
directory.

Restart Codex after an install or removal and confirm the expected server in
`codex mcp list`; then run a harmless tool action. A registered server is not
evidence that the client successfully connected to it.

For manual / per-server control, the original pattern still works:

```bash
codex mcp add my-server \
  -- pipelock mcp proxy --config pipelock.yaml \
  -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

## MCP Proxy Mode

Codex supports MCP servers via `codex mcp add`. Pipelock wraps any MCP
server as a stdio proxy with bidirectional scanning:

```text
Codex  <-->  pipelock mcp proxy  <-->  MCP Server
(agent)      (scan both ways)          (subprocess)
```

### Adding a Wrapped MCP Server

```bash
# Wrap a filesystem server
codex mcp add filesystem \
  -- pipelock mcp proxy --config pipelock.yaml \
  -- npx -y @modelcontextprotocol/server-filesystem ~/projects

# Wrap a database server
codex mcp add postgres \
  -- pipelock mcp proxy --config pipelock.yaml \
  -- npx -y @modelcontextprotocol/server-postgres postgresql://localhost/mydb

# Wrap a remote MCP server (Streamable HTTP)
codex mcp add remote-tools \
  -- pipelock mcp proxy --config pipelock.yaml \
  --upstream http://localhost:8080/mcp
```

### Or Edit the Config Directly

Codex stores MCP server config in `~/.codex/config.toml`:

```toml
[mcp_servers.filesystem]
command = "pipelock"
args = [
  "mcp", "proxy",
  "--config", "/home/you/pipelock.yaml",
  "--",
  "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/you/projects"
]
```

### What Gets Scanned

| Direction | What | Scanning |
|-----------|------|----------|
| Codex → MCP server | Tool call arguments | DLP (secrets, credentials, env vars), injection patterns |
| MCP server → Codex | Tool results, descriptions | Prompt injection (6-pass normalization) |
| Tool definitions | `tools/list` responses | Poisoned descriptions, schema injection, rug-pull detection |
| Tool sequences | Multi-call patterns | Chain detection (read-then-exfil, persist-then-callback) |

## Forward Proxy Mode

For outbound HTTP requests Codex makes through shell commands (curl, wget,
fetch), run pipelock as a forward proxy:

```bash
# Start the proxy
pipelock run --config pipelock.yaml &

# Set the proxy for Codex sessions
export HTTPS_PROXY=http://127.0.0.1:8888
export HTTP_PROXY=http://127.0.0.1:8888
export NO_PROXY=127.0.0.1,localhost
```

This scans outbound HTTP traffic that honors the proxy settings for DLP,
SSRF, and URL-based exfiltration. Response content is scanned for prompt
injection before reaching the agent. Use `pipelock contain`, sandboxing, or
another network boundary for tools that ignore proxy environment variables or
open raw sockets directly.

## Running an Assessment First

Before giving Codex access to a real repository, run an assessment.
Think of it as a background check before the agent starts work.

```bash
# Initialize an assessment session
pipelock assess init --config pipelock.yaml

# Run attack simulations
pipelock assess run assessment-*/

# Generate a signed report
pipelock assess finalize assessment-*/
```

The report returns a recommendation:
- **Approve**: config is solid, proceed
- **Approve with constraints**: tighten specific settings before production
- **Probation**: significant gaps found, monitor closely
- **Do not approve**: critical issues, do not use this config with real repos

Re-run after major changes: new model, new MCP tools, new repository,
updated config.

## Codex + Pipelock Sandbox

Both Codex and Pipelock have sandboxing. They work at different layers:

| Layer | Codex sandbox | Pipelock sandbox |
|-------|--------------|-----------------|
| Filesystem | bubblewrap/Seatbelt restricts paths | Landlock restricts paths, and seccomp filters syscalls on linux/amd64 |
| Network | Sandbox mode controls network access | Network namespace isolates + proxy inspects traffic |
| Process | Restricted by sandbox policy | Subreaper for descendant cleanup, plus seccomp on linux/amd64 |

For maximum containment, use both:

```bash
# Codex sandbox + pipelock sandbox on MCP server
pipelock generate config --preset strict -o pipelock-strict.yaml
codex mcp add secure-filesystem \
  -- pipelock mcp proxy --config pipelock-strict.yaml --sandbox \
  -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

## Choosing a Config

A preset is chosen when the config is generated, with `pipelock generate config
--preset <name> -o pipelock.yaml`, and the file it writes is what `--config`
takes. Run `pipelock presets` to list them.

| Preset | Action | Best For |
|--------|--------|----------|
| `balanced` | warn | Getting started, tuning phase |
| `claude-code` | block | Unattended Codex sessions (works for Codex too) |
| `strict` | block | High-security repos, sensitive code |
| `hostile-model` | block | If using uncensored models via Codex |

Start with `balanced` to see what gets flagged. Switch to
`claude-code` or `strict` once you've verified no false positives.

## Evidence and Audit Trail

Every scanning decision is logged. For Codex workflows that touch
sensitive repos, enable the flight recorder:

```yaml
flight_recorder:
  enabled: true
  dir: /tmp/pipelock-codex-evidence
  sign_checkpoints: true
  signing_key_path: /etc/pipelock/keys/flight-recorder-signing.key   # `pipelock init` writes this next to your config
  redact: true
```

This produces a hash-chained JSONL evidence log with signed checkpoints
and DLP-redacted content. Hand it to your security team as proof of what
the agent did and didn't access.

## Troubleshooting

### MCP server not starting under Codex

Verify the command works without Codex first:

```bash
# Test the MCP server directly
pipelock mcp proxy --config pipelock.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Then add to Codex
codex mcp add test-fs -- pipelock mcp proxy --config pipelock.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

### Environment variables not passing through

Codex's `mcp add --env` takes `KEY=VALUE`, which exposes the value to process-command-line readers. Use the `env_vars` whitelist in `config.toml` instead, and export the variables before starting Codex. For example, this entry inherits `API_KEY` into the wrapper and forwards it by name to the MCP child:

```toml
[mcp_servers.my-server]
command = "pipelock"
args = ["mcp", "proxy", "--config", "/home/you/pipelock.yaml", "--env", "API_KEY", "--", "my-mcp-server"]
env_vars = ["API_KEY"]
```

`pipelock codex install` creates the whitelist when wrapping an existing stdio server. If a literal value exists only in the server's `env` table, export that value in the environment running setup and Codex before retrying.

Pipelock refuses requests to pass code-loading and other blocked names into the child at startup. Setting them on the wrapper doesn't pass them into its filtered child environment. Proxy variables supplied to the wrapper aren't inherited by the MCP child. See [child environment restrictions](sandbox.md#child-environment-restrictions) for the shared list and supported operator choices.

### Checking what Codex MCP servers are configured

```bash
codex mcp list
```

### Previewing, removing, and recovering wrappers

```bash
# Preview without changing Codex configuration.
pipelock codex install --config "$PWD/pipelock.yaml" --dry-run

# Restore only MCP servers previously wrapped by Pipelock.
pipelock codex remove --dry-run
pipelock codex remove
```

Re-running install after upgrading Pipelock also recovers and re-wraps an older Pipelock-authored registration using the current binary's invocation shape; a registration it cannot safely normalize is refused with a message naming it, and nothing is changed.

The installer replaces each server registration and attempts to restore the
previous registration if that replacement fails. If it reports that rollback
also failed, stop and inspect `codex mcp list` before retrying or editing the
server. The remove command leaves registrations it does not recognize as
Pipelock wrappers unchanged.

### False positives

If legitimate tool responses are blocked, start with `warn` mode:

```yaml
response_scanning:
  action: warn
```

Check pipelock stderr for detection logs, then adjust patterns.
