# pipelock discover

`pipelock discover` inventories known MCP client configuration files. It reports configured commands and URLs without starting clients or MCP servers.

```bash
pipelock discover
pipelock discover --json
pipelock discover --generate
pipelock discover --home /home/example --project /home/example/project
```

`--home` selects a home directory and suppresses ambient configuration-directory overrides and implicit current-directory discovery. `--project` is repeatable and requires an absolute directory. Without `--home`, the current directory is included. Registered trusted Codex projects are checked even without `--project`. Discovery does not recursively search the filesystem for projects.

| Status | Meaning |
| --- | --- |
| `unprotected` | The checked command or URL is not a verified wrapper. |
| `unconfirmed` | A wrapper was found in the checked files, but discovery cannot verify that the client actually launches it. |
| `unknown` | The entry has neither a command nor a URL. |
| `protected_pipelock`, `protected_other` | Reserved for confirmed protection evidence. File-only discovery does not emit these statuses. |

Some entries previously reported as protected now report **unconfirmed**. This corrects the scope of the evidence: a wrapped home-level definition can differ from the server a client launches. Human output explains the limitation for each wrapped entry. JSON uses `protection_state: "unconfirmed"`, an `evidence` explanation, and the `summary.unconfirmed` count. Unconfirmed entries are excluded from protected counts. Assessment retains the status, gives it the same partial credit as `unknown`, and includes a finding asking for verification of the effective launch settings. Signed posture capsules include these entries in their existing `unknown` count, which reduces discovery cleanliness and fails strict policy.

`--generate` suggests wrappers for unprotected entries. For unconfirmed entries, it explains that adding another wrapper cannot confirm the launch. It does not nest another wrapper around an existing one. Codex entries marked `enabled = false` remain listed and counted because another configuration layer can enable them.

`pipelock init` also shows unconfirmed discovery counts in its human and JSON summaries. Its exit status still describes the local setup checks; it does not verify client routing.

## Project coverage

Codex project views apply checked `.codex/config.toml` layers over the user file, from the Git root to the requested working directory. Registered trusted project directories are also checked. Trust is evaluated for each layer: only a known `trust_level = "trusted"` permits reading it. A trusted repository layer still applies when a child directory is explicitly untrusted; the child layer is skipped. A trusted child can also contribute over an untrusted root. Missing or unreadable project directories and malformed applicable files are reported as errors. The root walk uses `.git` marker presence; it doesn't validate Git metadata or resolve custom project-root markers. Profiles, CLI overrides, plugins, system/cloud settings, and requirements are not resolved, so a wrapper remains unconfirmed. Sources: [Codex configuration precedence](https://developers.openai.com/codex/config-basic/#configuration-precedence) and [project trust configuration](https://developers.openai.com/codex/config-reference/). Partial field inheritance was also reproduced with `codex-cli 0.162.0` using `codex mcp list --json` in a trusted fixture project.

Grok project views read `.grok/config.toml` from the Git root to the requested directory. A nearer definition replaces the entire same-name server, including command, arguments, and environment. Outside a Git checkout, only the requested directory is checked. Plugins, compatibility sources, environment expansion, managed settings, and launch overrides are not resolved. Source: [Grok MCP project scope](https://docs.x.ai/build/features/mcp-servers#project-scope).

The user-file inventory and each project view are separate entries, distinguished by `project_path`. Counts describe inventory entries across those views, not unique running processes. A project parse error prevents emission of a partial project view; it does not make the retained user-file view confirmed.

Claude Code project `.mcp.json`, Cursor project `.cursor/mcp.json`, and VS Code workspace `.vscode/mcp.json` files are not read. Their wrapped entries are unconfirmed. Sources: [Claude Code MCP scopes](https://code.claude.com/docs/en/mcp), [Cursor MCP configuration](https://cursor.com/docs/context/mcp), and [VS Code MCP configuration](https://code.visualstudio.com/docs/copilot/customization/mcp-servers).

For other clients, discovery cannot verify every launch source or the client's execution context. Their wrapped entries also remain unconfirmed; this does not assert that any particular override is active.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No servers found, or every server has confirmed protection evidence. |
| 1 | At least one unprotected, unconfirmed, unknown, or unparseable entry. |
| 2 | Usage or runtime error. |

Unconfirmed uses exit 1, like unknown: neither establishes protection. This applies to human output, `--json`, and `--generate`.
