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

## Consumer migration

Automation that previously accepted a wrapped configuration as protected must handle `servers[].protection_state: "unconfirmed"` and `summary.unconfirmed`. Read the per-entry `evidence` explanation; don't add unconfirmed entries to `protected_pipelock` or `protected_other`. A run containing only wrappers now exits `1`, including with `--json` or `--generate`; the JSON inventory is still emitted. Adding another wrapper won't change that outcome because file-only discovery can't establish what launched.

`pipelock assess` collects discovery directly and gives each unconfirmed entry 50% MCP Protection credit, the same as `unknown`, instead of the 100% credit previously given to protected entries. It adds a finding asking the operator to verify effective launch settings. The MCP section score and weighted overall score can drop even when the configuration files haven't changed. Assessment JSON retains the new status and summary count; see [assessment scoring impact](../compliance/assess-mapping.md#discovery-and-assessment-scoring).

Signed posture capsules retain their existing schema and count unconfirmed entries as `unknown`. Current file-only collection can't satisfy strict, including an empty inventory, and a nonempty inventory's best-case score is 62 against the default minimum of 85. Older signed capsules aren't reclassified at verification time. See [posture verification migration](../guides/posture-capsule.md#file-only-collection-limits) for the arithmetic and CI impact. Launch-evidence confirmation is planned.

## Project coverage

Codex project views apply checked `.codex/config.toml` layers over the user file, from the Git root to the requested working directory. Registered trusted project directories are also checked. Trust is evaluated for each layer: only a known `trust_level = "trusted"` permits reading it. A trusted repository layer still applies when a child directory is explicitly untrusted; the child layer is skipped. A trusted child can also contribute over an untrusted root. A requested project directory that is missing, unreadable, or not absolute is reported as an error, as is an unreadable or malformed applicable file. A registered trusted directory that no longer exists, such as a deleted clone or worktree, is skipped: no client can start in it, so it has no layers to check. The root walk uses `.git` marker presence; it doesn't validate Git metadata or resolve custom project-root markers. Profiles, CLI overrides, plugins, system/cloud settings, and requirements are not resolved, so a wrapper remains unconfirmed. Sources: [Codex configuration precedence](https://developers.openai.com/codex/config-basic/#configuration-precedence) and [project trust configuration](https://developers.openai.com/codex/config-reference/). Partial field inheritance was also reproduced with `codex-cli 0.162.0` using `codex mcp list --json` in a trusted fixture project.

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
