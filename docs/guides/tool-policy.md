# Tool-call policy argument sources

Tool-call policy rules can match a tool name and, optionally, strings in its arguments. Use `arg_source: patch_targets` when a rule should inspect the files named by a patch instead of matching text in the patch body.

For example, this rule blocks a patch that targets a shell startup file even when the patch body contains no mention of that file:

```yaml
mcp_tool_policy:
  enabled: true
  action: warn
  rules:
    - name: Block shell startup file edits
      tool_pattern: '^apply_patch$'
      arg_pattern: '\.bashrc$'
      arg_source: patch_targets
      action: block
```

`patch_targets` extracts paths from recognized Git diffs, unified diffs, and `apply_patch` headers. It checks the extracted target paths, so a path mentioned only in patch content does not match this rule. If an argument looks like a patch but Pipelock cannot reliably inspect its targets, the rule is treated as a match and its action applies.

`arg_source` accepts only `patch_targets` and requires `arg_pattern`. Add `arg_key` to scope structured path values alongside the parsed patch targets. Pipelock still inspects patch headers regardless of their argument key; descriptions and replacement content outside matching keys are excluded. Calls without patch headers use the scoped values. If a rule omits `action`, it inherits `mcp_tool_policy.action`.

Built-in credential destination rules cover recognized file writes, edits, moves, copies and patches, including NTFS stream destinations. They inspect target fields and patch headers, preserving each preset's configured credential action. Ordinary `.env` writes and document content that mentions a credential path remain allowed by these rules. Custom tool names, custom credential locations and a remote server's filesystem aliases need operator-specific rules or filesystem containment.

The shipped persistence-path and shell-profile file-write rules distinguish scalar document and replacement text from destinations in recognized file-write/edit calls. A flat argument object must name a nonempty pathname through a recognized target field such as `path`, `file_path`, `target` or `destination`. Scalar `content`, `document`, `body`, `text`, `old_text`, `new_text`, `old_string`, `new_string`, `oldText` and `newText` then count as data for these two rules. Unknown fields, nested objects, arrays and calls without a recognized target retain their existing checks. Custom rules and credential-read rules keep inspecting their configured argument set. Shell tools keep command scanning, including persistence writes through redirection, `tee`, `cp`, `mv`, `install`, `ln`, `sed -i` and `dd of=`.

See the [MCP development listener guide](mcp-inspector-front.md) for a reverse proxy example and the [false-positive tuning guide](false-positive-tuning.md) for DLP warn-mode patterns.

## Shell command text

The shipped destructive-Git and reverse-shell patterns require a command-word start, so names such as `stack::push` and `async` do not match `push` or `nc`. Path-qualified commands remain covered.

On the shell execution hook path, the shipped Destructive Git Operation, Reverse Shell, Destructive File Delete and Recursive Permission Change patterns can exclude fully quoted literal arguments to read-only printing and search commands when the entire script uses the supported read-only command set. Verbatim custom copies of these patterns receive the same treatment. Rules with a different pattern, an `arg_key` or an `arg_source` keep inspecting the original text. Credential rules keep inspecting literal paths. Pipelines, redirections, expansions, functions and unknown commands retain ordinary whole-script matching.

The destructive-Git rule also recognizes literal `git clean -n` and `git clean --dry-run` previews. Every `git clean` occurrence must be a preview, with literal operands and no visible command-resolution override. A literal directory change alone is allowed; dynamic directory targets, modified `PATH`, shell setup files, aliases and Git functions retain conservative matching. These checks inspect submitted command text; they do not establish which executable an inherited environment will run. Generic MCP tool arguments keep their existing text-matching behavior.
