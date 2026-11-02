# Finding Suppression Guide

Pipelock has three layers for suppressing false positives, from most precise to broadest:

1. **Inline comments:** suppress one rule on one line
2. **Config suppress entries:** suppress a rule across matching paths
3. **`--exclude` flag:** remove entire paths from results

All three work in `pipelock audit`, `pipelock git scan-diff`, and the GitHub Action.

## Layer 1: Inline Comments

Add `// pipelock:ignore` to a source line to suppress non-core findings on that line. Core DLP and core response floor patterns cannot be suppressed. They remain findings even with a bare marker or a marker naming the rule, matching the config suppression policy.

`git scan-diff` applies the core DLP floor even with `dlp.include_defaults: false` or a custom pattern replacing a built-in name. This includes the core-only GCP service-account marker, which can also occur in documentation and fixtures without a private key. There is no per-rule or per-line exception for a core finding. Construct synthetic test values from fragments when possible. For files that must retain a literal example, the path exclusions below remove every finding for that path, including core findings. Generated pre-push hooks don't expose an exclusion option.

```go
// Suppress a specific rule:
url := buildTestURL("token", testToken) // pipelock:ignore Credential in URL

// Suppress all non-core rules on this line (use sparingly):
testValue := loadFixture("fake-key.txt") // pipelock:ignore
```

**Supported comment styles:**

| Language | Syntax |
|----------|--------|
| Go, JS, TS, Java, C | `// pipelock:ignore [RuleName]` |
| Python, YAML, Bash | `# pipelock:ignore [RuleName]` |

Rule names are case-insensitive. `pipelock:ignore credential in url` works.

**When to use:** Test files with fake credentials, documentation examples with placeholder tokens, assignments that look like credentials but aren't.

## Layer 2: Config Suppress Entries

Add `suppress` entries to your pipelock config file to silence findings across file paths:

Config suppression applies only to non-core rules. Pipelock rejects core DLP and core response floor names at startup and reload because those minimum protections cannot be removed by config. A core response finding on one host can instead be observed, not blocked, with `response_scanning.core_observe_exceptions`; see [configuration.md](../configuration.md).

```yaml
suppress:
  - rule: "Credential in URL"
    path: "docs/"
    reason: "Documentation examples use placeholder tokens"

  - rule: "Social Security Number"
    path: "test/fixtures/*.csv"
    reason: "Test data with synthetic SSNs"

  - rule: "JWT Token"
    path: "*.test.ts"
    reason: "Test JWTs with no real claims"

  - rule: "Jailbreak Attempt"
    path: "*/robots.txt"
    reason: "robots.txt content triggers developer mode regex"
```

**Path matching supports five styles:**

| Style | Example | Matches |
|-------|---------|---------|
| Exact path | `app/config.go` | Only that file |
| Directory prefix | `vendor/` | All files under `vendor/` |
| Full path glob | `config/initializers/*.rb` | `config/initializers/auth.rb` |
| Basename glob | `*.generated.go` | `pkg/api/types.generated.go` |
| URL suffix | `robots.txt` | `https://example.com/robots.txt` |

A complete URL without glob characters matches that URL, with standard-port normalization. To match a URL prefix, end the entry with `/` or use an explicit wildcard. Scheme-qualified entries aren't URL path suffixes; the suffix form uses a path tail such as `robots.txt`.

The characters `*`, `?`, and `[` introduce glob matching, including in query strings. Write `[?]` for a literal `?` and `[[]` for a literal `[`: for example, `https://api.vendor.example/token[?]mode=refresh` matches `https://api.vendor.example/token?mode=refresh`. Backslashes are normalized to `/`, so they can't escape glob characters. Globs first use Go's [`path.Match`](https://pkg.go.dev/path#Match), where `*` stops at `/`. URL patterns also have a fallback where `*` crosses `/`, but the pieces between stars are literal: that fallback doesn't interpret `?` or character classes such as `[?]`. When a query-specific entry needs to cover several path segments, list each complete URL with `[?]` instead of combining a separator-crossing `*` with a character class.

**Upgrade note:** Review URL suppress entries that previously matched more than the written URL. Those additional findings are no longer suppressed by a literal entry. For an intentional prefix, use a trailing `/` or an explicit `*` after checking the resulting scope. Plain path tails such as `robots.txt` retain suffix matching.

The `reason` field is optional but recommended. It appears in audit logs and helps future maintainers understand why the suppression exists.

**When to use:** Directories with known false positives, third-party code, generated files, documentation directories.

### Custom Provider Keys

Some providers use bare high-entropy strings or undocumented key shapes. Pipelock does not ship generic entropy-as-secret DLP because it would block legitimate IDs, digests, and session values. If you know a provider key shape in your environment, add a named DLP pattern and bind that same rule to the provider's host:

```yaml
dlp:
  patterns:
    - name: "Internal Provider API Key"
      regex: '\bintprov_[A-Za-z0-9_-]{32,}\b'
      severity: critical
      exempt_domains:
        - "api.provider.example"

suppress:
  - rule: "Internal Provider API Key"
    path: "https://api.provider.example/*"
    reason: "provider-bound credential"
```

Use both knobs. `exempt_domains` keeps URL DLP from blocking a provider-bound key on the provider's own host. `suppress` silences the same rule for request bodies and headers on the provider endpoint. The key still blocks when it is sent anywhere else.

### An exact token route

A body or header block can report a credential audience mismatch: the matched rule has a declared audience, and the request's canonical destination is outside it. The diagnostic names the pattern, scanned surface, destination host and built-in audience hosts, without including the credential. An absent mismatch explanation does not mean a request is safe; a carrier restriction, core rule or incomplete scan can still block it. `pipelock explain` evaluates URL scanning, not request bodies or headers.

Audience diagnostics show the canonical destination and public built-in audience hosts; they omit operator-declared audience hosts. A diagnostic marked `immutable core rule` cannot be cleared with `suppress`. Core protection still applies even if a configurable rule has the same name.

For GitHub Enterprise or a self-managed GitLab instance, review [`dlp.github_enterprise_hosts` or `dlp.gitlab_hosts`](../configuration.md#per-pattern-domain-exemptions). These lists trust exact hosts with credentials on eligible headers only; declare only instances your organization operates. They don't clear body or URL findings or remove carrier restrictions.

If investigation confirms a legitimate token exchange, an operator can suppress the specific non-core rule at an exact URL. Replace the neutral example URL with the verified endpoint and use the rule name from the diagnostic:

```yaml
suppress:
  - rule: Anthropic API Key
    path: https://api.vendor.example/v1/oauth/token
    reason: Operator-approved token route
```

This applies to that rule in request bodies and scanned headers at the route for forwarded, TLS-intercepted and reverse-proxy requests. It cannot suppress a CONNECT outer-header finding: that scan uses the tunnel authority URL, which has no inner request path. It is route-wide: the matching credential shape is suppressed in any body field or scanned header, not just a `refresh_token` field. Other DLP rules and core protections still apply. URL DLP does not consult `suppress`, so putting the credential in the URL query still blocks.

Reverse-proxy URL text scanning also does not consult per-pattern `exempt_domains`. Remove credentials from the request URL rather than applying body or header remedies to that finding.

The exact entry does not cover another route, a query-bearing target, a lookalike host or port 8443. Explicit port 443 and an omitted HTTPS port are equivalent. A trailing slash makes the entry a prefix, and a glob broadens it, including across slashes and query strings; keep the complete exact URL when that is the intended scope. Test the normal request and these negative cases before applying the entry. Keep its reason and remove it when it is no longer needed.

This does not add a refresh-token allowance or change the built-in audience. Avoid using `passthrough_domains` for this remedy: TLS passthrough removes inspection of inner requests and responses, far beyond one pattern at one route.

## Layer 3: `--exclude` Flag

Remove entire paths from scan results. Available on `pipelock git scan-diff` and `pipelock audit`:

These exclusions also remove core findings. Use the narrowest path possible: an excluded fixture can contain a real secret that the gate will no longer report. The GitHub Action exposes the same control through `exclude-paths`.

```bash
pipelock git scan-diff --exclude vendor/ --exclude "*.generated.go"
pipelock audit --exclude node_modules/ --exclude dist/
```

Path patterns use the same matching rules as config suppress entries (exact, directory prefix, glob, basename glob).

**When to use:** Third-party code, build artifacts, generated files, and anything else you don't control.

## GitHub Action

These examples target v3.8.0 after publication. The commit pin selects action source; the `version` input selects the binary.

### Exclude paths

Use the `exclude-paths` input (one pattern per line):

```yaml
- uses: pipelab-org/pipelock@3b5140812d6c37a52a22b66af1daf92759c280ab # v3.8.0 examples; source snapshot, not release tag
  with:
    version: '3.8.0'
    exclude-paths: |
      vendor/
      *.generated.go
      node_modules/
```

### Config-level suppression

Write a Pipelock config file, then pass its path with the `config` input:

```yaml
- name: Write Pipelock config
  run: |
    cat > pipelock-ci.yaml <<'EOF'
    suppress:
      - rule: "Credential in URL"
        path: "docs/"
        reason: "Documentation examples"
      - rule: "JWT Token"
        path: "test/"
        reason: "Test tokens"
    EOF

- uses: pipelab-org/pipelock@3b5140812d6c37a52a22b66af1daf92759c280ab # v3.8.0 examples; source snapshot, not release tag
  with:
    version: '3.8.0'
    config: pipelock-ci.yaml
```

### Inline comments

Inline `// pipelock:ignore` comments work automatically for non-core findings with no action config needed. Core floor findings remain in the results.

## Available Rule Names

### DLP (Secret Detection)

| Rule Name | What It Detects | Severity |
|-----------|----------------|----------|
| Anthropic API Key | `sk-ant-*` with 20+ token chars | critical |
| OpenAI API Key | `sk-proj-*` with 20+ token chars | critical |
| OpenAI Service Key | `sk-svcacct-*` with 20+ token chars | critical |
| Fireworks API Key | `fw_*` | critical |
| LLM Router API Key | `sk-or-v1-*` with 20+ hex chars | critical |
| Answer Engine API Key | `pplx-*` with 20+ token chars | critical |
| Web Research API Key | `tvly-*` with 20+ token chars | critical |
| Google API Key | `AIza*` | high |
| Google OAuth Client Secret | `GOCSPX-*` | critical |
| Google OAuth Token | `ya29.*` | critical |
| Google OAuth Client ID | `*.apps.googleusercontent.com` | medium |
| Stripe Key | `sk_live_*` / `rk_live_*` | critical |
| GitHub Token | `ghp_` / `ghs_` / `gho_` / `ghu_` / `ghr_` | critical |
| GitHub Fine-Grained PAT | `github_pat_*` | critical |
| AWS Access ID | `AKIA*` / `ASIA*` / `AROA*` + 6 more prefixes | critical |
| Slack Token | `xox[bpras]-*` | critical |
| Slack App Token | `xapp-*` | critical |
| Discord Bot Token | `M*.*.*` / `N*.*.*` / `mfa.*` | critical |
| Twilio API Key | `SK` + 32 hex | high |
| SendGrid API Key | `SG.*.*` | critical |
| Mailgun API Key | `key-` + 32 chars | high |
| Private Key Header | `-----BEGIN * PRIVATE KEY-----` | critical |
| JWT Token | JSON-object base64url header and payload, three segments | high |
| Social Security Number | `###-##-####` | low |
| Credential in URL | `password=`, `token=`, `apikey=`, etc. | high |

### Injection Detection

| Rule Name | What It Detects |
|-----------|----------------|
| Prompt Injection | "ignore previous instructions" patterns |
| System Override | `system:` at line start |
| Role Override | "you are now DAN/evil/unrestricted" |
| New Instructions | "new instructions/directives/rules" |
| Jailbreak Attempt | "act as DAN", "DAN mode", "developer mode", "sudo mode" |
| Hidden Instruction | "do not reveal this to the user" |
| Behavior Override | "from now on you will/must" |
| Encoded Payload | "decode from base64 and execute" |
| Tool Invocation | "you must call/execute the function" |
| Authority Escalation | "you now have admin access" |
| Instruction Downgrade | "treat previous instructions as outdated" |
| Instruction Dismissal | "set the previous instructions aside" |
| Priority Override | "prioritize the current request" |

## Precedence

When multiple layers apply to the same finding:

1. **Inline comments win first.** Checked before anything else.
2. **Config suppress entries.** Checked if no inline match.
3. **`--exclude` flag.** Applied last, removes from output entirely.

## What NOT to Do

- **Don't remove patterns from config** to suppress findings. That disables detection everywhere, including for real secrets.
- **Don't lower severity** to avoid emission. Use `min_severity` on emit sinks instead.
- **Don't use blanket `// pipelock:ignore`** without a rule name. It suppresses every non-core rule on that line.
- **Don't suppress findings you haven't investigated.** Every suppression is a risk acceptance decision.
