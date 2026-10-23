<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Posture capsule

A posture capsule is a signed `proof.json` artifact that captures the current
Pipelock posture at one point in time. It is intended for operators who need a
portable record of:

- the loaded tool version
- a hash of the active config
- discovery counts for local MCP client protection
- simulated scanner coverage
- current flight recorder receipt activity

## When to generate one

Generate a capsule when you want a signed snapshot of the current installation,
for example:

- after enabling or changing the flight recorder
- before handing an environment to another operator
- before attaching posture evidence to a ticket or audit trail
- after config changes that should be reflected in signed evidence

## Emit a capsule

```bash
pipelock posture emit --config pipelock.yaml --output .pipelock/posture
```

The command writes:

- `.pipelock/posture/proof.json`

`proof.json` is written with `0o600` permissions.

## Signing model

`pipelock posture emit` reuses the Ed25519 private key configured at
`flight_recorder.signing_key_path`.

The signature covers canonical JSON for these fields:

- `schema_version`
- `generated_at`
- `expires_at`
- `tool_version`
- `config_hash`
- `evidence`

The canonical form sorts object keys and omits extra whitespace so the signed
payload is deterministic.

## Verification model

Consumers should verify:

1. `schema_version` is supported.
2. `expires_at` is still in the future.
3. `signer_key_id` matches the trusted public key they expect.
4. the Ed25519 signature matches the canonical JSON payload.

The CLI `pipelock posture verify` is the primary verification surface; the Go package API is available for embedding.

```go
err := posture.Verify(capsule, trustedPublicKey)
```

## `pipelock posture verify`

Verify a signed capsule against a named policy, with optional freshness and minimum-score gates. File-only collection cannot currently satisfy `strict`, including when no MCP servers are found. A newly emitted capsule with any discovered servers also falls below the default minimum score of 85, even under `enterprise`. See [file-only collection limits](#file-only-collection-limits) before using verification as a CI gate.

Flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--proof` | (required) | Path to the signed capsule (`proof.json`). |
| `--key` | (required) | Path to the Ed25519 public key file (pipelock-ed25519-public-v1 format) |
| `--policy` | `enterprise` | Policy name: `enterprise`, `strict`, or `none` |
| `--config` | (optional) | Path to local `pipelock.yaml` for config-hash comparison |
| `--min-score` | `85` | Minimum weighted evidence score (0-100). Explicitly pass `--min-score 0` to skip the score gate. |
| `--max-age` | `30d` | Maximum capsule age in days. Format `Nd` only (e.g. `30d`, `7d`). Use `--max-age 0` to skip freshness. |
| `--max-receipt-age` | `7d` | Maximum age of the most recent flight-recorder receipt, format `Nd`. `0` skips. |
| `--require-discovery` | `false` | Require at least one discovered MCP server (strict policy already enforces this). |
| `--workspace-statement` | (optional) | Path to a signed workspace-change statement that must bind to `--proof`; an incomplete statement is authentic partial evidence and fails verification. |
| `--json` | `false` | Machine-readable output including per-factor score breakdown. |

### Exit codes

`pipelock posture verify` uses distinct exit codes so CI gates can distinguish integrity failure from policy failure. **These are part of the CLI's stable contract — key CI jobs on these values.**

| Exit | Meaning |
|------|---------|
| `0` | Verification passed: signature valid, schema supported, capsule fresh, score meets minimum, all policy gates passed. |
| `1` | **Verification could not complete.** Flag parse error, bad proof file, bad key, signature did not verify, expired capsule, or schema mismatch. The capsule cannot be trusted. |
| `2` | **Verified but failed.** Signature is valid and the capsule is authentic, but one or more policy gates or the minimum-score gate did not pass, or a bound workspace statement reports an incomplete observation. The environment does not meet the requested verification requirements. |

### Policies

Three named policies ship with the current `PolicyVersion = "2"`:

- **`enterprise`** (default) requires no unprotected servers, no simulation category with zero detection, an active flight recorder, and recorded receipts fresh within `--max-receipt-age`. Zero discovered MCP servers produces a warning rather than a hard failure; other gates and the minimum score still apply.
- **`strict`** adds hard failures for zero discovered MCP servers, unknown discovery entries, and discovery parse errors. Capsules count file-only wrappers as unknown, so current file-only collection cannot pass this policy.
- **`none`** skips named policy gates. Signature, validity, configured freshness, and minimum-score checks still apply. It doesn't verify MCP launch coverage.

The policy evaluation produces hard failures (gate-blocking) and warnings (informational). JSON output lists both categories separately.

### Scoring model

The score (0-100) is a weighted sum of evidence factors. High-level factor groups:

- **Discovery** — count of discovered MCP clients and servers, portion under pipelock protection, parse errors.
- **Simulate** — pass rate on the built-in scenario corpus, grade (A/B/C/D/F).
- **Flight recorder** — receipt count in the recent window, verdict distribution (proportion of clean vs blocked), recency of the most recent receipt.
- **Verify install** — proxying active, flight recorder active.

The weighting is encoded in `internal/posture/score.go` and bumps `PolicyVersion` whenever weights change. Capsule consumers should record the `policy_version` alongside score for reproducibility across pipelock upgrades.

### File-only collection limits

Discovery inventories configuration files without starting clients or MCP servers. This applies across supported discovery clients. A wrapper in a checked file is `unconfirmed` because it can't establish what the client launched. Capsules fold that status into the existing signed `discover.unknown` count. Wrapping an unprotected entry fixes its configured command, but adding or repeating a wrapper can't supply launch evidence. See [discovery coverage](../cli/discover.md).

For a nonempty file-only inventory, the best case is all entries wrapped, no parse errors, an active recorder with recent receipts, and perfect simulation. The current functions in [`internal/posture/score.go`](../../internal/posture/score.go) compute:

```text
computeTransportPct:   100 * (protected_pipelock + protected_other)
                          / (total_servers + parse_errors) = 0
computeRecorderPctAt:  100 with an active recorder and recent receipts
computeSimulatePct:    100 with every scorable scenario detected
computeCleanlinessPct: 50 because discover.unknown > 0

factor(raw, weight) = floor(raw * weight / 100)
score = 0 * 25 / 100 + 100 * 15 / 100 + 100 * 35 / 100
        + floor(50 * 25 / 100)
      = 0 + 15 + 35 + 12 = 62
```

Switching from `strict` to `enterprise` alone therefore won't pass the default minimum of 85. A minimum of 80 also exceeds the best-case 62. Lowering the score requirement doesn't remove strict's hard failures: unwrapped entries fail `unprotected_servers`, wrapped or unknown entries fail `unknown_servers`, parse errors fail `discovery_parse_errors`, and an empty inventory fails `no_servers_discovered`.

Using `--policy none --min-score 0` is a deliberate reduction to capsule authenticity, validity, and freshness checks. It provides no MCP coverage verification. `none` alone retains the default score gate; `--min-score 0` alone retains the selected policy's hard gates. Optional config-hash and workspace-statement checks still apply when requested. No default, scoring weight, or policy gate has been lowered. Launch-evidence confirmation is planned; current file-only collection has no equivalent replacement for a successful strict MCP coverage gate.

### CI upgrade impact

CI that emits a capsule and verifies it with `strict` now fails policy verification for file-only evidence. Jobs using the default `enterprise` policy and minimum 85 also fail for a nonempty inventory. The former strict/minimum-80 example can't pass with current file-only collection and has been removed. Keep a required MCP coverage gate failing until suitable evidence is available; any reduction in verification requirements must be an explicit operator decision.

Exit `2` means the capsule's signature is valid but a policy gate or the minimum score failed. If a bound workspace statement is incomplete, read its incomplete reason; relaxing policy won't change that result. Exit `1` means verification couldn't complete, for example because the capsule expired or its signature didn't verify.

### Existing capsules

The signed schema remains version `1`. Verification evaluates the signed counts without recollecting discovery or reclassifying historical protected counts. Older signed capsules can still pass until their existing validity, freshness, score, or policy checks fail. Re-emitting collects the new conservative evidence and can produce a different policy result with a valid signature. That difference isn't signature corruption.

## Artifact shape

Minimal example:

```json
{
  "config_hash":"7d3ec7c0c7d1f2c9d5e44c4f1fbe2fbc08d63fcac2c7248d8c3066cb917d6d0d",
  "evidence":{
    "discover":{
      "high_risk":0,
      "parse_errors":0,
      "protected_other":0,
      "protected_pipelock":0,
      "total_clients":1,
      "total_servers":2,
      "unknown":2,
      "unprotected":0
    },
    "flight_recorder":{
      "last_receipt_at":"2026-04-11T13:05:12Z",
      "receipt_count":4,
      "scanner_verdict":{
        "dlp":{"allow":0,"block":3,"warn":0},
        "unknown":{"allow":1,"block":0,"warn":0}
      }
    },
    "simulate":{
      "config_file":"",
      "failed":0,
      "grade":"A",
      "known_limitations":0,
      "mode":"balanced",
      "passed":24,
      "percentage":100,
      "scenarios":[],
      "total":24
    },
    "verify_install":{
      "flight_recorder_active":true,
      "proxying":true,
      "receipt_count":4
    }
  },
  "expires_at":"2026-05-11T13:05:12Z",
  "generated_at":"2026-04-11T13:05:12Z",
  "schema_version":"1",
  "signature":"c1b8b9c4f4d2...",
  "signer_key_id":"9f6b9d7c...",
  "tool_version":"0.0.0-dev.unknown"
}
```

## Notes

- `pipelock posture emit` writes `proof.json` and `proof.md` (human-readable). A `badge.svg` companion is a planned follow-up.
- The verify CLI is the supported gate surface. Earlier documentation called CI gates and scores "follow-up work" — both are shipping.
- SARIF output is planned for later releases.
