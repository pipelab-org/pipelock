# Pipelock receipt v3

Receipt v3 records signed statements about mediated decisions. This specification uses RFC 2119 requirement words. The encoding and signing references are RFC 8785 (June 2020), RFC 8032 (January 2017), RFC 4648 (October 2006, Base64 in §4), and DSSE protocol v1.

## Storage and detection

A record has this exact byte layout followed by one LF (0x0A).

```text
{"payloadType":"application/vnd.pipelock.receipt.v3+json","signatures":[{"keyid":"<key id>","sig":"<base64>"}],"payload":<payload>}
```

The fixed prefix ends at `[`. One to four entries follow, separated by commas and sorted by key ID bytes with no repeats. Each entry is exactly `{"keyid":"`, a key ID, `","sig":"`, 88 Base64 characters, then `"}`. A digest string is `sha256:` and 64 lowercase hexadecimal digits. The key ID is the digest string of the raw 32-byte Ed25519 public key. The signature encodes 64 bytes using the standard padded alphabet and zero unused bits.

Match `],"payload":` and take every byte before the final `}` and LF as the payload. It must be one JSON object. Reject additional outer members, alternate ordering, byte order marks, and whitespace outside payload strings. A reader never reconstructs the signed bytes. Split on LF alone. U+0085, U+2028, and U+2029 can occur literally in strings. The line limit includes LF.

A file name is the stream ID, a hyphen, the first sequence number as 16 zero-padded decimal digits, and `.receipt-v3.jsonl`. Read files in ascending order of that number. A v3-named file must contain at least one complete record and match its first record's stream and sequence. A differently named single file may be explicitly identified as v3. A name ending in `.receipt-v<N>.jsonl` for another version, or a v3-named file carrying another receipt payload profile, gives `UNKNOWN_PROFILE`. A file supplied explicitly or selected by legacy discovery beginning with `{"payloadType":"application/vnd.pipelock.receipt.` without a v3 claim gives `V3_CONTENT_UNCLAIMED`. A damaged v3 claim never falls back to a legacy decoder.

Directory scope selects those files, cutover inventories and files selected by legacy discovery. Count other files as ignored. Select a legacy decoder using its native discriminator. A selected file with no recognized records gives `UNRECOGNIZED_FILE`. Valid operational recorder files without receipts are ignored and counted in directory scope. The same input by itself lacks receipt evidence. An explicit file list mixing old and new formats is a usage error. Verify the directory for combined evidence.

Unterminated bytes give `TORN_TAIL` only after the last complete record of the stream's last file, when that record is not a close. Ignore those bytes. A torn tail after a close is `DATA_AFTER_CLOSE`. Reject a torn tail in an earlier file or a file without a complete record.

## Signing and trust

The signature message is the DSSE v1 pre-authentication encoding.

```text
"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```

`SP` is one ASCII space. Lengths count bytes, in ASCII decimal with no leading zeros. The payload type is the 40 bytes `application/vnd.pipelock.receipt.v3+json`. Hash the entire message to get the record ID. The inputs to signing and hashing include the exact stored payload.

Verify the entry whose key ID equals `signer`. Other entries must pass the layout checks and have no effect on verification. A writer emits one entry. DSSE export preserves `payloadType` and `signatures` and replaces the payload object with standard padded Base64 of the exact payload bytes.

Write `A` for the public key, `R` for the first 32 bytes of the signature, and `S` for the last 32 bytes. Verify pure Ed25519 with these constraints.

1. The little-endian integer `S` is less than the group order `L`.
2. `A` and `R` canonically encode curve points. Each 255-bit y coordinate is less than 2²⁵⁵−19, each point decodes under RFC 8032 §5.1.3, and x equal to zero requires a zero sign bit.
3. Neither point is the identity. `[L]A` must be the identity using unreduced point multiplication.
4. Compute `k` from SHA-512 of `R || A || PAE` as a little-endian integer modulo `L`. Compare the canonical encoding of `[S]B − [k]A` to `R` byte for byte. With a cofactored library, also check `[L]R` is the identity. Multiplication by eight is injective in the prime-order subgroup, so the equations then agree.

The sole trust input is a caller-pinned set of raw public keys. If the set is nonempty, every stream must use a pinned key. Without pins, verify signatures using the embedded stream keys and report self-consistency. Key changes occur on restart. Pin each key independently. The result names the exact key IDs used and makes no assertion about freshness, revocation or the writer instance.

## Payload and body validation

Payloads use RFC 8785 over a restricted data model. Signature and digest checks always use the input bytes.

- UTF-8, no byte order mark or inter-token whitespace. Values are objects, arrays, strings, bounded integers or booleans. Nulls are forbidden.
- Integers use `0|-?[1-9][0-9]*` and stay within the wire magnitude limit.
- Object names match `[a-z][a-z0-9_]{0,63}`, are unique and ascend by byte order. Object names come from the schema. Use sorted arrays of objects for data-derived keys.
- Strings contain Unicode scalar values without normalization. Escape quotation mark, backslash, backspace, form feed, LF, carriage return and tab with their short escapes. Other controls below U+0020 use lowercase `\u00xx`. All other characters are literal UTF-8, including `<>&/`, U+007F, U+0085, U+2028 and U+2029.
- The payload object is at depth one. Each nested object or array increases the depth by one.
- Omit optional values when absent. Optional strings, arrays and objects may not be empty. Required arrays may be empty.
- `v` is 3. `ts` is UTC in `YYYY-MM-DDTHH:MM:SS.mmmZ` form and is a signer claim. For sequence zero, `prev` is the digest of ASCII `pipelock-receipt-v3-genesis`, one NUL byte and the 32 ASCII stream ID characters. Later records use the prior record ID.
- `crit` is sorted and unique. This profile defines no values and reports `UNKNOWN_CRIT` for any entry. Ignore unrecognized signed `ext` content. Common members and understood bodies admit only the listed names.
- Treat an unknown kind as an event. Verify layout, signature, ordering and trust for unknown events and events with a newer body version. Effective ones are uninterpreted. A newer control body version or unknown control enumeration yields `UNKNOWN_CONTROL`. An extension that changes verification must advertise the requirement with `crit` or a newer control body version.

### Conditional fields

- Only a history's first open has `legacy_cutover`. It has no `previous`. Every other open has `previous` and omits `legacy_cutover`. The embedded key has the fingerprint in `signer`. Its coverage applies throughout the stream. Sort `surfaces` by byte order. Include `posture` when required by the writer's configuration.
- The close's `records` is its `seq + 1`. Heartbeats number from one and report cumulative counters.
- An action policy uses `request_snapshot` with the decision's snapshot digest or `unavailable` without a digest. A later configuration reload cannot supply a missing digest. The opener alone uses `writer_config`.
- The caller's `mcp_door_verified` requires all four identity members. The `none` form has only the authorization label. The caller object never contains a token.
- Include normalization when text normalization ran and carry the identity and digest of the profile used. Report an unresolved digest as `NORMALIZATION_UNKNOWN`; never use the verifier's default in its place.
- For checker selection `unavailable`, disposition is `not_run` and `config_hash` is absent. Other selections require their configuration digests. The built-in default on a surface without its own selection is `configured`. A configured checker error does not trigger a built-in fallback. A future explicit fallback would use `fallback` and bind the substitute's configuration. There is no verdict-payload hash in this version.
- Holds carry policy and may carry a parent hold. Resolutions carry resolution policy and source. A correcting block resolution carries `correction:true`, which is absent otherwise.
- Ask `observed` is true for `approval_api` and false for `host_prompt`. It reports the channel, not the answer. A host prompt is `asked_unobserved` even if the host protocol acknowledges the request.
- Sort redaction classes by `class` with no duplicates.

`id128` is 32 lowercase hexadecimal characters. `action_id` is one to 128 ASCII letters, digits, periods, underscores, colons or hyphens. `name` uses the object member-name grammar. `key` is standard padded Base64 of 32 bytes. `time`, `digest`, and `version` use the forms above. `uint` is a nonnegative wire integer, and `positive` starts at one. `target` and `instance` are bounded strings measured in bytes. `[]` is an array and `@` an enumeration. Capitalized types refer to object tables.

## Stream and history verification

For each record check line layout, payload layout, common members, signature, stream rules, known body schema, and pinned trust, in that order. The first failure stops checks on that record. Verify every presented copy before coalescing equal stream, position and record ID. Repeated positions in one file fail. Different IDs at one position give `FORK`; use only the shared prefix. A fork at position zero leaves the stream contested without an agreed signer or lineage.

A stream starts with `stream_open` at zero and advances one position per record. All records keep the stream and signer and name their immediate predecessor. A close is last. Warn about gaps in heartbeat numbering and backward timestamps. Choose stream and lineage IDs at random, with one lineage shared by successive streams.

Each successor pins a predecessor in the same lineage. Multiple successors give `SUCCESSION_FORK`. Multiple roots give `ROOT_FORK`. Missing predecessors give `PREDECESSOR_NOT_PRESENTED`. Separate components give `HISTORY_DISCONNECTED`.

A `closed` pin names the terminal close. An `unsealed` pin names the last complete record when there is no close. Records after either pin yield `TAIL_AFTER_SUCCESSION`. A `write_error` pin names the writer's last confirmed record, whose file data and directory entry were flushed. Later complete records, including a close, must verify but count as `UNCONFIRMED`. They do not affect effective decisions, counts or the effective tip. Missing pinned positions are `PREDECESSOR_TRUNCATED`; mismatched IDs or close status are `PIN_MISMATCH`.

End states are `closed` for a terminal close, `superseded_unsealed` or `superseded_write_error` for the respective effective pins, `open` without a terminal close or effective successor, and `forked` for the shared prefix of a fork. The tip is the last complete record except when an effective write-error pin supplies it. A stream with multiple successors has no tip. A close proves the writer signed the end of the bytes presented. It does not prove its own flush succeeded or that bytes lost after an earlier write error were recovered by a later flush.

## Decisions

A history identifies each decision by `action_id`. One effect is the tuple of `action_type`, `transport`, `method`, `target`, and `effect_boundary`. Releasing verdicts are `allow`, `warn`, `strip`, `forward`, and `redirect`. Releasing boundaries exclude `none` and `approval_prompt`.

| Phase | Verdict | Boundary and relation | Conditions |
| --- | --- | --- | --- |
| decision | block | Any boundary, not_attempted | |
| decision | ask | hook_execution, before | Host prompt |
| decision | releasing | Releasing boundary, before, after or unknown | Receipts are not required |
| intent | releasing | Releasing boundary, before | Attempt required |
| outcome | Same releasing verdict as intent | Intent's boundary, after for completed or failed_after_attempt, not_attempted for failed_before_attempt, unknown for attempt_unknown | Same attempt and effect as intent |
| outcome | block | Boundary of intended effect, not_attempted | Class not_released. Attempt and effect match the intent if present |
| hold | defer or ask | approval_prompt, before | Hold ID, approval API for ask |
| resolution | allow or ask | approval_prompt, after | Same hold ID, approval API for ask |
| resolution | block | approval_prompt, after, not_attempted or unknown | Same hold ID |

Only an intent or outcome carries an attempt. Only an outcome carries an outcome class. Only a hold or resolution carries a hold object. Only ask carries an ask object.

A decision phase ends the decision. A block counts as `blocked`, a host ask as `asked_unobserved`, and a releasing decision as `allowed_effect_unrecorded`.

One hold with no resolution counts as `pending`. An ask resolution ends it as `stepped_up`; a subsequent decision uses a new ID. One or more block resolutions end it as `blocked`. A single allow resolution ends it as `outcome_unknown` unless followed by attempts or one or more correcting blocks. A correcting block ends it as `blocked`. Resolutions keep the hold ID. Block is marked as a correction exactly when the first resolution was allow. Ask and allow can only be the first resolution. No resolution follows any intent or outcome.

Number attempts from one. An attempt is an intent with an optional outcome, or a standalone `not_released` outcome. Another attempt can follow only `failed_before_attempt` or `not_released`. All attempts in a decision describe the same effect. The last attempt determines the state. `completed` and `not_released` keep their names. Both failure classes give `failed`. A missing outcome or `attempt_unknown` gives `outcome_unknown`.

### Appraisal across gaps

Appraise effective records in connected segments. A stream continues a predecessor in its lineage if the predecessor is presented, has no fork and has that single successor. A fork contributes its shared prefix and ends its segment. Each decision's records in one segment form a piece. A segment rooted at a first stream must contain the start of each of its decisions. Otherwise an unknown legal prefix is allowed.

Reject a piece if no legal prefix admits exactly that piece. At an unknown start, an initial resolution requires an inferred hold, and an initial correction also requires an inferred allow resolution. An initial outcome other than `not_released` requires a legal matching intent, including a releasing boundary. If the first attempt in a piece with an unknown start is above two, subtract its number minus two from every attempt in that piece. One inferred preceding standalone refusal suffices after shifting. Work must be independent of signed attempt magnitude and bounded per repeated block.

Never join pieces across a gap. A missing stream can supply a pin that makes the earlier tail unconfirmed, and there is no provable order for later segments. A hold ID used by different decisions is inconsistent across the whole history, even across gaps. Apply this rule to effective readable hold and resolution phases with understood IDs, including records with another unknown enumeration.

An effective v1 action with an unknown enumeration is uninterpreted. Report it and exempt its decision from sequence checks across all pieces. Still check the shapes of the decision's readable actions. An effective action with a higher body version suspends sequence appraisal for the history and gives `DECISIONS_NOT_APPRAISED`. Hold ownership, shape checks, and the index limit for readable decision IDs still apply. Effective uninterpreted events other than actions do not change completeness.

## Cutover inventory

The inventory is one canonical JSON object using the payload data model, with `v` equal to 1 and a required `chains` array. Each row has `chain` (identity), `format` (a label below), `record` (digest string), and `seq` (terminal wire integer). Sort rows by format then chain and require uniqueness on that pair. The optional `journal` digest binds the exact bytes of the deferred approval journal when present. There is no final LF. The file name is `receipt-v3-cutover-<hex>.json` using the inventory digest's 64 hexadecimal digits.

| Format | Identity | Terminal position |
| --- | --- | --- |
| action_v1 | Signed run nonce at genesis, or the first canonical action record's hash for a chain without a nonce | Sequence and canonical action-record hash of the last receipt |
| evidence_v2 | First receipt's v2 hash | Sequence and v2 hash of the last receipt |
| receipt_group | Signed group ID | Shard count and digest of the close manifest, or the open manifest for an incomplete group |

Use digest strings for legacy hashes. The fixed empty inventory bytes are `{"chains":[],"v":1}`. Their digest is `sha256:5fba275c695ef4915395ac61c90788e9022c8ad4858e046ac1440726f0144d1f`. With neither old chains nor a journal, use that digest and zero chains and omit the file.

Cutover inventories every old chain in the evidence directory, without an epoch or chain cap. A writer refuses a partial inventory. It verifies the old evidence and refuses unresolved holds before switching. While holding the directory lock it persists the inventory, then publishes and flushes the first v3 file carrying the pin. That first file commits the switch. The same directory cannot subsequently resume legacy writes.

A missing inventory is incomplete. A digest, encoding or chain-count mismatch is invalid. Apply each legacy chain or group's own verification rules with the same pinned keys. An incomplete legacy group stays incomplete. A legacy chain with an unproven end contributes an end-unproven finding unless the caller accepts it by naming the root open. Other legacy failures are invalid.

An absent listed chain is incomplete. A chain shorter or longer than listed, or ending with a different hash, is invalid. Verify all presentations. Identical copies count once, and a matching prefix of a longer copy is covered by that copy. Disagreement at a common position is invalid. An unlisted chain is invalid when every history has its verified root inventory and no contested open might carry another inventory. Otherwise report `LEGACY_MEMBERSHIP_UNKNOWN`. A later gap in a rooted history does not hide an unlisted chain.

## Caller requirements and result

- `--expect-head <stream>:<seq>:<record>` requires that exact tip. `--expect-seq <stream>:<seq>` requires the tip's sequence. A matched tip proves its stream's end.
- `--expect-lineage <lineage>` requires that history.
- `--accept-discontinuity <record>` must name an open with an unsealed or write-error pin, or a root open that pins old evidence with an unproven end.
- `--allow-partial-history <stream>` accepts only a missing predecessor named by the supplied stream. It does not accept a disconnected history or unknown legacy membership.
- An unmet requirement is `EXPECTATION_NOT_MET`. The scope and trust preferences below do not stand in for these requirements.

The result is canonical JSON with `kind:verify_result` and `v:1`. It contains `verdict`, `exit_code`, `integrity`, `completeness`, `trust_state`, `trust`, `accepted`, `histories`, `contested_streams`, `legacy`, `counts`, `ignored_files`, `findings`, and `limits`.

- Integrity is `ok` or `failed`. Completeness is `complete`, `incomplete`, or `end_unproven`. Trust state is `pinned` or `unpinned`. Trust contains `mode` (`pinned_keys` or `unpinned`) and sorted `keys` used. Accepted inputs have `kind` and `value`, sorted by both. Boolean options use the string `true`.
- Histories have `lineage` and a `streams` array sorted by stream ID. Sort histories by lineage. Each stream has `stream`, `signer`, `records`, `end`, `previous` if named, and `last` and `tip` when known. Each position has `seq` and `record`. A superseded write-error stream reports physical `last`, effective `tip` and count, and the first unconfirmed sequence as `unconfirmed_from`. A contested stream has `stream` and sorted position-zero digests in `records`. Sort contested streams by ID. Legacy rows have `format`, `chain`, and their frozen `verdict` text, sorted by format and chain.
- Counts have `scope:full_history` only when every history is one appraised rooted segment. Otherwise report only `scope:not_appraised`. Full counts contain `complete` (no unaccepted invalid, unsupported or incomplete finding), sorted `decisions` with `state` and `count`, `effects_completed`, `effects_unknown`, and `uninterpreted` with `kind` and `count` sorted by kind. Count each decision once. Unknown effect states are `outcome_unknown`, `pending`, `asked_unobserved`, `allowed_effect_unrecorded` and `uninterpreted`. An unproven end does not make the counts incomplete.
- Findings contain `code`, its registered `class`, and `stream`, `seq`, and `record` where they apply. Sort and deduplicate on code, stream, sequence, record, with absent members sorting first. Always include `L-FSYNC-HONESTY` and `L-FSYNC-ERROR-REOPEN` in the sorted limits. Add `L-DECISION-INDEX` on index exhaustion.

Usage and unreadable input errors exit 2 without a document. Otherwise use the first matching verdict.

| Evidence status | Verdict |
| --- | --- |
| Any invalid finding | INVALID |
| Any unsupported finding | UNSUPPORTED |
| Unaccepted incomplete finding | INCOMPLETE |
| Unaccepted end-unproven finding | VALID PREFIX, END UNPROVEN |
| No pinned keys | SELF-CONSISTENT ONLY |
| A gap or discontinuity was accepted | VALID, GAPS ACCEPTED |
| Otherwise | VALID |

Invalid exits 1. Unsupported and incomplete exit 3. For other verdicts, exit 3 if an unaccepted end remains and `--allow-prefix` is absent. Otherwise exit 1 if trust is unpinned and `--allow-unpinned` is absent, or exit 0. Both flags preserve the verdict. Only `VALID` is an unqualified pass. Expose unknown effects alongside the verdict when counts were appraised.

The normative projection includes `verdict`, `exit_code`, `trust`, `accepted`, `integrity`, `completeness`, `trust_state`, and `finding_codes` (the sorted set of codes of the deciding class excluding accepted findings). For valid, accepted-gaps, self-consistent and prefix verdicts also include `counts` and `histories`. Project histories to `lineage` and `streams`, and streams to `stream`, `previous` if present, `records`, `end`, and `tip` if present. The full document is deterministic across input file order.

## Limits and conformance

A host verifier does not load a whole stream into memory. Streams and files have no additional length limits. Writers should start a new file at 64 MiB and reserve room for a close. The memory decision index counts distinct effective readable IDs per history. Past its limit, report `DECISION_INDEX_FULL` and continue stream and signature checks. The Go verifier's disk index has no such limit. Browser readers exceeding a listed archive bound return `USE_HOST_VERIFIER`.

Shared corpus inputs, pins, caller flags, expected documents and projections are generated from recipes. A rejecting vector names one target check and finding. All its other checks must pass, including the signature over the presented bytes unless the vector tests the signature. Compare canonical projections across implementations and full documents across presentation orders within one implementation. Keep frozen old-format fixtures byte-identical. Use the Wycheproof Ed25519 suite at revision 65ca494727a52944c204441c860b039e6786b99b (schema eddsa_verify_schema_v1.json) for signature edge cases.

## Field registry

<!-- BEGIN generated receipt v3 registry -->

### Kinds

| Kind | Class | Body version | Body |
| --- | --- | --- | --- |
| `action` | event | 1 | Action |
| `heartbeat` | event | 1 | Heartbeat |
| `stream_close` | control | 1 | StreamClose |
| `stream_open` | control | 1 | StreamOpen |

### Action

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `action_id` | `action_id` | yes |  |
| `action_type` | `@action_type` | yes |  |
| `actor` | `string` | yes |  |
| `ask` | `Ask` | conditional or optional |  |
| `attempt` | `positive` | conditional or optional |  |
| `caller` | `Caller` | yes |  |
| `checker` | `Checker` | conditional or optional |  |
| `contestation_window` | `string` | conditional or optional |  |
| `contract` | `Contract` | conditional or optional |  |
| `data` | `Data` | yes |  |
| `delegation_chain` | `[]string` | conditional or optional |  |
| `effect_boundary` | `@boundary` | yes |  |
| `effect_relation` | `@relation` | yes |  |
| `hold` | `Hold` | conditional or optional |  |
| `intent` | `string` | conditional or optional |  |
| `jurisdiction` | `string` | conditional or optional |  |
| `layer` | `string` | conditional or optional |  |
| `method` | `string` | conditional or optional |  |
| `normalization` | `Normalization` | conditional or optional |  |
| `outcome_class` | `@outcome` | conditional or optional |  |
| `parent_action_id` | `action_id` | conditional or optional |  |
| `pattern` | `string` | conditional or optional |  |
| `phase` | `@phase` | yes |  |
| `policy` | `ActionPolicy` | yes |  |
| `precedent_refs` | `[]string` | conditional or optional |  |
| `principal` | `string` | yes |  |
| `redaction` | `Redaction` | conditional or optional |  |
| `remedy_class` | `string` | conditional or optional |  |
| `request_id` | `string` | conditional or optional |  |
| `rulebook_id` | `string` | conditional or optional |  |
| `session` | `Session` | conditional or optional |  |
| `severity` | `string` | conditional or optional |  |
| `shield` | `Shield` | conditional or optional |  |
| `taint` | `Taint` | conditional or optional |  |
| `target` | `target` | yes |  |
| `transport` | `string` | yes |  |
| `venue` | `string` | conditional or optional |  |
| `verdict` | `@verdict` | yes |  |

### ActionPolicy

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `hash` | `digest` | conditional or optional |  |
| `source` | `@action_policy_source` | yes |  |

### Ask

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `channel` | `@ask_channel` | yes |  |
| `observed` | `bool` | yes |  |

### Caller

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `authn` | `@authn` | yes |  |
| `client_id` | `string` | conditional or optional |  |
| `issuer` | `string` | conditional or optional |  |
| `resource` | `string` | conditional or optional |  |
| `subject` | `string` | conditional or optional |  |

### Checker

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `config_hash` | `digest` | conditional or optional |  |
| `disposition` | `@checker_disposition` | yes |  |
| `mode` | `@checker_mode` | yes |  |
| `selection` | `@checker_selection` | yes |  |
| `surface` | `@checker_surface` | yes |  |

### Common

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `body` | `object` | yes | Kind-specific signed statement. |
| `body_v` | `positive` | yes | Version of the body. |
| `crit` | `[]name` | conditional or optional | Sorted unique mandatory feature names. |
| `ext` | `object` | conditional or optional | Signed extensions. |
| `kind` | `name` | yes | Record kind. |
| `prev` | `digest` | yes | Previous record ID or genesis digest. |
| `seq` | `uint` | yes | Position from zero. |
| `signer` | `digest` | yes | Fingerprint of the signing key. |
| `stream` | `id128` | yes | Stream ID. |
| `ts` | `time` | yes | UTC with milliseconds. |
| `v` | `version` | yes | Receipt profile version. |

### Contract

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `generation` | `uint` | conditional or optional |  |
| `hash` | `string` | conditional or optional |  |
| `live_verdict` | `string` | conditional or optional |  |
| `manifest_hash` | `string` | conditional or optional |  |
| `policy_sources` | `[]string` | conditional or optional |  |
| `rule_id` | `string` | conditional or optional |  |
| `selector_id` | `string` | conditional or optional |  |
| `winning_source` | `string` | conditional or optional |  |

### Coverage

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `content_scan` | `bool` | yes |  |
| `receipts_required` | `bool` | yes |  |
| `redaction_ruleset` | `Ruleset` | yes |  |
| `surfaces` | `[]string` | yes |  |

### Cutover

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `chains` | `uint` | yes |  |
| `inventory` | `digest` | yes |  |

### Data

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `classes_in` | `[]string` | conditional or optional |  |
| `classes_out` | `[]string` | conditional or optional |  |
| `reversibility` | `string` | yes |  |
| `side_effect_class` | `string` | yes |  |

### Durability

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `durability_blocks` | `uint` | yes |  |
| `fsync_errors_gated` | `uint` | yes |  |

### Heartbeat

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `beat` | `positive` | yes |  |
| `durability_blocks` | `uint` | yes |  |
| `fsync_errors_gated` | `uint` | yes |  |

### Hold

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `correction` | `bool` | conditional or optional |  |
| `id` | `string` | yes |  |
| `parent` | `string` | conditional or optional |  |
| `policy` | `string` | conditional or optional |  |
| `resolution_policy` | `string` | conditional or optional |  |
| `resolution_source` | `string` | conditional or optional |  |

### Normalization

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `digest` | `digest` | yes |  |
| `id` | `string` | yes |  |

### Posture

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `capsule_sha256` | `digest` | yes |  |
| `contained_uid` | `string` | yes |  |
| `containment_nonce` | `string` | yes |  |
| `signer_key_id` | `string` | yes |  |

### Previous

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `ended` | `@ended` | yes |  |
| `record` | `digest` | yes |  |
| `seq` | `uint` | yes |  |
| `stream` | `id128` | yes |  |

### Recorder

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `entries` | `uint` | yes |  |
| `session` | `string` | yes |  |
| `transcript_root` | `digest` | yes |  |

### Redaction

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `cache_boundary_kept` | `bool` | conditional or optional |  |
| `classes` | `[]RedactionClass` | conditional or optional |  |
| `parser` | `string` | conditional or optional |  |
| `profile` | `string` | conditional or optional |  |
| `provider` | `string` | conditional or optional |  |
| `total_redactions` | `uint` | conditional or optional |  |

### RedactionClass

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `class` | `string` | yes |  |
| `count` | `uint` | yes |  |

### Ruleset

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `hash` | `string` | yes |  |
| `id` | `string` | yes |  |
| `version` | `string` | yes |  |

### Session

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `contaminated` | `bool` | conditional or optional |  |
| `id` | `string` | conditional or optional |  |
| `original_id` | `string` | conditional or optional |  |
| `taint_level` | `string` | conditional or optional |  |
| `taint_sources` | `[]TaintSource` | conditional or optional |  |
| `task_id` | `string` | conditional or optional |  |
| `task_label` | `string` | conditional or optional |  |

### Shield

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `adaptive_signal_max_per_body` | `uint` | conditional or optional |  |
| `adaptive_signals_recorded` | `uint` | conditional or optional |  |
| `agent_traps` | `uint` | conditional or optional |  |
| `body_bytes` | `uint` | conditional or optional |  |
| `extension_probes` | `uint` | conditional or optional |  |
| `fingerprint_shim_injected` | `bool` | conditional or optional |  |
| `partial` | `bool` | conditional or optional |  |
| `pipeline` | `string` | conditional or optional |  |
| `scanned_bytes` | `uint` | conditional or optional |  |
| `svg_animation_injections` | `uint` | conditional or optional |  |
| `svg_event_handlers` | `uint` | conditional or optional |  |
| `svg_external_references` | `uint` | conditional or optional |  |
| `svg_foreign_objects` | `uint` | conditional or optional |  |
| `svg_hidden_text` | `uint` | conditional or optional |  |
| `total_rewrites` | `uint` | conditional or optional |  |
| `tracking_beacons` | `uint` | conditional or optional |  |

### SignerKey

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `alg` | `@algorithm` | yes |  |
| `public` | `key` | yes |  |

### StreamClose

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `durability` | `Durability` | yes |  |
| `reason` | `@close_reason` | yes |  |
| `recorder` | `Recorder` | conditional or optional |  |
| `records` | `positive` | yes |  |

### StreamOpen

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `coverage` | `Coverage` | yes |  |
| `heartbeat_seconds` | `uint` | conditional or optional |  |
| `legacy_cutover` | `Cutover` | conditional or optional | Required on the first stream only. |
| `lineage` | `id128` | yes |  |
| `policy` | `StreamPolicy` | yes |  |
| `posture` | `Posture` | conditional or optional |  |
| `previous` | `Previous` | conditional or optional | Required after the first stream. |
| `recorder_session` | `string` | conditional or optional |  |
| `signer_key` | `SignerKey` | yes |  |
| `writer` | `Writer` | yes |  |

### StreamPolicy

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `hash` | `digest` | yes |  |
| `source` | `@stream_policy_source` | yes |  |

### Taint

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `authority_kind` | `string` | conditional or optional |  |
| `decision` | `string` | conditional or optional |  |
| `reason` | `string` | conditional or optional |  |
| `task_override_applied` | `bool` | conditional or optional |  |

### TaintSource

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `kind` | `string` | yes |  |
| `level` | `uint` | yes |  |
| `match_reason` | `string` | conditional or optional |  |
| `receipt_id` | `string` | conditional or optional |  |
| `timestamp` | `string` | yes |  |
| `url` | `string` | yes |  |

### Writer

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `binary_digest` | `digest` | conditional or optional |  |
| `instance` | `instance` | yes |  |
| `product` | `string` | yes |  |
| `version` | `string` | yes |  |

### Types

| Enumeration | Values |
| --- | --- |
| `@action_policy_source` | `request_snapshot`, `unavailable` |
| `@action_type` | `actuate`, `authorize`, `commit`, `delegate`, `derive`, `read`, `spend`, `unclassified`, `write` |
| `@algorithm` | `ed25519` |
| `@ask_channel` | `approval_api`, `host_prompt` |
| `@authn` | `mcp_door_verified`, `none` |
| `@boundary` | `approval_prompt`, `downstream_delivery`, `hook_execution`, `none`, `redirect_dispatch`, `tunnel_open`, `upstream_send` |
| `@checker_disposition` | `error`, `flagged`, `not_run`, `passed` |
| `@checker_mode` | `block`, `off`, `warn` |
| `@checker_selection` | `configured`, `fallback`, `unavailable` |
| `@checker_surface` | `browser_shield`, `hook_tool_input`, `hook_tool_result`, `http_request_body`, `http_response`, `mcp_tool_description`, `mcp_tool_input`, `mcp_tool_result`, `scan_api` |
| `@close_reason` | `rollover`, `shutdown` |
| `@ended` | `closed`, `unsealed`, `write_error` |
| `@outcome` | `attempt_unknown`, `completed`, `failed_after_attempt`, `failed_before_attempt`, `not_released` |
| `@phase` | `decision`, `hold`, `intent`, `outcome`, `resolution` |
| `@relation` | `after`, `before`, `not_applicable`, `not_attempted`, `unknown` |
| `@stream_policy_source` | `writer_config` |
| `@verdict` | `allow`, `ask`, `block`, `defer`, `forward`, `redirect`, `strip`, `warn` |

### Findings

| Code | Class |
| --- | --- |
| `ACTION_UNINTERPRETED` | incomplete |
| `BODY_SCHEMA` | invalid |
| `CLOCK_REGRESSION` | warning |
| `COMMON_SCHEMA` | invalid |
| `CUTOVER_INVENTORY_MISMATCH` | invalid |
| `CUTOVER_INVENTORY_NOT_PRESENTED` | incomplete |
| `DATA_AFTER_CLOSE` | invalid |
| `DECISIONS_NOT_APPRAISED` | incomplete |
| `DECISION_INCONSISTENT` | invalid |
| `DECISION_INDEX_FULL` | incomplete |
| `END_UNPROVEN` | end_unproven |
| `EVENT_UNINTERPRETED` | info |
| `EXPECTATION_NOT_MET` | invalid |
| `FILE_LAYOUT` | invalid |
| `FORK` | invalid |
| `HEARTBEAT_GAP` | warning |
| `HISTORY_DISCONNECTED` | incomplete |
| `LEGACY_CHAIN_HEAD_MISMATCH` | invalid |
| `LEGACY_CHAIN_NOT_PRESENTED` | incomplete |
| `LEGACY_CHAIN_TRUNCATED` | invalid |
| `LEGACY_CHAIN_UNLISTED` | invalid |
| `LEGACY_END_UNPROVEN` | end_unproven |
| `LEGACY_EXTENDED_AFTER_CUTOVER` | invalid |
| `LEGACY_GROUP_INCOMPLETE` | incomplete |
| `LEGACY_INVALID` | invalid |
| `LEGACY_MEMBERSHIP_UNKNOWN` | incomplete |
| `LINEAGE_MISMATCH` | invalid |
| `LINE_LAYOUT` | invalid |
| `LINE_SIZE` | invalid |
| `NORMALIZATION_UNKNOWN` | warning |
| `NO_EVIDENCE` | incomplete |
| `PAYLOAD_LAYOUT` | invalid |
| `PIN_MISMATCH` | invalid |
| `PREDECESSOR_NOT_PRESENTED` | incomplete |
| `PREDECESSOR_TRUNCATED` | invalid |
| `ROOT_FORK` | invalid |
| `SIGNATURE_EQUATION` | invalid |
| `SIGNATURE_KEY` | invalid |
| `SIGNATURE_POINT` | invalid |
| `SIGNATURE_SCALAR` | invalid |
| `SIGNER_MISSING` | invalid |
| `STREAM_ORDER` | invalid |
| `SUCCESSION_FORK` | invalid |
| `TAIL_AFTER_SUCCESSION` | invalid |
| `TORN_TAIL` | info |
| `TRUST` | invalid |
| `UNCONFIRMED` | info |
| `UNKNOWN_CONTROL` | unsupported |
| `UNKNOWN_CRIT` | unsupported |
| `UNKNOWN_PROFILE` | unsupported |
| `UNRECOGNIZED_FILE` | invalid |
| `USE_HOST_VERIFIER` | unsupported |
| `V3_CONTENT_UNCLAIMED` | invalid |

### Limits

| Limit | Value |
| --- | --- |
| browser archive bytes | 8,388,608 |
| browser archive files | 4,096 |
| browser entry bytes | 33,554,432 |
| browser total bytes | 33,554,432 |
| decisions | 10,000,000 |
| depth | 16 |
| integer | 9,007,199,254,740,991 |
| line bytes | 1,048,576 |
| member bytes | 64 |
| signatures | 4 |
| target bytes | 2,048 |
| writer instance bytes | 128 |

<!-- END generated receipt v3 registry -->

## Producer attribution

The emission registry published beside this specification assigns each catalogued site an effect boundary. Carry a decision-time policy snapshot through every later phase of the same effect. Carry the original action ID for a hold, its resolutions, and retries of the same effect. Omit optional attribution a producer cannot establish.

| Producer or decision context | Boundary | Attribution and conditions |
| --- | --- | --- |
| HTTP fetch, forward, reverse and intercepted upstream requests | upstream_send | Use the selected request policy and request identity. Contract fields come from the contract evaluation when one ran. Request redaction fields describe an actual rewrite. Retain the snapshot for an outcome. |
| CONNECT tunnel | tunnel_open | Use the policy selected for the connection before dialing. An outcome observes the tunnel operation; a pre-connection denial has no releasing effect. |
| HTTP response, Browser Shield, and SSE delivery | downstream_delivery | Retain request policy. Add response checker or normalization evidence only when the relevant check ran. The shield summary describes the processing or coverage of the response being delivered. |
| WebSocket upgrade and frames | upstream_send for an upgrade or upstream frame; downstream_delivery for a client frame | Use the snapshot for the upgrade or relay decision that gated the effect. Populate scanner attribution only from that direction's actual assessment. |
| MCP tool send over stdio, HTTP or WebSocket | upstream_send | Use the captured tool decision policy, session and taint if available, and contract attribution if evaluated. Only a verified MCP door identity supplies caller fields. |
| MCP result, tool discovery, and streamed response | downstream_delivery | Use the actual response decision and its checker and normalization attribution. Discovery may have already contacted the upstream. Its gated release is delivery to the client. |
| Dispatch of an MCP redirect | redirect_dispatch | Use the snapshot that approved dispatch, and the rechecked destination as target. |
| Approval exposure and settlement | approval_prompt | Preserve stable hold identity, policy and the recorded effect relation. Native approval asks use approval_api. Recovery uses the recorded context, and may not take decision attribution from the configuration loaded at recovery. |
| Hook decision | hook_execution | A completed decision may have policy or checker evidence from the hook invocation. Host-prompt ask describes an instruction to the host, with no answer or display claim. |
| Refusal before a covered effect | none | Bind the refusal to the request or decision context available at the point of refusal. Omit absent optional values, use caller authn none without verified identity, and use unavailable for an absent policy snapshot. |

For a checker disposition, map an affirmative assessment to passed, a finding to flagged, failed or incomplete assessment to error, and disabled or unexecuted assessment to not_run. Watch-only assessments do not replace the checker that decided delivery. The checker configuration digest is captured with the effective checker policy at decision time. A later reload cannot supply it.

A production text-normalization profile must resolve from a digest-keyed registry of exact profile documents. Hash the exact published profile document bytes. Provenance replay transforms have their own profile documents and digests; they must not be substituted for a live normalization profile. A verifier that cannot resolve a production profile reports the unresolved binding.

The existing hook protocol with a nested permission decision emits allow or deny, or uses exit status for denial. The protocol with a top-level permission member forwards the decision outcome. The v3 ask vocabulary does not assign new values to either hook protocol.
