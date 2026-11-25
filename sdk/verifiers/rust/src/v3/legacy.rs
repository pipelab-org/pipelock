// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    io::{self, BufRead, BufReader, Read},
    path::{Path, PathBuf},
};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    canonical::{canonicalize_action_record, canonicalize_jcs_value},
    chain::{evidence_chain_key, verify_chain_with_options},
    chain_set::{
        parse_evidence_filename, read_session_evidence,
        resolve_base_sessions_excluding_receipt_groups, run_session_base, verify_base,
        verify_base_excluding_receipt_groups, with_recorder_file_exclusions, with_session_files,
        BaseVerifyOptions, SessionReadError,
    },
    lifecycle::close_ends_chain,
    rawjson::{go_raw_message_bytes, object_member_span, EXT_SOURCE_KEY},
    receipt_group::{verify_receipt_groups_for_cutover, ReceiptGroupReport},
    recorder::{
        extract_typed_from_lines, read_entry_lines_text, ExtractedReceipts, MAX_RECORDER_LINE_BYTES,
    },
    recorder_chain::recorder_entry_hash,
    types::Receipt,
    util::{metadata_identity, parse_json_line, reject_duplicate_keys, Result, VerifierError},
};

use super::{
    digest, input_error, is_digest, lower_hex, name, open,
    result::{Document, LegacyRow, PREFIX},
    wire::parse_payload,
    Discovery, Verifier, MAX_INTEGER,
};

const ACTION: &str = "action_v1";
const EVIDENCE: &str = "evidence_v2";
const GROUP: &str = "receipt_group";
const EVIDENCE_RECORD: &str = "evidence_receipt_v2";
const EMPTY_INVENTORY: &[u8] = b"{\"chains\":[],\"v\":1}";

pub(super) fn candidate(name: &str) -> bool {
    parse_evidence_filename(name).is_some()
        || group_artifact(name)
        || matches!(
            name,
            "activation-receipts.jsonl"
                | "redaction-receipts.jsonl"
                | "ratification-receipts.jsonl"
        )
}

fn group_artifact(name: &str) -> bool {
    name.starts_with("receipt-group-") && name.ends_with(".json")
}

pub(super) fn inventory_id(name: &str) -> Option<String> {
    let hex = name
        .strip_prefix("receipt-v3-cutover-")?
        .strip_suffix(".json")?;
    lower_hex(hex, 64).then(|| format!("sha256:{hex}"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryRow {
    chain: String,
    format: String,
    record: String,
    seq: u64,
}

impl InventoryRow {
    fn valid(&self) -> bool {
        self.seq <= MAX_INTEGER
            && is_digest(&self.record)
            && match self.format.as_str() {
                ACTION => lower_hex(&self.chain, 32) || is_digest(&self.chain),
                EVIDENCE => is_digest(&self.chain),
                GROUP => lower_hex(&self.chain, 32),
                _ => false,
            }
    }
}

#[derive(Default)]
struct Presented {
    head: String,
    seq: u64,
    order: u64,
    invalid: bool,
    forked: bool,
    rotated: bool,
    end_unproven: bool,
    group_verdict: String,
    positions: BTreeMap<u64, String>,
}

impl Presented {
    fn compare_cutover_position(&self, row: &InventoryRow) -> Ordering {
        if self.head != row.record && !self.forked {
            if self
                .positions
                .range(..self.order)
                .any(|(_, hash)| hash == &row.record)
            {
                return Ordering::Greater;
            }
            // A key rotation resets signed action sequences, so only a chain
            // that crossed one cannot be ordered by them. Without a rotation a
            // pin beyond the presented tail is truncation; a pin at or before
            // it that the chain never recorded is a different head.
            if row.format == ACTION && (self.rotated || self.seq >= row.seq) {
                return Ordering::Equal;
            }
        }
        self.seq.cmp(&row.seq)
    }
}

/// Identity of every presented shard of `session`, as it is before the read.
fn session_stamps(paths: &[PathBuf], session: &str) -> Vec<(PathBuf, String)> {
    paths
        .iter()
        .filter(|path| {
            parse_evidence_filename(&name(path)).is_some_and(|(found, _)| found == session)
        })
        .map(|path| (path.clone(), file_stamp(path)))
        .collect()
}

fn file_stamp(path: &Path) -> String {
    std::fs::symlink_metadata(path).map_or_else(
        |_| String::new(),
        |metadata| {
            format!(
                "{:?}:{}:{:?}:{:?}",
                metadata_identity(&metadata),
                metadata.len(),
                metadata.modified().ok(),
                metadata.file_type()
            )
        },
    )
}

fn stamps_unchanged(stamps: &[(PathBuf, String)]) -> bool {
    stamps
        .iter()
        .all(|(path, stamp)| !stamp.is_empty() && file_stamp(path) == *stamp)
}

type Legacy = BTreeMap<(&'static str, String), Presented>;
type CutoverEnds = BTreeMap<String, String>;

impl Verifier<'_> {
    pub(super) fn verify_cutover(&mut self, found: &Discovery) -> Result<CutoverEnds> {
        let excluded = if self.options.directory {
            found
                .files
                .iter()
                .map(|file| name(&file.path).into_owned())
                .collect()
        } else {
            BTreeSet::new()
        };
        let legacy = with_recorder_file_exclusions(excluded, || self.verify_legacy(&found.old))?;
        let mut unproven = BTreeMap::new();
        if found.files.is_empty() {
            return Ok(unproven);
        }
        if !legacy.is_empty() && !self.options.directory {
            return Err(input_error(
                "old-format and v3 evidence require directory scope; verify the directory",
            ));
        }
        let mut checked = BTreeSet::new();
        let mut known = self.membership_known()?;
        let mut listed = BTreeSet::new();
        for (id, stream) in &self.streams {
            let Some(pin) = stream
                .body
                .as_ref()
                .and_then(|body| body.legacy_cutover.as_ref())
            else {
                continue;
            };
            let origin = stream.open.as_ref().unwrap();
            checked.insert(pin.inventory.as_str());
            let paths = found.inventories.get(&pin.inventory);
            let copies: Vec<_> = paths.map_or_else(
                || vec![None],
                |paths| paths.iter().map(|p| Some(p.as_path())).collect(),
            );
            let mut inventory = None;
            for copy in copies {
                match read_inventory(copy, &pin.inventory, Some(pin.chains))? {
                    Ok(rows) => inventory = Some(rows),
                    Err(code) => self.doc.add_record(code, origin),
                }
            }
            let Some(inventory) = inventory else {
                known = false;
                continue;
            };
            for row in inventory {
                let format = match row.format.as_str() {
                    ACTION => ACTION,
                    EVIDENCE => EVIDENCE,
                    _ => GROUP,
                };
                let key = (format, row.chain.clone());
                let actual = legacy.get(&key);
                listed.insert(key);
                let Some(actual) = actual else {
                    self.doc.add_record("LEGACY_CHAIN_NOT_PRESENTED", origin);
                    continue;
                };
                match actual.compare_cutover_position(&row) {
                    Ordering::Greater => {
                        self.doc.add_record("LEGACY_EXTENDED_AFTER_CUTOVER", origin);
                    }
                    Ordering::Less => self.doc.add_record("LEGACY_CHAIN_TRUNCATED", origin),
                    Ordering::Equal if actual.forked || actual.head != row.record => {
                        self.doc.add_record("LEGACY_CHAIN_HEAD_MISMATCH", origin);
                    }
                    Ordering::Equal if actual.end_unproven && !actual.invalid => {
                        unproven.insert(origin.id.clone(), id.clone());
                    }
                    Ordering::Equal => {}
                }
            }
        }
        for (id, copies) in &found.inventories {
            if !checked.contains(id.as_str()) {
                for copy in copies {
                    if let Err(code) = read_inventory(Some(copy), id, None)? {
                        self.doc.add_code(code, "");
                    }
                }
            }
        }
        if legacy.keys().any(|key| !listed.contains(key)) {
            self.doc.add_code(
                if known {
                    "LEGACY_CHAIN_UNLISTED"
                } else {
                    "LEGACY_MEMBERSHIP_UNKNOWN"
                },
                "",
            );
        }
        Ok(unproven)
    }

    fn verify_legacy(&mut self, paths: &[PathBuf]) -> Result<Legacy> {
        let mut presented = Legacy::new();
        let mut sessions = BTreeMap::new();
        let mut dirs = BTreeMap::new();
        let keys = self.options.keys.join(",");
        for path in paths {
            if self.options.directory {
                let dir = path.parent().expect("discovered directory");
                dirs.insert(dir, false);
                if group_artifact(&name(path)) {
                    continue;
                }
                if let Some((session, _)) = parse_evidence_filename(&name(path)) {
                    sessions.insert(session, dir);
                    continue;
                }
            }
            match read_legacy(path) {
                Ok((batch, recorder)) => {
                    if batch.action.is_empty() && batch.evidence.is_empty() {
                        if recorder && self.options.directory {
                            self.doc.ignored += 1;
                        } else {
                            self.doc.add_code("UNRECOGNIZED_FILE", "");
                        }
                    } else {
                        self.legacy_batch(&mut presented, &keys, batch, recorder);
                    }
                }
                Err(error) => record_read_failure(&mut self.doc, "", unavailable(&error)),
            }
        }
        for (dir, grouped) in &mut dirs {
            let result = verify_receipt_groups_for_cutover(dir, &self.options.keys, |report| {
                add_group(&mut presented, &mut self.doc, report);
                Ok(())
            });
            *grouped = match result {
                Ok(summary) => summary.groups != 0,

                Err(error) => {
                    let incomplete = unavailable(&error);
                    self.doc.add_code(
                        if incomplete {
                            "LEGACY_GROUP_INCOMPLETE"
                        } else {
                            "LEGACY_INVALID"
                        },
                        "",
                    );
                    self.doc.legacy.push(LegacyRow {
                        format: GROUP,
                        chain: String::new(),
                        class: "failure",
                        verdict: if incomplete {
                            "GROUP_INCOMPLETE"
                        } else {
                            "GROUP_INVALID"
                        }
                        .into(),
                    });
                    true
                }
            };
        }
        let mut ordinary = BTreeMap::new();
        let mut bare_stamps: Vec<(PathBuf, String)> = Vec::new();
        let mut bases = BTreeMap::new();
        for (session, dir) in sessions {
            let base = run_session_base(&session).unwrap_or(&session);
            if dirs[dir] {
                let ordinary = match ordinary.entry((dir, base.to_owned())) {
                    std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::btree_map::Entry::Vacant(e) => e.insert(
                        resolve_base_sessions_excluding_receipt_groups(dir, base).map_err(|e| {
                            input_error(format!("list legacy receipt sessions: {e}"))
                        })?,
                    ),
                };
                if ordinary.binary_search(&session).is_err() {
                    continue;
                }
            }
            if run_session_base(&session).is_some() {
                bases.insert(base.to_owned(), dir);
            }
            // Bind a wrapper's exclusion to the files as they were before the read.
            let stamps = session_stamps(paths, &session);
            let batch = read_bare_session(dir, &session).and_then(|bare| {
                if let Some(batch) = bare {
                    bare_stamps.extend(stamps);
                    Ok((None, batch))
                } else {
                    read_session_evidence(dir, &session)
                }
            });
            match batch {
                Ok((None, batch)) if batch.action.is_empty() && batch.evidence.is_empty() => {
                    self.doc.ignored += 1
                }
                Ok((None, batch)) => self.legacy_batch(&mut presented, &keys, batch, true),
                Ok((Some(_), _)) => record_read_failure(&mut self.doc, &session, false),
                Err(err) => record_read_failure(
                    &mut self.doc,
                    &session,
                    !err.refused && is_unavailable_message(&err.message),
                ),
            }
        }
        let legacy_opts = BaseVerifyOptions {
            trusted_keys: self.options.keys.clone(),
            endorsements: Vec::new(),
        };
        let bare_names = bare_stamps
            .iter()
            .map(|(path, _)| name(path).into_owned())
            .collect::<BTreeSet<_>>();
        // A wrapper shard stays excluded only while it is the file that was
        // read; a replacement under the same name is a change, not a pass.
        let settled = || stamps_unchanged(&bare_stamps);
        for (base, dir) in bases {
            let verify = if dirs[dir] {
                verify_base_excluding_receipt_groups
            } else {
                verify_base
            };
            let checked = settled().then(|| {
                with_recorder_file_exclusions(bare_names.clone(), || {
                    verify(dir, &base, &legacy_opts)
                })
            });
            let changed = checked.is_none() || !settled();
            if !changed
                && checked
                    .as_ref()
                    .is_some_and(|result| result.as_ref().is_ok_and(|report| report.healthy()))
            {
                continue;
            }
            self.doc.add_code("LEGACY_INVALID", "");
            self.doc.legacy.push(LegacyRow {
                format: ACTION,
                chain: base,
                class: "failure",
                verdict: if changed || checked.is_some_and(|result| result.is_err()) {
                    "RESTART CONTINUITY INCOMPLETE"
                } else {
                    "RESTART CONTINUITY FAILED"
                }
                .into(),
            });
        }
        for ((format, chain), item) in &presented {
            let (class, verdict) = if *format == GROUP {
                (
                    if item.group_verdict == "GROUP_VALID" {
                        "pass"
                    } else {
                        "failure"
                    },
                    item.group_verdict.clone(),
                )
            } else {
                let label = if *format == ACTION {
                    "CHAIN"
                } else {
                    "EVIDENCE CHAIN"
                };
                let permitted_unpinned = !keys.is_empty() || self.options.allow_unpinned;
                if item.invalid || item.forked {
                    ("failure", format!("{label} BROKEN"))
                } else if item.end_unproven {
                    (
                        if self.options.allow_prefix && permitted_unpinned {
                            "pass"
                        } else {
                            "failure"
                        },
                        PREFIX.into(),
                    )
                } else if keys.is_empty() {
                    (
                        if permitted_unpinned {
                            "pass"
                        } else {
                            "failure"
                        },
                        format!("{label} UNPINNED"),
                    )
                } else {
                    ("pass", format!("{label} VALID"))
                }
            };
            self.doc.legacy.push(LegacyRow {
                format,
                chain: chain.clone(),
                class,
                verdict,
            });
        }
        Ok(presented)
    }

    fn legacy_batch(
        &mut self,
        presented: &mut Legacy,
        keys: &str,
        batch: ExtractedReceipts,
        recorder: bool,
    ) {
        for (format, records) in [
            (ACTION, batch.action.as_slice()),
            (EVIDENCE, batch.evidence.as_slice()),
        ] {
            let mut remaining = records;
            while !remaining.is_empty() {
                let n = if recorder {
                    remaining.len()
                } else {
                    remaining
                        .iter()
                        .enumerate()
                        .skip(1)
                        .find_map(|(i, item)| {
                            let genesis = chain_seq(item, format) == 0;
                            let rotation = format == ACTION
                                && !item["action_record"]["key_transition"].is_null();
                            (genesis && !rotation).then_some(i)
                        })
                        .unwrap_or(remaining.len())
                };
                let chain = &remaining[..n];
                remaining = &remaining[n..];
                self.legacy_chain(presented, keys, chain, format);
            }
        }
    }

    fn legacy_chain(
        &mut self,
        presented: &mut Legacy,
        keys: &str,
        chain: &[Receipt],
        format: &'static str,
    ) {
        let first = &chain[0];
        let nonce = first["action_record"]["run_nonce"]
            .as_str()
            .filter(|nonce| !nonce.is_empty());
        let id = nonce.map_or_else(|| chain_hash(first, format), str::to_owned);
        let item = presented.entry((format, id)).or_default();
        let mut last = String::new();
        for (index, receipt) in chain.iter().enumerate() {
            let signer = if format == ACTION {
                &receipt["signer_key"]
            } else {
                &receipt["signature"]["signer_key_id"]
            };
            if let Some(raw) = signer
                .as_str()
                .and_then(|key| hex::decode(key).ok())
                .filter(|raw| raw.len() == 32)
            {
                self.used.insert(digest(&raw));
            }
            let hash = chain_hash(receipt, format);
            let position = if format == ACTION {
                index as u64
            } else {
                chain_seq(receipt, format)
            };
            if position > MAX_INTEGER {
                item.forked = true;
            } else if let Some(prior) = item.positions.insert(position, hash.clone()) {
                item.forked |= prior != hash;
            }
            last = hash;
        }
        let seq = chain_seq(chain.last().unwrap(), format);
        let order = if format == ACTION {
            chain.len() as u64 - 1
        } else {
            seq
        };
        if order > MAX_INTEGER || seq > MAX_INTEGER {
            self.doc.add_code("LEGACY_INVALID", "");
            return;
        }
        let key = if format == EVIDENCE {
            evidence_chain_key(keys, chain)
        } else {
            keys.into()
        };
        let valid = verify_chain_with_options(chain, &key, keys.is_empty()).valid;
        if !valid {
            self.doc.add_code("LEGACY_INVALID", "");
            item.invalid = true;
        }
        if item.head.is_empty() || order > item.order {
            item.head = last;
            item.seq = seq;
            item.order = order;
            item.rotated = format == ACTION
                && chain
                    .iter()
                    .any(|receipt| !receipt["action_record"]["key_transition"].is_null());
            item.end_unproven = format == EVIDENCE || !close_ends_chain(chain);
        }
    }
}

fn read_bare_session(
    dir: &Path,
    session: &str,
) -> std::result::Result<Option<ExtractedReceipts>, SessionReadError> {
    with_session_files(dir, session, |paths| {
        read_bare_files(paths).map_err(|err| SessionReadError::from(err.to_string()))
    })
}

fn read_bare_files(paths: &[PathBuf]) -> Result<Option<ExtractedReceipts>> {
    // Go's bare-session discriminator scans at most 10 MiB per wrapper.
    const BARE_LINE_BYTES: u64 = 10 << 20;
    let mut batch = ExtractedReceipts::default();
    let mut line = Vec::new();
    for path in paths {
        let mut reader = BufReader::new(open(path)?);
        loop {
            line.clear();
            let size = reader
                .by_ref()
                .take(BARE_LINE_BYTES)
                .read_until(b'\n', &mut line)
                .map_err(|e| crate::util::io_read_error(path, e))?;
            if size == 0 {
                break;
            }
            if size as u64 == BARE_LINE_BYTES && line.last() != Some(&b'\n') {
                return Err(VerifierError::Invalid(
                    "bare evidence line exceeds 10 MiB".into(),
                ));
            }
            let Ok(text) = std::str::from_utf8(&line) else {
                return Ok(None);
            };
            let text = crate::line_space::trim_go_space(text);
            if text.is_empty() {
                continue;
            }
            let Ok(mut value) = serde_json::from_str::<Value>(text) else {
                return Ok(None);
            };
            if value.as_object().is_none_or(|object| object.len() != 2)
                || value["type"] != "evidence_receipt"
                || !value["detail"].is_object()
                || reject_duplicate_keys(text).is_err()
            {
                return Ok(None);
            }
            let (start, end) = object_member_span(text, 0, "detail").expect("parsed detail span");
            let detail = value["detail"].take();
            crate::secret_egress::validate_raw_receipt(&detail, &text[start..end])
                .map_err(VerifierError::Invalid)?;
            batch.evidence.push(detail);
        }
    }
    Ok((!batch.evidence.is_empty()).then_some(batch))
}

fn record_read_failure(doc: &mut Document, chain: &str, unavailable: bool) {
    doc.add_code("LEGACY_INVALID", "");
    doc.legacy.push(LegacyRow {
        format: ACTION,
        chain: chain.into(),
        class: "failure",
        verdict: if unavailable {
            "CHAIN UNAVAILABLE"
        } else {
            "CHAIN BROKEN"
        }
        .into(),
    });
}

fn is_unavailable_message(message: &str) -> bool {
    message.contains("evidence changed during verification")
        || message.contains("evidence read unavailable")
        || message.contains("Permission denied")
}

fn unavailable(error: &VerifierError) -> bool {
    matches!(error, VerifierError::Unavailable(_))
}

fn add_group(presented: &mut Legacy, doc: &mut Document, report: ReceiptGroupReport) {
    match report.verdict.as_str() {
        "GROUP_VALID" => {}
        "GROUP_INCOMPLETE" => doc.add_code("LEGACY_GROUP_INCOMPLETE", ""),
        _ => doc.add_code("LEGACY_INVALID", ""),
    }
    let head = report
        .close_manifest_sha256
        .or(report.open_manifest_sha256)
        .map(|hex| format!("sha256:{hex}"))
        .unwrap_or_default();
    presented.insert(
        (GROUP, report.group_id),
        Presented {
            head,
            seq: report.shard_count as u64,
            group_verdict: report.verdict,
            ..Presented::default()
        },
    );
}

fn chain_seq(receipt: &Receipt, format: &str) -> u64 {
    if format == ACTION {
        &receipt["action_record"]["chain_seq"]
    } else {
        &receipt["chain_seq"]
    }
    .as_u64()
    .unwrap_or_default()
}

fn chain_hash(receipt: &Receipt, format: &str) -> String {
    if format == ACTION {
        digest(&canonicalize_action_record(&receipt["action_record"]))
    } else {
        canonicalize_jcs_value(receipt).map_or_else(|_| "sha256:".into(), |bytes| digest(&bytes))
    }
}

#[derive(PartialEq, Eq)]
enum Mode {
    Action,
    Evidence,
    Recorder,
}

fn read_legacy(path: &Path) -> Result<(ExtractedReceipts, bool)> {
    let mut reader = BufReader::new(open(path)?);
    let mut batch = ExtractedReceipts::default();
    let mut line = Vec::new();
    let mut mode = None;
    let mut prior = None::<(u64, String, String)>;
    let parsed_name = parse_evidence_filename(&name(path));
    while reader
        .by_ref()
        .take((MAX_RECORDER_LINE_BYTES + 3) as u64)
        .read_until(b'\n', &mut line)
        .map_err(|e| crate::util::io_read_error(path, e))?
        != 0
    {
        let payload = line.strip_suffix(b"\n").map_or(line.as_slice(), |payload| {
            payload.strip_suffix(b"\r").unwrap_or(payload)
        });
        if payload.len() > MAX_RECORDER_LINE_BYTES {
            return Err(VerifierError::Invalid(
                "line exceeds recorder entry limit".into(),
            ));
        }
        let text = std::str::from_utf8(payload)
            .map_err(|err| VerifierError::Invalid(format!("input is not UTF-8: {err}")))?;
        let text = crate::line_space::trim_go_space(text);
        if !text.is_empty() {
            let value = parse_json_line(text, "read legacy discriminator")?;
            let kind = if value["record_type"] == EVIDENCE_RECORD {
                Mode::Evidence
            } else if absent_text(&value["record_type"])
                && value["version"] == 1
                && absent_text(&value["type"])
            {
                Mode::Action
            } else if !absent_text(&value["type"]) && !absent_text(&value["session_id"]) {
                Mode::Recorder
            } else if mode.is_none() {
                return Ok((ExtractedReceipts::default(), false));
            } else {
                return Err(VerifierError::Invalid(
                    "malformed or mixed legacy record".into(),
                ));
            };
            if mode.as_ref().is_some_and(|mode| *mode != kind) {
                return Err(VerifierError::Invalid(
                    "malformed or mixed legacy record".into(),
                ));
            }
            reject_duplicate_keys(text)?;
            match kind {
                Mode::Action => batch.action.push(bare_action(value, text)?),
                Mode::Evidence => {
                    crate::secret_egress::validate_raw_receipt(&value, text)
                        .map_err(VerifierError::Invalid)?;
                    batch.evidence.push(value);
                }
                Mode::Recorder => {
                    let lines = read_entry_lines_text(text)?;
                    let entry = &lines[0].entry;
                    let session = entry["session_id"].as_str().unwrap_or_default();
                    let seq = entry["seq"].as_u64().unwrap_or_default();
                    let hash = recorder_entry_hash(text).map_err(VerifierError::Invalid)?;
                    let prev = entry["prev_hash"].as_str().unwrap_or_default();
                    let invalid = entry["hash"] != hash
                        || parsed_name.as_ref().is_some_and(|(id, start)| {
                            id != session || (prior.is_none() && *start != seq)
                        })
                        || match &prior {
                            Some((prior_seq, prior_session, prior_hash)) => {
                                prior_seq.checked_add(1) != Some(seq)
                                    || prior_session != session
                                    || prior_hash != prev
                            }
                            None => seq == 0 && prev != "genesis",
                        };
                    if invalid {
                        return Err(VerifierError::Invalid(
                            "recorder entry has invalid sequence or hash".into(),
                        ));
                    }
                    prior = Some((seq, session.into(), hash));
                    // Operational entries have no legacy receipt payload.
                    if matches!(
                        entry["type"].as_str(),
                        Some("action_receipt" | "evidence_receipt")
                    ) {
                        let typed = extract_typed_from_lines(lines)?;
                        batch.action.extend(typed.action);
                        batch.evidence.extend(typed.evidence);
                    }
                }
            }
            mode = Some(kind);
        }
        line.clear();
    }
    Ok((batch, mode == Some(Mode::Recorder)))
}

fn absent_text(value: &Value) -> bool {
    value.as_str().is_none_or(str::is_empty)
}

fn bare_action(mut value: Value, raw: &str) -> Result<Receipt> {
    crate::strict::validate_v1_receipt(&value)?;
    if let Some((start, end)) = object_member_span(raw, 0, "ext") {
        value.as_object_mut().unwrap().insert(
            EXT_SOURCE_KEY.into(),
            Value::String(go_raw_message_bytes(&raw[start..end])),
        );
    }
    Ok(value)
}

struct HashReader<R> {
    input: R,
    hash: Sha256,
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let length = self.input.read(bytes)?;
        self.hash.update(&bytes[..length]);
        Ok(length)
    }
}

fn read_inventory(
    path: Option<&Path>,
    id: &str,
    count: Option<u64>,
) -> Result<std::result::Result<Vec<InventoryRow>, &'static str>> {
    const MISMATCH: &str = "CUTOVER_INVENTORY_MISMATCH";
    let Some(path) = path else {
        return Ok(if id != digest(EMPTY_INVENTORY) {
            Err("CUTOVER_INVENTORY_NOT_PRESENTED")
        } else if count.is_some_and(|n| n > 0) {
            Err(MISMATCH)
        } else {
            Ok(Vec::new())
        });
    };
    let mut reader = BufReader::new(HashReader {
        input: open(path)?,
        hash: Sha256::new(),
    });
    let rows = decode_inventory(&mut reader, count)
        .map_err(|e| input_error(format!("read cutover inventory: {e}")))?;
    if id.strip_prefix("sha256:") != Some(&hex::encode(reader.into_inner().hash.finalize())) {
        return Ok(Err(MISMATCH));
    }
    Ok(rows.ok_or(MISMATCH))
}

fn decode_inventory(
    reader: &mut impl BufRead,
    count: Option<u64>,
) -> io::Result<Option<Vec<InventoryRow>>> {
    let mut rows: Vec<InventoryRow> = Vec::new();
    if !consume(reader, b"{\"chains\":[")? {
        return Ok(None);
    }
    while reader.fill_buf()?.first() != Some(&b']') {
        if count.is_some_and(|count| rows.len() as u64 >= count) {
            return Ok(None);
        }
        if !rows.is_empty() && !consume(reader, b",")? {
            return Ok(None);
        }
        // Every valid row fits in this bound from its four fixed fields,
        // two 71-byte digests, the format label, and a wire integer.
        let mut raw = Vec::new();
        reader.take(256).read_until(b'}', &mut raw)?;
        if parse_payload(&raw).is_none_or(|(_, tail)| !tail.is_empty()) {
            return Ok(None);
        }
        let Ok(row) = serde_json::from_slice::<InventoryRow>(&raw) else {
            return Ok(None);
        };
        if !row.valid()
            || rows
                .last()
                .is_some_and(|last| (&last.format, &last.chain) >= (&row.format, &row.chain))
        {
            return Ok(None);
        }
        rows.push(row);
    }
    if count.is_some_and(|count| rows.len() as u64 != count) || !consume(reader, b"],\"")? {
        return Ok(None);
    }
    if reader.fill_buf()?.first() == Some(&b'j') {
        if !consume(reader, b"journal\":\"")? {
            return Ok(None);
        }
        let mut journal = [0; 71];
        if !read_exact(reader, &mut journal)?
            || !std::str::from_utf8(&journal).is_ok_and(is_digest)
            || !consume(reader, b"\",\"")?
        {
            return Ok(None);
        }
    }
    Ok((consume(reader, b"v\":1}")? && reader.fill_buf()?.is_empty()).then_some(rows))
}

fn read_exact(reader: &mut impl Read, input: &mut [u8]) -> io::Result<bool> {
    match reader.read_exact(input) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(err) => Err(err),
    }
}

fn consume(reader: &mut impl Read, literal: &[u8]) -> io::Result<bool> {
    let mut bytes = [0; 16];
    let bytes = &mut bytes[..literal.len()];
    Ok(read_exact(reader, bytes)? && bytes == literal)
}

#[cfg(test)]
mod tests {
    use super::{decode_inventory, digest, session_stamps, stamps_unchanged, EMPTY_INVENTORY};

    #[test]
    fn rejects_oversized_unterminated_legacy_line() {
        let path =
            std::env::temp_dir().join(format!("pipelock-v3-legacy-line-{}", std::process::id()));
        std::fs::write(&path, vec![b' '; (1 << 20) + 1]).unwrap();
        let result = super::read_legacy(&path);
        std::fs::remove_file(path).unwrap();
        assert!(matches!(result, Err(err) if err.to_string().contains("recorder entry limit")));
    }

    #[test]
    fn rejects_inventories_with_invalid_rows_order_and_shape() {
        let id = digest(EMPTY_INVENTORY);
        let row = format!(
            "{{\"chain\":\"{id}\",\"format\":\"evidence_v2\",\"record\":\"{id}\",\"seq\":0}}"
        );
        let good = format!("{{\"chains\":[{row}],\"journal\":\"{id}\",\"v\":1}}");
        assert_eq!(
            decode_inventory(&mut good.as_bytes(), Some(1))
                .unwrap()
                .unwrap()
                .len(),
            1
        );
        for (text, count) in [
            ("{}".into(), None),
            (format!("{{\"chains\":[{row}],\"v\":1}}"), Some(0)),
            (
                String::from_utf8_lossy(EMPTY_INVENTORY).into_owned(),
                Some(1),
            ),
            (format!("{{\"chains\":[{row},{row}],\"v\":1}}"), None),
            (format!("{{\"chains\":[{row} {row}],\"v\":1}}"), None),
            (
                format!(
                    "{{\"chains\":[{}],\"v\":1}}",
                    row.replace("evidence_v2", "unsupported")
                ),
                None,
            ),
            (
                format!("{{\"chains\":[{row}],\"journal\":\"wrong\",\"v\":1}}"),
                None,
            ),
            ("{\"chains\":[],\"junk\":\"sha256:\"}".into(), None),
            ("{\"chains\":[{\"seq\":-0}],\"v\":1}".into(), None),
            ("{\"chains\":[],\"v\":1}\n".into(), None),
        ] {
            assert!(
                decode_inventory(&mut text.as_bytes(), count)
                    .unwrap()
                    .is_none(),
                "{text}"
            );
        }
    }

    #[test]
    fn bare_wrapper_exclusion_follows_the_file_that_was_read() {
        let dir = std::env::temp_dir().join(format!("pipelock-bare-stamp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let session = "example.run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let path = dir.join(format!("evidence-{session}-0.jsonl"));
        std::fs::write(&path, b"wrapper\n").unwrap();
        let paths = [path.clone(), dir.join("unrelated.jsonl")];
        let stamps = session_stamps(&paths, session);
        assert_eq!(stamps.len(), 1);
        assert!(stamps_unchanged(&stamps), "a file nobody touched changed");
        let replacement = dir.join("replacement");
        std::fs::write(&replacement, b"ordinary shard\n").unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert!(
            !stamps_unchanged(&stamps),
            "a same-name replacement kept the wrapper's exclusion"
        );
        std::fs::remove_file(&path).unwrap();
        assert!(
            !stamps_unchanged(&stamps),
            "a removed wrapper kept its exclusion"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
