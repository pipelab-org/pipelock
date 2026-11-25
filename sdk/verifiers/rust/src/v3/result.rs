// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::{json, Value};

use super::{registry, wire::Record, Options, Position};

pub(super) const PREFIX: &str = "VALID PREFIX, END UNPROVEN";

/// A full receipt v3 verification document and its conformance projection.
pub struct VerificationResult {
    result: Vec<u8>,
    projection: Vec<u8>,
    exit_code: i32,
}

impl VerificationResult {
    /// RFC 8785 verification document, without a trailing LF.
    pub fn json(&self) -> &[u8] {
        &self.result
    }

    /// RFC 8785 normative projection, without a trailing LF.
    pub fn projection(&self) -> &[u8] {
        &self.projection
    }

    /// The verification exit code.
    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }
}

#[derive(Serialize)]
pub(super) struct Finding {
    class: &'static str,
    code: &'static str,
    #[serde(skip_serializing_if = "str::is_empty")]
    stream: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
    #[serde(skip_serializing_if = "str::is_empty")]
    record: String,
}

#[derive(Clone, Default, Serialize)]
pub(super) struct Summary {
    pub end: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<Position>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    pub records: u64,
    pub signer: String,
    pub stream: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip: Option<Position>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unconfirmed_from: Option<u64>,
}

#[derive(Serialize)]
pub(super) struct History {
    pub lineage: String,
    pub streams: Vec<Summary>,
}

#[derive(Serialize)]
pub(super) struct Contested {
    pub records: Vec<String>,
    pub stream: String,
}

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct LegacyRow {
    pub format: &'static str,
    pub chain: String,
    pub verdict: String,
    pub class: &'static str,
}

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Acceptance {
    kind: &'static str,
    value: String,
}

pub(super) struct Document {
    accepted: Vec<Acceptance>,
    pub counts: Value,
    pub contested: Vec<Contested>,
    pub findings: Vec<Finding>,
    pub histories: Vec<History>,
    pub ignored: usize,
    pub legacy: Vec<LegacyRow>,
    pub limits: BTreeSet<&'static str>,
    mode: &'static str,
    trust_state: &'static str,
}

pub(super) fn class(code: &str) -> &'static str {
    registry()["findings"][code]
        .as_str()
        .expect("registered finding")
}

impl Document {
    pub(super) fn new(options: &Options, ignored: usize) -> Self {
        let (mode, trust_state) = if options.keys.is_empty() {
            ("unpinned", "unpinned")
        } else {
            ("pinned_keys", "pinned")
        };
        Self {
            accepted: Vec::new(),
            counts: Value::Null,
            contested: Vec::new(),
            findings: Vec::new(),
            histories: Vec::new(),
            ignored,
            legacy: Vec::new(),
            limits: BTreeSet::from(["L-FSYNC-ERROR-REOPEN", "L-FSYNC-HONESTY"]),
            mode,
            trust_state,
        }
    }

    pub(super) fn add_code(&mut self, code: &'static str, stream: &str) {
        self.findings.push(Finding {
            class: class(code),
            code,
            stream: stream.into(),
            seq: None,
            record: String::new(),
        });
    }

    pub(super) fn add_record(&mut self, code: &'static str, r: &Record) {
        self.findings.push(Finding {
            class: class(code),
            code,
            stream: r.stream.clone(),
            seq: Some(r.seq),
            record: r.id.clone(),
        });
    }

    pub(super) fn accept(&mut self, kind: &'static str, value: impl Into<String>, satisfied: bool) {
        if satisfied {
            self.accepted.push(Acceptance {
                kind,
                value: value.into(),
            });
        } else {
            self.add_code("EXPECTATION_NOT_MET", "");
        }
    }

    fn accepted_finding(&self, finding: &Finding) -> bool {
        let (kind, value) = match finding.code {
            "PREDECESSOR_NOT_PRESENTED" => ("allow-partial-history", &finding.stream),
            "LEGACY_END_UNPROVEN" => ("accept-discontinuity", &finding.record),
            _ => return false,
        };
        self.accepted
            .binary_search_by(|a| (a.kind, a.value.as_str()).cmp(&(kind, value.as_str())))
            .is_ok()
    }

    pub(super) fn finish(
        mut self,
        options: &Options,
        used: BTreeSet<String>,
    ) -> VerificationResult {
        fn sort_key(f: &Finding) -> (&str, &str, Option<u64>, &str) {
            (f.code, &f.stream, f.seq, &f.record)
        }
        self.findings.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
        self.findings.dedup_by(|a, b| sort_key(a) == sort_key(b));
        self.accepted.sort();
        self.accepted.dedup();
        self.legacy.sort();

        let classes: BTreeSet<_> = self
            .findings
            .iter()
            .filter(|f| !self.accepted_finding(f))
            .map(|f| f.class)
            .collect();
        let (invalid, unsupported, incomplete, end) = (
            classes.contains("invalid"),
            classes.contains("unsupported"),
            classes.contains("incomplete"),
            classes.contains("end_unproven"),
        );
        let integrity = if invalid { "failed" } else { "ok" };
        let completeness = if incomplete {
            "incomplete"
        } else if end {
            "end_unproven"
        } else {
            "complete"
        };
        if self.counts["scope"] == "full_history" {
            self.counts["complete"] = json!(!(invalid || unsupported || incomplete));
        }
        let unpinned = options.keys.is_empty();
        let gaps = self
            .accepted
            .iter()
            .any(|a| matches!(a.kind, "allow-partial-history" | "accept-discontinuity"));
        let (verdict, deciding) = match (invalid, unsupported, incomplete, end, unpinned, gaps) {
            (true, ..) => ("INVALID", "invalid"),
            (_, true, ..) => ("UNSUPPORTED", "unsupported"),
            (_, _, true, ..) => ("INCOMPLETE", "incomplete"),
            (_, _, _, true, ..) => (PREFIX, "end_unproven"),
            (_, _, _, _, true, _) => ("SELF-CONSISTENT ONLY", ""),
            (_, _, _, _, _, true) => ("VALID, GAPS ACCEPTED", ""),
            _ => ("VALID", ""),
        };
        let exit_code = if invalid {
            1
        } else if unsupported || incomplete || end && !options.allow_prefix {
            3
        } else {
            i32::from(unpinned && !options.allow_unpinned)
        };
        let trust = json!({ "keys": used, "mode": self.mode });
        let mut projection = json!({
            "accepted": self.accepted, "completeness": completeness, "exit_code": exit_code,
            "finding_codes": self.findings.iter()
                .filter(|f| f.class == deciding && !self.accepted_finding(f))
                .map(|f| f.code).collect::<BTreeSet<_>>(),
            "integrity": integrity, "trust": trust, "trust_state": self.trust_state, "verdict": verdict,
        });
        let full = json!({
            "accepted": self.accepted, "completeness": completeness, "contested_streams": self.contested,
            "counts": self.counts, "exit_code": exit_code, "findings": self.findings,
            "histories": self.histories, "ignored_files": self.ignored, "integrity": integrity,
            "kind": "verify_result", "legacy": self.legacy, "limits": self.limits,
            "trust": trust, "trust_state": self.trust_state, "v": 1, "verdict": verdict,
        });
        if !(invalid || unsupported || incomplete) {
            let mut histories = full["histories"].clone();
            for history in histories.as_array_mut().unwrap() {
                for stream in history["streams"].as_array_mut().unwrap() {
                    let stream = stream.as_object_mut().unwrap();
                    for field in ["last", "signer", "unconfirmed_from"] {
                        stream.shift_remove(field);
                    }
                }
            }
            projection["histories"] = histories;
            projection["counts"] = self.counts;
        }
        VerificationResult {
            result: canonical(full),
            projection: canonical(projection),
            exit_code,
        }
    }
}

fn canonical(mut value: Value) -> Vec<u8> {
    // All document member names are fixed ASCII, and all numbers are integers.
    // serde_json's string encoding matches RFC 8785 without NFC or HTML escapes.
    value.sort_all_objects();
    serde_json::to_vec(&value).expect("serialize verification result")
}
