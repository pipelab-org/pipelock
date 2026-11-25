// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{json, Value};

use crate::util::Result;

use super::{history::Segment, registry, result::Document, store::Store, wire::Record, Verifier};

const MAX_DECISIONS: usize = 10_000_000;
const INCONSISTENT: &str = "DECISION_INCONSISTENT";

struct Action<'a> {
    body: &'a Value,
    id: &'a str,
    phase: &'a str,
    verdict: &'a str,
    relation: &'a str,
    boundary: &'a str,
    outcome: &'a str,
    attempt: Option<u64>,
    hold: Option<&'a str>,
    correction: Option<bool>,
}

impl<'a> Action<'a> {
    fn new(body: &'a Value) -> Self {
        Self {
            body,
            id: text(body, "action_id"),
            phase: text(body, "phase"),
            verdict: text(body, "verdict"),
            relation: text(body, "effect_relation"),
            boundary: text(body, "effect_boundary"),
            outcome: text(body, "outcome_class"),
            attempt: body["attempt"].as_u64(),
            hold: body["hold"]["id"].as_str(),
            correction: body["hold"]["correction"].as_bool(),
        }
    }

    fn effect(&self) -> [&str; 5] {
        [
            text(self.body, "action_type"),
            text(self.body, "transport"),
            text(self.body, "method"),
            text(self.body, "target"),
            self.boundary,
        ]
    }

    fn valid(&self, receipts_required: bool) -> bool {
        if matches!(self.phase, "intent" | "outcome") != self.attempt.is_some()
            || (self.phase == "outcome") == self.outcome.is_empty()
            || matches!(self.phase, "hold" | "resolution") != self.hold.is_some()
            || self
                .correction
                .is_some_and(|c| !c || self.phase != "resolution" || self.verdict != "block")
            || !self.valid_ask()
        {
            return false;
        }
        let releases = matches!(
            self.verdict,
            "allow" | "warn" | "strip" | "forward" | "redirect"
        );
        let release_boundary = releasing_boundary(self.boundary);
        match (self.phase, self.verdict) {
            ("decision", "block") => self.relation == "not_attempted",
            ("decision", "ask") => self.boundary == "hook_execution" && self.relation == "before",
            ("decision", _) => {
                !receipts_required
                    && releases
                    && release_boundary
                    && matches!(self.relation, "before" | "after" | "unknown")
            }
            ("intent", _) => releases && release_boundary && self.relation == "before",
            ("outcome", _) if self.outcome == "not_released" => {
                self.verdict == "block" && self.relation == "not_attempted"
            }
            ("outcome", _) => {
                releases
                    && matches!(
                        (self.outcome, self.relation),
                        ("completed" | "failed_after_attempt", "after")
                            | ("failed_before_attempt", "not_attempted")
                            | ("attempt_unknown", "unknown")
                    )
            }
            ("hold", "ask" | "defer") => {
                self.boundary == "approval_prompt" && self.relation == "before"
            }
            ("resolution", "allow" | "ask") => {
                self.boundary == "approval_prompt" && self.relation == "after"
            }
            ("resolution", "block") => {
                self.boundary == "approval_prompt"
                    && matches!(self.relation, "after" | "not_attempted" | "unknown")
            }
            _ => false,
        }
    }

    fn valid_ask(&self) -> bool {
        let ask = &self.body["ask"];
        if self.verdict != "ask" {
            return ask.is_null();
        }
        if self.phase == "decision" {
            ask["channel"] == "host_prompt" && ask["observed"] == false
        } else {
            ask["channel"] == "approval_api" && ask["observed"] == true
        }
    }
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field].as_str().unwrap_or_default()
}

fn releasing_boundary(boundary: &str) -> bool {
    !matches!(boundary, "none" | "approval_prompt")
}

#[derive(Default)]
struct Decision {
    state: &'static str,
    hold: String,
    first_resolution: String,
    attempt: u64,
    effect: [String; 5],
    intent_verdict: String,
    retryable: bool,
    failed: bool,
}

impl Decision {
    fn advance(&mut self, action: &Action<'_>, unknown_start: bool) -> bool {
        if self.state.is_empty() && unknown_start && !self.infer_prefix(action) {
            return false;
        }
        match action.phase {
            "decision" if self.state.is_empty() => {
                self.state = match action.verdict {
                    "block" => "blocked",
                    "ask" => "asked_unobserved",
                    _ => "allowed_effect_unrecorded",
                };
                true
            }
            "hold" if self.state.is_empty() => {
                self.state = "pending";
                self.hold = action.hold.unwrap().into();
                true
            }
            "resolution" => self.resolve(action),
            "intent" | "outcome" => self.attempt(action),
            _ => false,
        }
    }

    fn infer_prefix(&mut self, action: &Action<'_>) -> bool {
        match action.phase {
            "resolution" => {
                self.hold = action.hold.unwrap().into();
                self.state = "pending";
                if action.correction.is_some() {
                    self.first_resolution = "allow".into();
                    self.state = "outcome_unknown";
                }
            }
            "intent" | "outcome" => {
                // Only the last inferred refusal matters, regardless of the
                // signed attempt number.
                let attempt = action.attempt.unwrap();
                self.attempt = attempt - 1;
                if self.attempt != 0 {
                    self.effect = action.effect().map(str::to_owned);
                    self.state = "not_released";
                    self.retryable = true;
                }
                if action.phase == "outcome" && action.outcome != "not_released" {
                    if !releasing_boundary(action.boundary) {
                        return false;
                    }
                    self.attempt = attempt;
                    self.effect = action.effect().map(str::to_owned);
                    self.intent_verdict = action.verdict.into();
                    self.state = "outcome_unknown";
                    self.retryable = false;
                }
            }
            _ => {}
        }
        true
    }

    fn resolve(&mut self, action: &Action<'_>) -> bool {
        if self.attempt != 0 || self.hold.is_empty() || action.hold != Some(&self.hold) {
            return false;
        }
        let prior = &self.first_resolution;
        if prior == "ask"
            || (!prior.is_empty() && action.verdict != "block")
            || action.correction.is_some() != (prior == "allow" && action.verdict == "block")
        {
            return false;
        }
        if prior.is_empty() {
            self.first_resolution = action.verdict.into();
        }
        self.state = match action.verdict {
            "allow" => "outcome_unknown",
            "ask" => "stepped_up",
            _ => "blocked",
        };
        true
    }

    fn attempt(&mut self, action: &Action<'_>) -> bool {
        let attempt = action.attempt.unwrap();
        if self.attempt != 0 && self.effect != action.effect() {
            return false;
        }
        if !self.intent_verdict.is_empty() {
            if action.phase != "outcome"
                || attempt != self.attempt
                || (action.outcome != "not_released" && action.verdict != self.intent_verdict)
            {
                return false;
            }
            self.intent_verdict.clear();
        } else {
            let can_start = self.state.is_empty()
                || self.retryable
                || (self.attempt == 0
                    && self.first_resolution == "allow"
                    && self.state == "outcome_unknown");
            if !can_start
                || attempt != self.attempt + 1
                || (action.phase != "intent" && action.outcome != "not_released")
            {
                return false;
            }
            self.attempt = attempt;
            self.effect = action.effect().map(str::to_owned);
        }
        self.retryable = matches!(action.outcome, "failed_before_attempt" | "not_released");
        self.state = match action.outcome {
            "failed_before_attempt" | "failed_after_attempt" => "failed",
            "not_released" => "not_released",
            "completed" => "completed",
            _ => "outcome_unknown",
        };
        if action.phase == "intent" {
            self.intent_verdict = action.verdict.into();
        }
        true
    }
}

#[derive(Default)]
struct Counts {
    decisions: BTreeMap<&'static str, u64>,
    uninterpreted: BTreeMap<String, u64>,
}

impl Counts {
    fn document(self, complete_history: bool) -> Value {
        if !complete_history {
            return json!({ "scope": "not_appraised" });
        }
        let unknown: u64 = self
            .decisions
            .iter()
            .filter(|(state, _)| {
                matches!(
                    **state,
                    "outcome_unknown"
                        | "pending"
                        | "asked_unobserved"
                        | "allowed_effect_unrecorded"
                        | "uninterpreted"
                )
            })
            .map(|(_, count)| count)
            .sum();
        let completed = self.decisions.get("completed").copied().unwrap_or_default();
        let decisions: Vec<_> = self
            .decisions
            .into_iter()
            .map(|(state, count)| json!({ "state": state, "count": count }))
            .collect();
        let uninterpreted: Vec<_> = self
            .uninterpreted
            .into_iter()
            .map(|(kind, count)| json!({ "kind": kind, "count": count }))
            .collect();
        json!({
            "scope": "full_history", "decisions": decisions, "effects_completed": completed,
            "effects_unknown": unknown, "uninterpreted": uninterpreted
        })
    }
}

#[derive(Default)]
struct Inspection {
    ids: HashMap<String, bool>,
    hold_owners: HashMap<String, String>,
    bad_shapes: HashSet<(usize, String)>,
    future: bool,
    full: bool,
}

impl Inspection {
    fn remember(&mut self, id: &str, unknown: bool, max: usize) {
        if let Some(opaque) = self.ids.get_mut(id) {
            *opaque |= unknown;
        } else if self.ids.len() < max {
            self.ids.insert(id.into(), unknown);
        } else {
            self.full = true;
        }
    }

    fn action(
        &mut self,
        doc: &mut Document,
        counts: &mut Counts,
        segment: usize,
        required: bool,
        record: &Record,
    ) {
        if record.body_version != 1 {
            self.future = true;
            *counts.uninterpreted.entry("action".into()).or_default() += 1;
            return;
        }
        let action = Action::new(&record.body);
        let normalization = &record.body["normalization"];
        if let Some(digest) = normalization["digest"].as_str() {
            if registry()["normalization_profiles"][digest] != normalization["id"] {
                doc.add_record("NORMALIZATION_UNKNOWN", record);
            }
        }
        self.remember(action.id, record.unknown, MAX_DECISIONS);
        if let Some(hold) = action
            .hold
            .filter(|_| matches!(action.phase, "hold" | "resolution"))
        {
            let owner = self
                .hold_owners
                .entry(hold.into())
                .or_insert_with(|| action.id.into());
            if owner != action.id {
                doc.add_record(INCONSISTENT, record);
            }
        }
        if record.unknown {
            *counts.uninterpreted.entry("action".into()).or_default() += 1;
            doc.add_record("ACTION_UNINTERPRETED", record);
        } else if !action.valid(required) {
            doc.add_record(INCONSISTENT, record);
            self.bad_shapes.insert((segment, action.id.into()));
        }
    }
}

fn appraise_segment(
    store: &Store,
    doc: &mut Document,
    counts: &mut Counts,
    inspection: &Inspection,
    piece: &Segment,
    segment: usize,
    streams: &BTreeMap<String, super::history::Stream>,
) -> Result<()> {
    let mut decisions: HashMap<String, Decision> = HashMap::new();
    for id in &piece.ids {
        let Some(limit) = streams[id].limit else {
            continue;
        };
        for record in store.records(id, limit) {
            let record = record?;
            if record.kind != "action" || record.body_code.is_some() {
                continue;
            }
            let action = Action::new(&record.body);
            let decision = decisions.entry(action.id.into()).or_insert_with(|| {
                let mut decision = Decision::default();
                if inspection.ids.get(action.id) == Some(&true) {
                    decision.state = "uninterpreted";
                } else {
                    decision.failed = inspection.bad_shapes.contains(&(segment, action.id.into()));
                }
                decision
            });
            if !decision.failed
                && decision.state != "uninterpreted"
                && !decision.advance(&action, !piece.rooted)
            {
                decision.failed = true;
                doc.add_record(INCONSISTENT, &record);
            }
        }
    }
    if piece.rooted {
        for decision in decisions.values().filter(|d| !d.failed) {
            *counts.decisions.entry(decision.state).or_default() += 1;
        }
    }
    Ok(())
}

impl Verifier<'_> {
    pub(super) fn appraise_decisions(&mut self) -> Result<()> {
        let mut counts = Counts::default();
        let mut full = true;
        let histories: Vec<_> = self.histories.values().cloned().collect();
        for members in histories {
            let segments = self.segments(&members);
            full &= segments.len() == 1
                && segments[0].rooted
                && self.streams[segments[0].ids.last().unwrap()].fork.is_none();
            let mut inspection = Inspection::default();
            for (segment, piece) in segments.iter().enumerate() {
                for id in &piece.ids {
                    let stream = &self.streams[id];
                    let Some(limit) = stream.limit else { continue };
                    let required = stream.body.as_ref().unwrap().coverage.receipts_required;
                    for record in self.store.records(id, limit) {
                        let record = record?;
                        if record.body_code.is_some() {
                            continue;
                        }
                        if record.kind == "action" {
                            inspection.action(
                                &mut self.doc,
                                &mut counts,
                                segment,
                                required,
                                &record,
                            );
                        } else if record.unknown
                            && registry()["kinds"][&record.kind]["class"] != "control"
                        {
                            *counts.uninterpreted.entry(record.kind.clone()).or_default() += 1;
                            self.doc.add_record("EVENT_UNINTERPRETED", &record);
                        }
                    }
                }
            }
            let open = self.streams[&members[0]].open.as_ref().unwrap();
            if inspection.future {
                self.doc.add_record("DECISIONS_NOT_APPRAISED", open);
            }
            if inspection.full {
                self.doc.add_record("DECISION_INDEX_FULL", open);
                self.doc.limits.insert("L-DECISION-INDEX");
            }
            if inspection.future || inspection.full {
                full = false;
                continue;
            }
            for (index, piece) in segments.iter().enumerate() {
                appraise_segment(
                    &self.store,
                    &mut self.doc,
                    &mut counts,
                    &inspection,
                    piece,
                    index,
                    &self.streams,
                )?;
            }
        }
        self.doc.counts = counts.document(full);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Inspection;

    use super::{Action, Decision};
    use serde_json::json;

    #[test]
    fn inferred_decision_prefix_is_bounded_by_the_presented_actions() {
        let correction = json!({
            "phase":"resolution","verdict":"block","effect_boundary":"approval_prompt",
            "effect_relation":"after","hold":{"id":"h","correction":true}
        });
        let correction = Action::new(&correction);
        assert!(correction.valid(true));
        assert!(!Decision::default().advance(&correction, false));
        let mut decision = Decision::default();
        assert!(decision.advance(&correction, true));
        assert_eq!(decision.state, "blocked");

        let mut body = json!({
            "phase":"outcome","verdict":"allow","effect_boundary":"upstream_send",
            "effect_relation":"after","attempt": super::super::MAX_INTEGER,
            "outcome_class":"completed"
        });
        let mut decision = Decision::default();
        let outcome = Action::new(&body);
        assert!(outcome.valid(true));
        assert!(decision.advance(&outcome, true));
        assert_eq!(decision.state, "completed");

        body["effect_boundary"] = json!("approval_prompt");
        assert!(!Decision::default().advance(&Action::new(&body), true));
    }

    #[test]
    fn releasing_decisions_and_host_asks_have_distinct_shapes() {
        let mut body = json!({
            "phase":"decision","verdict":"allow","effect_boundary":"upstream_send",
            "effect_relation":"before"
        });
        let action = Action::new(&body);
        assert!(!action.valid(true));
        assert!(action.valid(false));
        let mut decision = Decision::default();
        assert!(decision.advance(&action, true));
        assert_eq!(decision.state, "allowed_effect_unrecorded");

        body["verdict"] = json!("ask");
        body["effect_boundary"] = json!("hook_execution");
        body["ask"] = json!({"channel":"host_prompt","observed":false});
        let action = Action::new(&body);
        assert!(action.valid(true));
        let mut decision = Decision::default();
        assert!(decision.advance(&action, false));
        assert_eq!(decision.state, "asked_unobserved");

        body["attempt"] = json!(1);
        assert!(!Action::new(&body).valid(true));
    }

    #[test]
    fn decision_index_counts_distinct_effective_ids() {
        let mut inspection = Inspection::default();
        inspection.remember("first", false, 1);
        inspection.remember("first", true, 1);
        assert!(!inspection.full);
        assert!(inspection.ids["first"]);

        inspection.remember("second", false, 1);
        assert!(inspection.full);
        assert!(!inspection.ids.contains_key("second"));
        inspection.remember("first", false, 1);
        assert!(inspection.ids["first"]);
    }
}
