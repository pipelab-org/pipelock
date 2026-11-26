// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::util::Result;

use super::{
    digest, input_error,
    result::{class, Contested, Document, History, Summary},
    store::Store,
    wire::Record,
    Position, Verifier, CLOSE, MAX_INTEGER, OPEN,
};

#[derive(Deserialize)]
pub(super) struct Cutover {
    pub chains: u64,
    pub inventory: String,
}

#[derive(Deserialize)]
struct Previous {
    stream: String,
    record: String,
    seq: u64,
    ended: String,
}

#[derive(Deserialize)]
pub(super) struct Coverage {
    pub receipts_required: bool,
}

#[derive(Deserialize)]
pub(super) struct OpenBody {
    pub lineage: String,
    previous: Option<Previous>,
    pub legacy_cutover: Option<Cutover>,
    pub coverage: Coverage,
}

pub(super) struct Stream {
    pub open: Option<Record>,
    pub body: Option<OpenBody>,
    last: Option<Record>,
    pub limit: Option<u64>,
    pub fork: Option<u64>,
    pub successors: Vec<String>,
    missing: bool,
    broken: bool,
    pub summary: Summary,
}

impl Default for Stream {
    fn default() -> Self {
        Self {
            open: None,
            body: None,
            last: None,
            limit: Some(MAX_INTEGER),
            fork: None,
            successors: Vec::new(),
            missing: false,
            broken: false,
            summary: Summary::default(),
        }
    }
}

pub(super) struct Segment {
    pub ids: Vec<String>,
    pub rooted: bool,
}

impl Verifier<'_> {
    pub(super) fn verify_streams(&mut self) -> Result<()> {
        for (id, stream) in &mut self.streams {
            verify_stream(&self.store, &mut self.doc, &self.pinned, id, stream)?;
            if stream.broken {
                stream.open = None;
                stream.last = None;
                stream.body = None;
            } else if let Some(body) = &stream.body {
                self.histories
                    .entry(body.lineage.clone())
                    .or_default()
                    .push(id.clone());
            }
        }
        Ok(())
    }

    pub(super) fn verify_succession(&mut self) -> Result<()> {
        let ids: Vec<_> = self.streams.keys().cloned().collect();
        for id in &ids {
            let child = &self.streams[id];
            let Some(pin) = child.body.as_ref().and_then(|body| body.previous.as_ref()) else {
                continue;
            };
            if self
                .streams
                .get(&pin.stream)
                .is_none_or(|parent| parent.open.is_none() && parent.fork.is_none())
            {
                self.doc
                    .add_record("PREDECESSOR_NOT_PRESENTED", child.open.as_ref().unwrap());
                self.streams.get_mut(id).unwrap().missing = true;
            } else {
                let parent = pin.stream.clone();
                self.streams
                    .get_mut(&parent)
                    .unwrap()
                    .successors
                    .push(id.clone());
            }
        }

        for id in ids {
            let parent = &self.streams[&id];
            let mut confirmed_write_error = None;
            for child in &parent.successors {
                let child = &self.streams[child];
                let opening = child.open.as_ref().unwrap();
                if parent.successors.len() > 1 {
                    self.doc.add_record("SUCCESSION_FORK", opening);
                }
                if parent.open.is_some() {
                    if let Some(seq) = check_pin(&self.store, &mut self.doc, parent, child)? {
                        confirmed_write_error = Some(seq);
                    }
                }
            }
            let successor = if let [child] = parent.successors.as_slice() {
                self.streams[child].body.as_ref()
            } else {
                None
            };
            let summary = summarize(parent, successor, confirmed_write_error);
            let parent = self.streams.get_mut(&id).unwrap();
            parent.limit = confirmed_write_error.or(parent.limit);
            parent.summary = summary;
        }
        Ok(())
    }

    pub(super) fn segments(&mut self, members: &[String]) -> Vec<Segment> {
        let mut next = BTreeMap::new();
        let mut has_parent = BTreeSet::new();
        let mut roots = Vec::new();
        let mut forked = false;
        for id in members {
            let member = &self.streams[id];
            let body = member.body.as_ref().unwrap();
            if body.previous.is_none() {
                roots.push(member.open.as_ref().unwrap());
            }
            forked |= member.fork.is_some() || member.successors.len() > 1;
            if member.fork.is_none() {
                if let [child] = member.successors.as_slice() {
                    if self.streams[child]
                        .body
                        .as_ref()
                        .is_some_and(|c| c.lineage == body.lineage)
                    {
                        next.insert(id.as_str(), child.as_str());
                        has_parent.insert(child.as_str());
                    }
                }
            }
        }
        if roots.len() > 1 {
            for root in roots {
                self.doc.add_record("ROOT_FORK", root);
            }
        }
        let mut pieces = Vec::new();
        let mut visited = BTreeSet::new();
        for id in members
            .iter()
            .filter(|id| !has_parent.contains(id.as_str()))
            .chain(members)
        {
            if visited.contains(id.as_str()) {
                continue;
            }
            forked |= has_parent.contains(id.as_str());
            let rooted = self.streams[id].body.as_ref().unwrap().previous.is_none();
            let mut ids = Vec::new();
            let mut current = Some(id.as_str());
            while let Some(id) = current.filter(|id| visited.insert(*id)) {
                ids.push(id.into());
                current = next.get(id).copied();
            }
            pieces.push(Segment { ids, rooted });
        }
        if pieces.len() != 1 || forked {
            self.doc.add_code("HISTORY_DISCONNECTED", &members[0]);
        }
        pieces
    }

    pub(super) fn check_expectations(&mut self, cutover_ends: &BTreeMap<String, String>) {
        let opts = self.options;
        for id in &opts.accept_discontinuities {
            let found = cutover_ends.contains_key(id)
                || self.streams.values().any(|stream| {
                    stream.open.as_ref().is_some_and(|open| open.id == *id)
                        && stream
                            .body
                            .as_ref()
                            .and_then(|body| body.previous.as_ref())
                            .is_some_and(|pin| {
                                matches!(pin.ended.as_str(), "write_error" | "unsealed")
                            })
                });
            self.doc.accept("accept-discontinuity", id, found);
        }
        for id in &opts.allow_partial_histories {
            self.doc.accept(
                "allow-partial-history",
                id,
                self.streams.get(id).is_some_and(|s| s.missing),
            );
        }
        let mut proved = BTreeSet::new();
        for head in &opts.expect_heads {
            let found = self
                .streams
                .get(&head.stream)
                .and_then(|s| s.summary.tip.as_ref())
                == Some(&head.position);
            self.doc.accept(
                "expect-head",
                format!(
                    "{}:{}:{}",
                    head.stream, head.position.seq, head.position.record
                ),
                found,
            );
            if found {
                proved.insert(head.stream.as_str());
            }
        }
        for sequence in &opts.expect_sequences {
            let found = self
                .streams
                .get(&sequence.stream)
                .and_then(|s| s.summary.tip.as_ref())
                .is_some_and(|tip| tip.seq == sequence.seq);
            self.doc.accept(
                "expect-seq",
                format!("{}:{}", sequence.stream, sequence.seq),
                found,
            );
            if found {
                proved.insert(sequence.stream.as_str());
            }
        }
        if !opts.expect_lineage.is_empty() {
            self.doc.accept(
                "expect-lineage",
                &opts.expect_lineage,
                self.histories.contains_key(&opts.expect_lineage),
            );
        }
        if opts.allow_prefix {
            self.doc.accept("allow-prefix", "true", true);
        }
        if opts.allow_unpinned {
            self.doc.accept("allow-unpinned", "true", true);
        }
        for id in cutover_ends.values() {
            self.doc.add_record(
                "LEGACY_END_UNPROVEN",
                self.streams[id].open.as_ref().unwrap(),
            );
        }
        for (id, stream) in &self.streams {
            if stream.open.is_none() || proved.contains(id.as_str()) {
                continue;
            }
            match stream.summary.end {
                "open" => self
                    .doc
                    .add_record("END_UNPROVEN", stream.last.as_ref().unwrap()),
                "superseded_unsealed" | "superseded_write_error" => {
                    let successor = self.streams[&stream.successors[0]].open.as_ref().unwrap();
                    if !opts.accept_discontinuities.contains(&successor.id) {
                        self.doc.add_record("END_UNPROVEN", successor);
                    }
                }
                _ => {}
            }
        }
        for (lineage, members) in &self.histories {
            self.doc.histories.push(History {
                lineage: lineage.clone(),
                streams: members
                    .iter()
                    .map(|id| self.streams[id].summary.clone())
                    .collect(),
            });
        }
    }
}

fn verify_stream(
    store: &Store,
    doc: &mut Document,
    pinned: &BTreeSet<String>,
    id: &str,
    stream: &mut Stream,
) -> Result<()> {
    let mut previous: Option<Record> = None;
    let mut contested_ids = Vec::new();
    let mut beat = 0;
    for current in store.records(id, MAX_INTEGER) {
        let current = current?;
        if let Some(seq) = stream.fork {
            if current.seq != seq {
                break;
            }
            doc.add_record("FORK", &current);
            if seq == 0 {
                contested_ids.push(current.id);
            }
            continue;
        }
        if let Some(prior) = previous.take() {
            if prior.seq == current.seq {
                doc.add_record("FORK", &prior);
                doc.add_record("FORK", &current);
                stream.fork = Some(current.seq);
                stream.limit = current.seq.checked_sub(1);
                if current.seq == 0 {
                    contested_ids.extend([prior.id, current.id]);
                }
                continue;
            }
            publish(doc, pinned, id, stream, &mut beat, prior)?;
        }
        previous = Some(current);
    }
    if !contested_ids.is_empty() {
        doc.contested.push(Contested {
            stream: id.into(),
            records: contested_ids,
        });
    }
    if let Some(last) = previous {
        publish(doc, pinned, id, stream, &mut beat, last)?;
    }
    Ok(())
}

fn publish(
    doc: &mut Document,
    pinned: &BTreeSet<String>,
    id: &str,
    stream: &mut Stream,
    beat: &mut u64,
    record: Record,
) -> Result<()> {
    let prior = stream.last.replace(record);
    let current = stream.last.as_ref().unwrap();
    let code = if let Some(prior) = &prior {
        if prior.kind == CLOSE {
            Some("DATA_AFTER_CLOSE")
        } else if current.seq != prior.seq + 1
            || current.prev != prior.id
            || current.signer != prior.signer
            || current.kind == OPEN
        {
            Some("STREAM_ORDER")
        } else {
            None
        }
    } else if current.seq != 0
        || current.kind != OPEN
        || current.prev != digest(format!("pipelock-receipt-v3-genesis\0{id}").as_bytes())
    {
        Some("STREAM_ORDER")
    } else {
        None
    };
    if let Some(code) = code {
        if code == "STREAM_ORDER"
            && current.after_damage
            && current.seq > prior.as_ref().map_or(0, |p| p.seq + 1)
        {
            stream.broken = true;
            check_body(doc, pinned, current);
        } else {
            doc.add_record(code, current);
        }
        return Ok(());
    }
    if !check_body(doc, pinned, current) {
        stream.broken = true;
        return Ok(());
    }
    if current.seq == 0 && current.kind == OPEN {
        // Retain the opening metadata for succession and appraisals.
        stream.open = Some(current.clone());
        if !current.unknown {
            stream.body = Some(
                serde_json::from_value(current.body.clone())
                    .map_err(|e| input_error(format!("decode verified open body: {e}")))?,
            );
        }
    }
    if prior.is_some_and(|prior| current.ts < prior.ts) {
        doc.add_record("CLOCK_REGRESSION", current);
    }
    if current.kind == "heartbeat" && !current.unknown {
        *beat += 1;
        if current.body["beat"].as_u64() != Some(*beat) {
            doc.add_record("HEARTBEAT_GAP", current);
        }
    }
    stream.summary.records += 1;
    Ok(())
}

fn check_body(doc: &mut Document, pinned: &BTreeSet<String>, current: &Record) -> bool {
    if let Some(code) = current.body_code {
        doc.add_record(code, current);
        return class(code) != "invalid";
    }
    if !pinned.is_empty() && !pinned.contains(&current.signer) {
        doc.add_record("TRUST", current);
    }
    true
}

fn check_pin(
    store: &Store,
    doc: &mut Document,
    parent: &Stream,
    child: &Stream,
) -> Result<Option<u64>> {
    let child_body = child.body.as_ref().unwrap();
    let pin = child_body.previous.as_ref().unwrap();
    let child_open = child.open.as_ref().unwrap();
    let same_lineage = parent
        .body
        .as_ref()
        .is_some_and(|p| p.lineage == child_body.lineage);
    if !same_lineage && parent.body.is_some() {
        doc.add_record("LINEAGE_MISMATCH", child_open);
    }
    let record = if parent.limit.is_some_and(|limit| pin.seq <= limit) {
        store.at(&pin.stream, pin.seq)?
    } else {
        None
    };
    let Some(record) = record else {
        doc.add_record("PREDECESSOR_TRUNCATED", child_open);
        return Ok(None);
    };
    if record.id != pin.record
        || pin.ended == "closed" && record.kind != CLOSE
        || pin.ended == "unsealed" && record.kind == CLOSE
    {
        doc.add_record("PIN_MISMATCH", child_open);
        return Ok(None);
    }
    let last = parent.last.as_ref().unwrap().seq;
    if pin.ended != "write_error" {
        if last > pin.seq {
            doc.add_record("TAIL_AFTER_SUCCESSION", child_open);
        }
        return Ok(None);
    }
    if parent.successors.len() != 1 || !same_lineage || parent.fork.is_some() {
        return Ok(None);
    }
    if last > pin.seq {
        for record in store.records(&pin.stream, last) {
            let record = record?;
            if record.seq > pin.seq {
                doc.add_record("UNCONFIRMED", &record);
            }
        }
    }
    Ok(Some(pin.seq))
}

fn summarize(
    stream: &Stream,
    successor: Option<&OpenBody>,
    confirmed_write_error: Option<u64>,
) -> Summary {
    let mut summary = stream.summary.clone();
    if let Some(open) = &stream.open {
        summary.stream.clone_from(&open.stream);
        summary.signer.clone_from(&open.signer);
    }
    if let Some(pin) = stream.body.as_ref().and_then(|body| body.previous.as_ref()) {
        summary.previous = Some(pin.stream.clone());
    }
    summary.last = stream.last.as_ref().map(Record::position);
    summary.tip.clone_from(&summary.last);
    summary.end = if stream.fork.is_some() {
        "forked"
    } else if stream.last.as_ref().is_some_and(|last| last.kind == CLOSE) {
        "closed"
    } else {
        "open"
    };
    if stream.successors.len() > 1 {
        summary.tip = None;
    } else if let Some(body) = successor.filter(|_| stream.fork.is_none()) {
        let pin = body.previous.as_ref().unwrap();
        let last = stream.last.as_ref();
        if pin.ended == "unsealed"
            && last.is_some_and(|last| {
                last.id == pin.record && last.seq == pin.seq && last.kind != CLOSE
            })
            && stream
                .body
                .as_ref()
                .is_some_and(|own| own.lineage == body.lineage)
        {
            summary.end = "superseded_unsealed";
        } else if pin.ended == "write_error" && confirmed_write_error == Some(pin.seq) {
            summary.end = "superseded_write_error";
            summary.tip = Some(Position {
                record: pin.record.clone(),
                seq: pin.seq,
            });
            summary.records = pin.seq + 1;
            summary.unconfirmed_from = Some(pin.seq + 1);
        }
    }
    summary
}
