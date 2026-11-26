// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::Path,
};

use super::{input_error, lower_hex, open, Discovery, Verifier};
use crate::{chain_set::parse_evidence_filename, util::Result};

const EMPTY: &[u8] = b"{\"chains\":[],\"v\":1}";

// Go discovery: internal/receipt/v3/legacy.go:43, internal/receipt/chain_set.go:358,
// internal/ael/emitter.go:138 and internal/receipt/group_inventory.go:83.
pub(super) fn candidate(name: &str) -> bool {
    name == "ael"
        || (name.starts_with("chain-link-") && name.ends_with(".json"))
        || parse_evidence_filename(name).is_some()
        || (name.starts_with("receipt-group-") && name.ends_with(".json"))
        || matches!(
            name,
            "activation-receipts.jsonl"
                | "redaction-receipts.jsonl"
                | "ratification-receipts.jsonl"
        )
}

pub(super) fn inventory_id(name: &str) -> Option<String> {
    let hex = name
        .strip_prefix("receipt-v3-cutover-")?
        .strip_suffix(".json")?;
    lower_hex(hex, 64).then(|| format!("sha256:{hex}"))
}

fn is_empty(path: &Path) -> Result<bool> {
    let mut bytes = Vec::with_capacity(EMPTY.len() + 1);
    open(path)?
        .take((EMPTY.len() + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| input_error(format!("read cutover inventory: {e}")))?;
    Ok(bytes == EMPTY)
}

impl Verifier<'_> {
    pub(super) fn verify_empty_cutover(
        &mut self,
        found: &Discovery,
    ) -> Result<BTreeMap<String, String>> {
        if found.files.is_empty() {
            return Ok(BTreeMap::new());
        }
        let mut checked = BTreeSet::new();
        for stream in self.streams.values() {
            let Some(pin) = stream
                .body
                .as_ref()
                .and_then(|body| body.legacy_cutover.as_ref())
            else {
                continue;
            };
            let Some(origin) = stream.open.as_ref() else {
                continue;
            };
            checked.insert(pin.inventory.as_str());
            let paths = found.inventories.get(&pin.inventory);
            if paths.is_none() && pin.chains != 0 {
                self.doc.add_record("CUTOVER_INVENTORY_MISMATCH", origin);
            }
            if let Some(paths) = paths {
                for path in paths {
                    if pin.chains != 0 || !is_empty(path)? {
                        self.doc.add_record("CUTOVER_INVENTORY_MISMATCH", origin);
                    }
                }
            }
        }
        for (id, paths) in &found.inventories {
            if !checked.contains(id.as_str()) {
                for path in paths {
                    if !is_empty(path)? {
                        self.doc.add_code("CUTOVER_INVENTORY_MISMATCH", "");
                    }
                }
            }
        }
        Ok(BTreeMap::new())
    }
}
