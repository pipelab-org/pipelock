// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

mod common;

use pipelock_verifier_rs::signing::verify_receipt;
use serde_json::Value;
use std::fs;

#[test]
fn proxy_delivery_outcomes() {
    let root = common::repo_root().join("sdk/conformance/testdata");
    let key: Value =
        serde_json::from_str(&fs::read_to_string(root.join("test-key.json")).unwrap()).unwrap();
    let vectors: Vec<Value> = serde_json::from_str(
        &fs::read_to_string(root.join("proxy-delivery-outcomes.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(vectors.len(), 6);
    let public_key = key["public_key_hex"].as_str().unwrap();
    for vector in vectors {
        let mut receipt = vector["receipt"].clone();
        verify_receipt(&receipt, public_key).unwrap();
        let pattern = receipt["action_record"]["pattern"].as_str().unwrap_or("");
        receipt["action_record"]["pattern"] = Value::String(format!("{pattern} tampered"));
        let error = verify_receipt(&receipt, public_key).unwrap_err();
        assert!(error.to_lowercase().contains("signature"), "{error}");
    }
}
