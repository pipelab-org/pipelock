// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

mod common;

use pipelock_verifier_rs::signing::verify_receipt;
use serde_json::Value;
use std::fs;

// Fixed here, not read back from the fixture, so a re-signed fixture with
// changed outcome fields fails.
const EXPECTED: [(&str, &str, &str, &str); 6] = [
    (
        "legacy completion",
        "outcome",
        "allow",
        "status=200 bytes=16 reason=complete",
    ),
    ("admission without outcome", "intent", "allow", ""),
    (
        "delivered representation",
        "outcome",
        "allow",
        "status=200 bytes=16 reason=complete delivered_bytes=130",
    ),
    (
        "upstream failure",
        "outcome",
        "warn",
        "status=502 bytes=unknown reason=fetch_failed delivered_bytes=120",
    ),
    (
        "partial delivery",
        "outcome",
        "warn",
        "status=200 bytes=16 reason=delivery_error delivered_bytes=7",
    ),
    (
        "denied response",
        "outcome",
        "block",
        "status=403 bytes=unknown reason=compressed_response delivered_bytes=7",
    ),
];

#[test]
fn proxy_delivery_outcomes() {
    let root = common::repo_root().join("sdk/conformance/testdata");
    let key: Value =
        serde_json::from_str(&fs::read_to_string(root.join("test-key.json")).unwrap()).unwrap();
    let vectors: Vec<Value> = serde_json::from_str(
        &fs::read_to_string(root.join("proxy-delivery-outcomes.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(vectors.len(), EXPECTED.len());
    let public_key = key["public_key_hex"].as_str().unwrap();
    for (vector, expected) in vectors.iter().zip(EXPECTED) {
        let mut receipt = vector["receipt"].clone();
        let record = &receipt["action_record"];
        let observed = (
            vector["name"].as_str().unwrap(),
            record["decision_phase"].as_str().unwrap_or(""),
            record["verdict"].as_str().unwrap(),
            record["pattern"].as_str().unwrap_or(""),
        );
        assert_eq!(observed, expected);
        verify_receipt(&receipt, public_key).unwrap();
        let pattern = receipt["action_record"]["pattern"].as_str().unwrap_or("");
        receipt["action_record"]["pattern"] = Value::String(format!("{pattern} tampered"));
        let error = verify_receipt(&receipt, public_key).unwrap_err();
        assert!(error.to_lowercase().contains("signature"), "{error}");
    }
}
