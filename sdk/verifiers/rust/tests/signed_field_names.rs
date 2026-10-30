// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

mod common;

use pipelock_verifier_rs::receipt::run_receipt;
use serde_json::Value;
use std::fs;

#[test]
fn signed_field_names_shared_parity() {
    let fixtures = common::repo_root().join("sdk/conformance/testdata");
    let key: Value =
        serde_json::from_str(&fs::read_to_string(fixtures.join("test-key.json")).unwrap()).unwrap();
    let fixture: Value = serde_json::from_str(
        &fs::read_to_string(fixtures.join("signed-field-names.json")).unwrap(),
    )
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let file = fixtures.join(case["file"].as_str().unwrap());
        let report = run_receipt(
            file.to_str().unwrap(),
            key["public_key_hex"].as_str().unwrap(),
            false,
        )
        .unwrap();
        assert_eq!(
            report.valid,
            case["valid"].as_bool().unwrap(),
            "{:?}",
            report.error
        );
    }
}
