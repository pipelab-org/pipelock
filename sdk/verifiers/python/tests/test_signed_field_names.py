# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

from pipelock_aarp_verify.receipt import verify_receipt_file


def test_signed_field_names_shared_parity():
    fixtures = Path(__file__).resolve().parents[3] / "conformance/testdata"
    key = json.loads((fixtures / "test-key.json").read_text())["public_key_hex"]
    for case in json.loads((fixtures / "signed-field-names.json").read_text())["cases"]:
        path = fixtures / case["file"]
        # A missing fixture must fail here, not read as an expected rejection.
        path.read_bytes()
        report = verify_receipt_file(path, key)
        assert report["valid"] == case["valid"], report.get("error")
        if not case["valid"]:
            assert case.get("error"), f"{case['file']}: negative case names no expected error"
            assert case["error"] in (report.get("error") or ""), report.get("error")
