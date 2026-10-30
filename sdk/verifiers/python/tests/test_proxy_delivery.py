# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

from pipelock_aarp_verify.receipt import verify_receipt_file


def test_proxy_delivery_outcomes(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[3] / "conformance" / "testdata"
    key = json.loads((root / "test-key.json").read_text())["public_key_hex"]
    vectors = json.loads((root / "proxy-delivery-outcomes.json").read_text())
    assert len(vectors) == 6
    for index, vector in enumerate(vectors):
        path = tmp_path / f"outcome-{index}.json"
        path.write_text(json.dumps(vector["receipt"]))
        report = verify_receipt_file(path, key)
        assert report["valid"], report.get("error")
        record = vector["receipt"]["action_record"]
        assert report["verdict"] == record["verdict"]
        record["pattern"] = record.get("pattern", "") + " tampered"
        path.write_text(json.dumps(vector["receipt"]))
        report = verify_receipt_file(path, key)
        assert not report["valid"]
        assert "signature" in report["error"]
