# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

from pipelock_aarp_verify.receipt import verify_receipt_file


# Fixed here, not read back from the fixture, so a re-signed fixture with
# changed outcome fields fails.
EXPECTED = [
    ("legacy completion", "outcome", "allow", "status=200 bytes=16 reason=complete"),
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
]


def test_proxy_delivery_outcomes(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[3] / "conformance" / "testdata"
    key = json.loads((root / "test-key.json").read_text())["public_key_hex"]
    vectors = json.loads((root / "proxy-delivery-outcomes.json").read_text())
    assert len(vectors) == len(EXPECTED)
    for index, (vector, expected) in enumerate(zip(vectors, EXPECTED, strict=True)):
        path = tmp_path / f"outcome-{index}.json"
        path.write_text(json.dumps(vector["receipt"]))
        report = verify_receipt_file(path, key)
        assert report["valid"], report.get("error")
        record = vector["receipt"]["action_record"]
        observed = (
            vector["name"],
            record.get("decision_phase"),
            record["verdict"],
            record.get("pattern", ""),
        )
        assert observed == expected
        assert report["verdict"] == expected[2]
        record["pattern"] = record.get("pattern", "") + " tampered"
        path.write_text(json.dumps(vector["receipt"]))
        report = verify_receipt_file(path, key)
        assert not report["valid"]
        assert "signature" in report["error"]
