# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import io
import json
import shutil
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pipelock_aarp_verify import V3Options, canonical_v3, claims_v3_input, verify_v3
from pipelock_aarp_verify.cli import main
from pipelock_aarp_verify.v3.wire import PROFILE, REGISTRY, digest, pae, parse_line

SDK = Path(__file__).resolve().parents[3]
VECTORS = SDK / "conformance" / "testdata" / "v3"
REQUESTS = sorted(VECTORS.glob("*/request.json"))


def _options(request):
    return V3Options(
        keys=tuple(request.get("keys", ())),
        allow_unpinned=request.get("allow_unpinned", False),
        allow_prefix=request.get("allow_prefix", False),
        accept_discontinuities=tuple(request.get("accept_discontinuities", ())),
        allow_partial_histories=tuple(request.get("allow_partial_histories", ())),
        expect_lineage=request.get("expect_lineage", ""),
        expect_heads=tuple(request.get("expect_heads", ())),
        expect_sequences=tuple(request.get("expect_sequences", ())),
        directory=request.get("directory", False),
        explicit_v3=request.get("format") == "v3",
    )


@pytest.mark.parametrize("request_path", REQUESTS, ids=lambda path: path.parent.name)
def test_v3_corpus(request_path, tmp_path):
    request = json.loads(request_path.read_bytes())
    inputs = [request_path.parent / name for name in request["inputs"]]
    if request.get("legacy"):
        assert all(not claims_v3_input(path) for path in inputs)
        return
    options = _options(request)
    expected = (
        (request_path.parent / "projection.json").read_bytes().removesuffix(b"\n")
    )
    if options.directory:
        for index, order in enumerate((inputs, inputs[::-1])):
            directory = tmp_path / str(index)
            directory.mkdir()
            for path in order:
                target = directory / path.relative_to(request_path.parent)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
        first, projection = verify_v3([tmp_path / "0"], options)
        second, _ = verify_v3([tmp_path / "1"], options)
    else:
        first, projection = verify_v3(inputs, options)
        second = verify_v3(inputs[::-1], options)[0] if len(inputs) > 1 else first
    assert canonical_v3(projection) == expected
    assert canonical_v3(first) == canonical_v3(second)
    if request_path.parent.name == "g04-absent-max-write-error-pin":
        parent = first["histories"][0]["streams"][0]
        assert parent["end"] == "closed"
        assert parent["tip"] == parent["last"]
        assert "unconfirmed_from" not in parent


def test_installed_registry_matches_spec():
    source = json.loads((SDK / "receipt-v3" / "registry.json").read_bytes())
    for key, table in REGISTRY.items():
        if key == "objects":
            assert table == {
                name: {
                    field: [spec["type"], spec["required"]]
                    for field, spec in shape.items()
                }
                for name, shape in source[key].items()
            }
        else:
            assert table == source[key]


def _request_args(name):
    directory = VECTORS / name
    request = json.loads((directory / "request.json").read_bytes())
    return [
        *(arg for key in request.get("keys", []) for arg in ("--key", key)),
        *(str(directory / path) for path in request["inputs"]),
    ]


@pytest.mark.parametrize(
    ("vector", "status"),
    [("g08-pinned", 0), ("g08-unpinned-refused", 1), ("g01-empty-input", 3)],
)
@pytest.mark.parametrize("output", ["result", "projection"])
def test_cli_result(capsys, vector, status, output):
    assert main(["v3", "--output", output, *_request_args(vector)]) == status
    stdout, stderr = capsys.readouterr()
    assert not stderr
    document = json.loads(stdout)
    assert document["exit_code"] == status
    assert canonical_v3(document) + b"\n" == stdout.encode()


@pytest.mark.parametrize(
    "args",
    [
        ["--format", "v2"],
        ["--output", "json"],
        ["--unknown"],
        ["--key", "ab"],
        ["--claims"],
        ["--claims", "--output", "result", "path"],
        ["--claims", "one", "two"],
        ["--format", "v3", "one", "two"],
        ["--expect-lineage", "bad"],
        ["--expect-head", "bad"],
        ["--expect-seq", "bad"],
        ["--accept-discontinuity", "bad"],
        ["--allow-partial-history", "bad"],
        ["missing"],
        ["--claims", "missing"],
    ],
)
def test_cli_usage(capsys, args):
    assert main(["v3", *args]) == 2
    stdout, stderr = capsys.readouterr()
    assert not stdout and stderr.endswith("\n") and stderr.count("\n") == 1


def test_cli_claims_and_requirements(capsys):
    legacy = VECTORS / "g10-action-receipt-v1-single" / "action-receipt-v1-single.json"
    assert main(["v3", "--claims", str(legacy)]) == 0
    assert capsys.readouterr().out == "false\n"
    args = _request_args("g08-pinned")
    assert main(["v3", "--claims", args[-1]]) == 0
    assert capsys.readouterr().out == "true\n"
    document = json.loads((VECTORS / "g08-pinned" / "expect.json").read_bytes())
    history = document["histories"][0]
    stream = history["streams"][0]
    pin = f"{stream['stream']}:{stream['tip']['seq']}"
    assert (
        main(
            [
                "v3",
                *args,
                "--expect-seq",
                pin,
                "--expect-head",
                f"{pin}:{stream['tip']['record']}",
                "--expect-lineage",
                history["lineage"],
            ]
        )
        == 0
    )
    assert len(json.loads(capsys.readouterr().out)["accepted"]) == 3
    assert main(["v3", *args, "--expect-seq", f"{stream['stream']}:7"]) == 1
    assert (
        json.loads(capsys.readouterr().out)["findings"][0]["code"]
        == "EXPECTATION_NOT_MET"
    )


def test_standalone_receipt_oversized_message(tmp_path, capsys):
    path = tmp_path / "receipt.json"
    with path.open("wb") as output:
        output.truncate((8 << 20) + 1)
    assert main(["receipt", "--json", str(path)]) == 1
    assert json.loads(capsys.readouterr().out)["error"] == (
        "read receipt: input exceeds 8388608 bytes"
    )


def _v3_open_with_cutover(directory, inventory, key):
    raw = canonical_v3(inventory)
    inventory_id = digest(raw)
    (directory / f"receipt-v3-cutover-{inventory_id[7:]}.json").write_bytes(raw)
    path = Path(_request_args("g08-pinned")[-1])
    original, _, _ = parse_line(path.read_bytes().split(b"\n", 1)[0] + b"\n")
    public = key.public_key().public_bytes_raw()
    signer = digest(public)
    original.fields["signer"] = signer
    original.body["legacy_cutover"] = {
        "inventory": inventory_id,
        "chains": len(inventory["chains"]),
    }
    original.body["signer_key"]["public"] = base64.b64encode(public).decode()
    payload = canonical_v3(original.fields)
    signature = base64.b64encode(key.sign(pae(payload))).decode()
    envelope = (
        b'{"payloadType":"'
        + PROFILE
        + b'","signatures":['
        + canonical_v3({"keyid": signer, "sig": signature})
        + b'],"payload":'
        + payload
        + b"}\n"
    )
    (directory / path.name).write_bytes(envelope)
    return public.hex()


def test_claims_profile_requires_exact_filename_suffix(tmp_path):
    path = tmp_path / "other.receipt-v3.jsonl\n"
    path.write_bytes(b"{}\n")
    assert not claims_v3_input(path)


def test_cutover_inventory_reads_are_bounded(monkeypatch):
    from pipelock_aarp_verify.v3 import legacy

    vector = VECTORS / "g09-inventory-over-1024-chains"
    inventory = next(vector.glob("receipt-v3-cutover-*.json"))
    raw = inventory.read_bytes()

    class BoundedInput(io.BytesIO):
        def read(self, size=-1):
            assert 0 < size <= 256
            return super().read(size)

    monkeypatch.setattr(legacy, "_open_regular_input", lambda _: BoundedInput(raw))
    rows = legacy._read_inventory(inventory, digest(raw), 1025)
    assert rows is not None and len(rows) == 1025


@pytest.mark.parametrize(
    ("layout", "count"),
    [
        pytest.param(b'{"v":1,"chains":[]}', 0, id="wrong-prefix"),
        pytest.param(b'{"chains":[ROW],"v":1}', 0, id="too-many-rows"),
        pytest.param(b'{"chains":[ROW],"v":1}', 2, id="not-enough-rows"),
        pytest.param(b'{"chains":[{', 1, id="truncated-row"),
        pytest.param(b'{"chains":[{"chain":}],"v":1}', 1, id="malformed-row"),
        pytest.param(b'{"chains":[ROW,ROW],"v":1}', 2, id="duplicate-row"),
        pytest.param(b'{"chains":[ROW,],"v":1}', 1, id="trailing-comma"),
        pytest.param(b'{"chains":[ROW],"v":1} ', 1, id="trailing-data"),
    ],
)
def test_cutover_inventory_rejects_invalid_layout(tmp_path, layout, count):
    from pipelock_aarp_verify.v3.legacy import _read_inventory

    row = canonical_v3(
        {"chain": "0" * 32, "format": "action_v1", "record": digest(b""), "seq": 0}
    )
    raw = layout.replace(b"ROW", row)
    inventory = tmp_path / "inventory.json"
    inventory.write_bytes(raw)
    assert _read_inventory(inventory, digest(raw), count) is None


def test_oversized_cutover_inventory_row(tmp_path, capsys):
    inventory = {
        "chains": [
            {
                "chain": "0" * (1 << 20),
                "format": "action_v1",
                "record": digest(b""),
                "seq": 0,
            }
        ],
        "v": 1,
    }
    key = _v3_open_with_cutover(tmp_path, inventory, Ed25519PrivateKey.generate())
    assert main(["v3", "--key", key, "--output", "projection", str(tmp_path)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["verdict"] == "INVALID"
    assert result["finding_codes"] == ["CUTOVER_INVENTORY_MISMATCH"]


def test_mixed_group_directory(tmp_path):
    from pipelock_aarp_verify import verify_receipt_groups
    from pipelock_aarp_verify.legacy_directory import recorder_index
    from test_receipt_group import GROUP_ID, TRUSTED_KEYS, _extract_fixture

    root = _extract_fixture("group-valid", tmp_path)
    (group,) = verify_receipt_groups(root, TRUSTED_KEYS)
    assert group["verdict"] == "GROUP_VALID"
    assert recorder_index(root) and not recorder_index(root, exclude_groups=True)
    head = group["close_manifest_sha256"]
    inventory = {
        "v": 1,
        "chains": [
            {
                "chain": GROUP_ID,
                "format": "receipt_group",
                "seq": group["shard_count"],
                "record": head if head.startswith("sha256:") else "sha256:" + head,
            }
        ],
    }
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    v3_pub = _v3_open_with_cutover(root, inventory, key)
    options = V3Options(keys=(*TRUSTED_KEYS, v3_pub), directory=True, allow_prefix=True)
    full, projection = verify_v3([root], options)
    assert full["legacy"] == [
        {
            "chain": GROUP_ID,
            "format": "receipt_group",
            "class": "pass",
            "verdict": "GROUP_VALID",
        }
    ]
    assert projection["finding_codes"] == ["END_UNPROVEN"]
    assert projection["exit_code"] == 0

    (root / f"receipt-group-{GROUP_ID}-open.json").unlink()
    full, _ = verify_v3([root], options)
    assert full["exit_code"] == 1
    assert {row["format"] for row in full["legacy"]} == {"receipt_group"}
    assert "LEGACY_INVALID" in {finding["code"] for finding in full["findings"]}


def test_decision_prefix_inference_and_shape_rules():
    from pipelock_aarp_verify.v3.decision import _Piece, _shape

    hold = {"id": "hold"}
    correction = {
        "phase": "resolution",
        "verdict": "block",
        "effect_boundary": "approval_prompt",
        "effect_relation": "after",
        "hold": {**hold, "correction": True},
    }
    assert _shape(correction, False)
    assert not _shape({**correction, "hold": {**hold, "correction": False}}, False)
    piece = _Piece()
    assert piece.advance(correction, True) and piece.state == "blocked"
    assert not piece.advance(
        {**correction, "hold": {"id": "other", "correction": True}}, False
    )
    assert not piece.advance({"phase": "hold"}, False)

    ask = {
        "phase": "decision",
        "verdict": "ask",
        "effect_boundary": "hook_execution",
        "effect_relation": "before",
        "ask": {"channel": "host_prompt", "observed": False},
    }
    assert _shape(ask, False)
    assert not _shape({**ask, "ask": None}, False)
    assert not _shape({**ask, "verdict": "block"}, False)
    releasing = {**ask, "verdict": "allow", "ask": None}
    assert _shape(releasing, False)
    assert not _shape(releasing, True)
    assert not _shape({**releasing, "phase": "unregistered"}, False)

    last = {
        "phase": "outcome",
        "verdict": "allow",
        "effect_boundary": "response_delivery",
        "effect_relation": "after",
        "outcome_class": "completed",
        "attempt": 9007199254740991,
    }
    assert not _Piece().advance({**last, "effect_boundary": "none"}, True)
    piece = _Piece()
    assert piece.advance(last, True) and piece.state == "completed"
    assert not piece.advance({**last, "effect_boundary": "hook_execution"}, False)


def test_decision_limit_keeps_integrity_checks(monkeypatch):
    from pipelock_aarp_verify.v3.wire import LIMITS

    candidate = next(
        path
        for path in REQUESTS
        if any(
            b'"kind":"action"' in (path.parent / name).read_bytes()
            for name in json.loads(path.read_bytes())["inputs"]
            if (path.parent / name).stat().st_size < 16 * 1024
        )
        and json.loads((path.parent / "projection.json").read_bytes())["verdict"]
        == "VALID"
    )
    request = json.loads(candidate.read_bytes())
    monkeypatch.setitem(LIMITS, "decisions", 0)
    paths = [candidate.parent / name for name in request["inputs"]]
    result, _ = verify_v3(paths, _options(request))
    assert "L-DECISION-INDEX" in result["limits"]
    assert result["counts"] == {"scope": "not_appraised"}
    assert "DECISION_INDEX_FULL" in {f["code"] for f in result["findings"]}


def test_legacy_scope_error_and_recorder_discriminator(tmp_path):
    legacy = VECTORS / "g10-action-receipt-v1-single" / "action-receipt-v1-single.json"
    with pytest.raises(ValueError, match="legacy-only evidence"):
        verify_v3([legacy])
    path = _request_args("g08-pinned")[-1]
    jsonl = tmp_path / "legacy.jsonl"
    jsonl.write_bytes(canonical_v3(json.loads(legacy.read_bytes())) + b"\n")
    with pytest.raises(ValueError, match="require directory scope"):
        verify_v3([path, jsonl])
    with pytest.raises(ValueError, match="exactly one directory"):
        verify_v3([path, legacy], V3Options(directory=True))
    evidence = SDK / "conformance" / "testdata" / "g1-valid-chain.jsonl"
    with pytest.raises(ValueError, match="legacy-only evidence"):
        verify_v3([evidence])


def test_cli_help(capsys):
    assert main(["v3", "--help"]) == 0
    assert "--claims" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("value", "kind", "required", "want"),
    [
        ("0000-02-29T03:04:05.006Z", "time", True, True),
        ("2026-02-30T03:04:05.006Z", "time", True, False),
        ("2026-01-02T03:04:05.006+00:00", "time", True, False),
        (["bad"], "[]uint", True, False),
        ([], "[]uint", False, False),
        ("x", "unsupported_field_type", True, False),
        ("", "string", True, False),
    ],
)
def test_wire_type_constraints(value, kind, required, want):
    from pipelock_aarp_verify.v3.wire import match_field

    assert match_field(value, kind, required)[1] is want


def test_cutover_with_unknown_group_artifact(tmp_path):
    path = Path(_request_args("g08-pinned")[-1])
    shutil.copyfile(path, tmp_path / path.name)
    (tmp_path / "receipt-group-unknown.json").write_text("{}")
    result, _ = verify_v3([tmp_path], V3Options(directory=True))
    assert any(f["code"] == "LEGACY_INVALID" for f in result["findings"])


def test_directory_rejects_an_evidence_subdirectory(tmp_path):
    (tmp_path / "evidence-proxy-0.jsonl").mkdir()
    with pytest.raises(ValueError, match="not a regular file"):
        verify_v3([tmp_path], V3Options(directory=True))


@pytest.mark.parametrize("present", ["changed", "absent"])
def test_continuity_failure_is_reported_in_cutover(tmp_path, monkeypatch, present):
    from pipelock_aarp_verify.v3 import legacy

    fixture = VECTORS / "g09-writer-switch-rotated-legacy"
    request = json.loads((fixture / "request.json").read_bytes())
    for name in request["inputs"]:
        shutil.copyfile(fixture / name, tmp_path / name)
    balance = "RESTART CONTINUITY FAILED"
    if present == "changed":
        (path,) = tmp_path.glob("chain-link-*.json")
        path.write_text("{}")
    else:

        def unavailable(*args, **kwargs):
            raise OSError("directory unavailable")

        monkeypatch.setattr(legacy, "verify_base", unavailable)
        balance = "RESTART CONTINUITY INCOMPLETE"
    full, _ = verify_v3([tmp_path], _options(request))
    assert any(item["verdict"] == balance for item in full["legacy"])
    assert any(f["code"] == "LEGACY_INVALID" for f in full["findings"])


def test_partial_history_acceptance_requires_the_named_missing_predecessor():
    path = next(
        p
        for p in REQUESTS
        if json.loads(p.read_bytes()).get("finding") == "PREDECESSOR_NOT_PRESENTED"
        and not json.loads(p.read_bytes()).get("directory")
    )
    request = json.loads(path.read_bytes())
    report = json.loads((path.parent / "expect.json").read_bytes())
    stream = next(
        f["stream"]
        for f in report["findings"]
        if f["code"] == "PREDECESSOR_NOT_PRESENTED"
    )
    files = [path.parent / name for name in request["inputs"]]
    _, projection = verify_v3(
        files, V3Options(keys=tuple(request["keys"]), allow_partial_histories=(stream,))
    )
    assert projection["accepted"] == [
        {"kind": "allow-partial-history", "value": stream}
    ]
    assert "PREDECESSOR_NOT_PRESENTED" not in projection["finding_codes"]
    _, projection = verify_v3(
        files,
        V3Options(keys=tuple(request["keys"]), allow_partial_histories=("0" * 32,)),
    )
    assert "EXPECTATION_NOT_MET" in projection["finding_codes"]


def test_inventory_rows_reject_bad_identity_and_sequence():
    from pipelock_aarp_verify.v3.legacy import _valid_row

    row = {"format": "action_v1", "chain": "0" * 32, "seq": 0, "record": digest(b"row")}
    assert _valid_row(row)
    assert not _valid_row({**row, "seq": True})
    assert not _valid_row({**row, "seq": -1})
    assert not _valid_row({**row, "format": "receipt_group", "chain": digest(b"row")})
    assert not _valid_row({**row, "extra": "data"})


def test_parse_line_rejects_trailing_comma_after_max_signatures(tmp_path):
    from pipelock_aarp_verify.v3.wire import WireError, parse_line

    fixture = VECTORS / "g08-pinned"
    request = json.loads((fixture / "request.json").read_bytes())
    original = (fixture / request["inputs"][0]).read_bytes()
    lines = original.splitlines(keepends=True)
    first = lines[0]
    prefix = b'{"payloadType":"application/vnd.pipelock.receipt.v3+json","signatures":['
    marker = b'],"payload":'
    start = len(prefix)
    end = first.index(marker)
    signer_entry = first[start:end]
    # Extract the 88-byte base64 signature from the existing entry and construct
    # 4 distinct strictly sorted signature entries (LIMITS["signatures"] == 4).
    sig_part = signer_entry.split(b'","sig":"', 1)[1][:-2]
    signer_keyid = signer_entry[len(b'{"keyid":"') : len(b'{"keyid":"') + 71]
    entries = {signer_keyid: signer_entry}
    for byte in (b"0", b"1", b"2", b"3"):
        if len(entries) == 4:
            break
        kid = b"sha256:" + byte * 64
        if kid not in entries:
            entries[kid] = b'{"keyid":"' + kid + b'","sig":"' + sig_part + b'"}'
    four_sigs = b",".join(entries[k] for k in sorted(entries))
    valid_four = prefix + four_sigs + first[end:]
    trailing_comma = prefix + four_sigs + b"," + first[end:]

    # 4 valid sorted signatures parse cleanly.
    parse_line(valid_four)

    # A trailing comma after the 4th signature must fail closed with LINE_LAYOUT.
    with pytest.raises(WireError) as exc_info:
        parse_line(trailing_comma)
    assert str(exc_info.value) == "LINE_LAYOUT"

    out = tmp_path / request["inputs"][0]
    out.write_bytes(trailing_comma + b"".join(lines[1:]))
    _, proj = verify_v3([out], _options(request))
    assert proj["verdict"] == "INVALID"
    assert proj["exit_code"] == 1
    assert proj["finding_codes"] == ["LINE_LAYOUT"]


def test_filename_claimed_missing_or_directory_inputs_are_input_errors(tmp_path):
    good = Path(_request_args("g08-pinned")[-1])
    absent_v3 = tmp_path / "absent.receipt-v3.jsonl"
    absent_v4 = tmp_path / "absent.receipt-v4.jsonl"
    dir_v3 = tmp_path / "dir.receipt-v3.jsonl"
    dir_v3.mkdir()

    for argv in (
        ["v3", "--claims", str(absent_v3)],
        ["v3", "--claims", str(absent_v4)],
        ["v3", "--claims", str(dir_v3)],
        ["v3", str(absent_v3)],
        ["v3", str(absent_v4)],
        ["v3", str(good), str(absent_v3)],
        ["v3", str(good), str(absent_v4)],
        ["v3", str(good), str(dir_v3)],
    ):
        assert main(argv) == 2, argv


def test_bare_wrapper_replacement_is_not_excluded_from_restart(
    tmp_path, monkeypatch, capsys
):
    from pipelock_aarp_verify.v3 import legacy

    vector = (
        Path(__file__).resolve().parents[3]
        / "conformance/testdata/v3/g09-legacy-bare-evidence-under-run-name"
    )
    request = json.loads((vector / "request.json").read_bytes())
    for name in request["inputs"]:
        shutil.copyfile(vector / name, tmp_path / name)
    wrapper = tmp_path / "evidence-example.run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0.jsonl"
    args = ["v3", "--output", "projection", str(tmp_path)]
    for key in request["keys"]:
        args[1:1] = ["--key", key]

    def codes():
        main(args)
        return set(json.loads(capsys.readouterr().out)["finding_codes"])

    assert codes() == {"LEGACY_CHAIN_UNLISTED"}
    verify_base = legacy.verify_base

    def replace_then_verify(*arguments, **options):
        wrapper.write_bytes(b"not a recorder entry")
        return verify_base(*arguments, **options)

    monkeypatch.setattr(legacy, "verify_base", replace_then_verify)
    assert "LEGACY_INVALID" in codes()
