# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
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
    core = request_path.parent / "projection.core.json"
    expected = (
        (core if core.exists() else request_path.parent / "projection.json")
        .read_bytes()
        .removesuffix(b"\n")
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


def test_legacy_cli_without_sqlite():
    script = """
import sys
sys.modules["_sqlite3"] = None
from pipelock_aarp_verify.cli import main

try:
    main(["receipt", "--help"])
except SystemExit as exc:
    assert exc.code == 0
sys.exit(main(["v3", *sys.argv[1:]]))
"""
    process = subprocess.run(
        [sys.executable, "-c", script, *_request_args("g08-pinned")],
        check=False,
        capture_output=True,
        text=True,
    )
    assert process.returncode == 2
    assert "usage:" in process.stdout
    assert "SQLite" in process.stderr
    assert "Traceback" not in process.stderr
    assert '"verdict"' not in process.stdout


def test_v3_predecessor_lookup_works_without_sqlite_json(monkeypatch):
    import sqlite3

    connect = sqlite3.connect

    def without_json(*args, **kwargs):
        db = connect(*args, **kwargs)

        def authorize(operation, _table, function, _database, _trigger):
            if operation == sqlite3.SQLITE_FUNCTION and function == "json_extract":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        db.set_authorizer(authorize)
        return db

    monkeypatch.setattr(sqlite3, "connect", without_json)
    request_path = next(
        path
        for path in REQUESTS
        if path.parent.name == "g04-absent-max-write-error-pin"
    )
    request = json.loads(request_path.read_bytes())
    paths = [request_path.parent / name for name in request["inputs"]]
    _, projection = verify_v3(paths, _options(request))
    assert (
        canonical_v3(projection) + b"\n"
        == (request_path.parent / "projection.json").read_bytes()
    )


def test_fork_scan_releases_decoded_contenders():
    import sqlite3
    from contextlib import closing

    from pipelock_aarp_verify.v3.verify import Verification, _Stream
    from pipelock_aarp_verify.v3.wire import Record

    class Contender(Record):
        alive = 0

        def __init__(self, index):
            super().__init__({"seq": 0, "stream": "example"}, str(index))
            Contender.alive += 1

        def __del__(self):
            Contender.alive -= 1

    class TrackedVerification(Verification):
        def walk(self, stream, limit=0):
            for index in range(10):
                assert Contender.alive <= 2
                yield Contender(index)

    with closing(sqlite3.connect(":memory:")) as db:
        verifier = TrackedVerification(db, V3Options(), 0)
        verifier.streams["example"] = _Stream()
        verifier.verify_streams()
        assert Contender.alive == 0
        assert verifier.result["contested_streams"] == [
            {"stream": "example", "records": [str(index) for index in range(10)]}
        ]
        assert len(verifier.result["findings"]) == 10


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
    if output == "projection":
        assert stdout.encode() == (VECTORS / vector / "projection.json").read_bytes()
    else:
        assert document["kind"] == "verify_result"
        assert "findings" in document and "finding_codes" not in document
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
    assert main(["v3", "--key", key, "--output", "projection", str(tmp_path)]) == 3
    result = json.loads(capsys.readouterr().out)
    assert result["verdict"] == "UNSUPPORTED"
    assert result["finding_codes"] == ["USE_HOST_VERIFIER"]


def test_ordinary_legacy_ignores_unrelated_symlink(tmp_path):
    vector = VECTORS / "g09-legacy-prefix"
    request = json.loads((vector / "request.json").read_bytes())
    for name in request["inputs"]:
        shutil.copyfile(vector / name, tmp_path / name)
    control, _ = verify_v3([tmp_path], _options(request))
    (tmp_path / "latest").symlink_to("missing")
    result, _ = verify_v3([tmp_path], _options(request))
    assert result["legacy"] == control["legacy"]
    assert result["findings"] == control["findings"]


def test_pending_hold_replay_retains_only_identity():
    from pipelock_aarp_verify.v3.decision import _Piece

    hold = "hold-" * 16384
    pending = {"phase": "hold", "hold": {"id": hold}}
    matching = {"phase": "resolution", "verdict": "allow", "hold": {"id": hold}}
    different = {**matching, "hold": {"id": hold + "other"}}
    piece = _Piece()
    assert piece.advance(pending, False)
    assert len(piece.hold) < 100
    assert not piece.advance(different, False)
    assert piece.advance(matching, False)
    inferred = _Piece()
    assert inferred.advance(matching, True)
    assert inferred.hold == piece.hold


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


@pytest.mark.parametrize("damage", [False, True])
def test_decision_limit_keeps_integrity_checks(monkeypatch, tmp_path, damage):
    from pipelock_aarp_verify.v3.wire import LIMITS

    vector = VECTORS / "g05-completed"
    request = json.loads((vector / "request.json").read_bytes())
    source = vector / request["inputs"][0]
    path = tmp_path / source.name
    path.write_bytes(source.read_bytes() + (b"torn tail" if damage else b""))
    monkeypatch.setitem(LIMITS, "decisions", 0)
    result, _ = verify_v3([path], _options(request))
    assert "L-DECISION-INDEX" in result["limits"]
    assert result["counts"] == {"scope": "not_appraised"}
    codes = {f["code"] for f in result["findings"]}
    assert "DECISION_INDEX_FULL" in codes
    if damage:
        assert "DATA_AFTER_CLOSE" in codes


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
    assert any(f["code"] == "USE_HOST_VERIFIER" for f in result["findings"])


def test_directory_rejects_an_evidence_subdirectory(tmp_path):
    (tmp_path / "evidence-proxy-0.jsonl").mkdir()
    with pytest.raises(ValueError, match="not a regular file"):
        verify_v3([tmp_path], V3Options(directory=True))


def test_directory_does_not_accept_a_nested_receipt_profile(tmp_path):
    name = "11111111111111111111111111111111-0000000000000000.receipt-v3.jsonl"
    shutil.copyfile(VECTORS / "g04-absent-max-write-error-pin" / name, tmp_path / name)
    leaf = tmp_path / "mid" / "leaf"
    leaf.mkdir(parents=True)
    shutil.copyfile(VECTORS / "g04-absent-max-write-error-pin" / name, leaf / name)
    with pytest.raises(ValueError, match="pipelock verify-receipt --chain") as caught:
        verify_v3([tmp_path], V3Options(directory=True, allow_unpinned=True))
    assert str(leaf) in str(caught.value)


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


def test_explicit_v3_treats_inventory_name_as_stream(tmp_path):
    from pipelock_aarp_verify.v3.verify import _discover

    path = tmp_path / ("receipt-v3-cutover-" + "a" * 64 + ".json")
    path.write_bytes(b"")
    files, legacy, inventories, _ = _discover([path], V3Options(explicit_v3=True))
    assert len(files) == 1
    assert not legacy
    assert not inventories


def test_resolution_rejects_empty_hold_id():
    from pipelock_aarp_verify.v3.decision import _Piece

    piece = _Piece()
    assert piece.advance({"phase": "hold", "hold": {"id": ""}}, False)
    assert not piece.advance(
        {"phase": "resolution", "verdict": "allow", "hold": {"id": ""}}, False
    )


@pytest.mark.parametrize("extra", ["chain-link-alone.json", "ael"])
def test_core_directory_defers_old_evidence(tmp_path, extra, capsys):
    name = "11111111111111111111111111111111-0000000000000000.receipt-v3.jsonl"
    shutil.copyfile(VECTORS / "g04-absent-max-write-error-pin" / name, tmp_path / name)
    if extra == "ael":
        (tmp_path / extra).mkdir()
    else:
        (tmp_path / extra).write_text("{}")
    result, _ = verify_v3([tmp_path], V3Options(directory=True, allow_unpinned=True))
    assert any(f["code"] == "USE_HOST_VERIFIER" for f in result["findings"])
    from pipelock_aarp_verify.v3.cli import run

    assert run(["--allow-unpinned", str(tmp_path)]) == 3
    assert "pipelock verify-receipt --chain <dir>" in capsys.readouterr().err


def test_hold_cardinality_does_not_fill_decision_index(monkeypatch):
    import sqlite3
    from collections import Counter
    from types import SimpleNamespace

    from pipelock_aarp_verify.v3.decision import _inspect_history
    from pipelock_aarp_verify.v3.wire import LIMITS

    monkeypatch.setitem(LIMITS, "decisions", 1)
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE hold_owners (id TEXT PRIMARY KEY, action_id TEXT)")
    db.execute(
        "CREATE TABLE bad_shapes (segment INTEGER, id TEXT, PRIMARY KEY(segment,id))"
    )
    records = []
    for hold in ("first", "second"):
        body = {
            "action_id": "decision",
            "phase": "hold",
            "verdict": "defer",
            "effect_boundary": "approval_prompt",
            "effect_relation": "before",
            "hold": {"id": hold},
        }
        records.append(
            SimpleNamespace(
                body_code=None,
                kind="action",
                fields={"body_v": 1},
                body=body,
                unknown=False,
            )
        )
    stream = SimpleNamespace(
        opening=SimpleNamespace(stream="s"),
        limit=2,
        body={"coverage": {"receipts_required": True}},
    )
    verification = SimpleNamespace(
        db=db, walk=lambda *_: iter(records), add=lambda *args, **kwargs: None
    )
    ids, future, full = _inspect_history(verification, [(True, [stream])], Counter())
    assert ids == {"decision": False}
    assert not future and not full
    assert db.execute("SELECT count(*) FROM hold_owners").fetchone()[0] == 2
    db.close()
