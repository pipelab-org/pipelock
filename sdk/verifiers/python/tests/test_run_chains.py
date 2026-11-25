# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from pipelock_aarp_verify import chain_set, verify_base, verify_receipt_groups
from pipelock_aarp_verify.chain_set import load_rotation_endorsement
from pipelock_aarp_verify.legacy_directory import recorder_index

ROOT = Path(__file__).resolve().parents[3] / "conformance" / "testdata"
RUNS = ROOT / "run-chains"
KEY = (RUNS / "signer-key.hex").read_text().strip()
ROTATED = (RUNS / "rotated-signer-key.hex").read_text().strip()
CASES = sorted(RUNS.glob("*/expect*.json"))


@pytest.mark.parametrize("fixture", CASES, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_run_chain_matches_go(fixture):
    want = json.loads(fixture.read_bytes())
    keys = (KEY, ROTATED) if fixture.stem.endswith("both-keys") else (KEY,)
    endorsements = (
        (load_rotation_endorsement(fixture.parent / "rotation-endorsement.json"),)
        if fixture.stem.endswith("endorsed")
        else ()
    )
    report = verify_base(fixture.parent, "proxy", keys, endorsements=endorsements)
    assert report["healthy"] == want["healthy"]
    assert report["unlinked"] == want["unlinked"]
    assert [
        {k: row[k] for k in ("session", "valid")} for row in report["chains"]
    ] == want["chains"]
    assert [
        {
            "session": row["session"],
            "predecessor_session": row["link"]["predecessor_session"],
            "predecessor_tail_seq": row["link"]["predecessor_tail_seq"],
            "trust": row["link_trust"],
        }
        for row in report["chains"]
        if row["link"]
    ] == want["linked"]
    assert (
        sorted(
            ({k: f[k] for k in ("kind", "session")} for f in report["findings"]),
            key=lambda f: (f["kind"], f["session"]),
        )
        == want["findings"]
    )


@pytest.mark.parametrize("variant", ["valid", "rotated"])
def test_recovery_binds_damage(tmp_path, variant):
    fixture = ROOT / "recovery-seals" / variant
    directory = tmp_path / "evidence"
    shutil.copytree(fixture / "evidence", directory)
    keys = tuple((fixture / "signer.pub").read_text().split())
    seal = json.loads((fixture / "seal.json").read_bytes())
    report = verify_base(directory, "proxy", keys)
    assert not report["healthy"]
    assert any(f["kind"] == "attested_discontinuity" for f in report["findings"]), (
        report
    )
    assert seal["successor_session"] not in report["unlinked"]
    if variant == "rotated":
        assert not any(
            row["recovery_seal"]
            for row in verify_base(directory, "proxy", keys[:1])["chains"]
        )
    shard = directory / seal["shard"]
    with shard.open("ab") as file:
        file.write(b"x")
    report = verify_base(directory, "proxy", keys)
    assert any(f["kind"] == "invalid_recovery_seal" for f in report["findings"])
    assert seal["successor_session"] in report["unlinked"]


def test_moved_directory_fails_closed(tmp_path, monkeypatch):
    directory = tmp_path / "evidence"
    moved = tmp_path / "moved"
    shutil.copytree(RUNS / "valid", directory)
    read = chain_set.read_run

    def swap(*args, **kwargs):
        if not moved.exists():
            directory.rename(moved)
            shutil.copytree(moved, directory)
        return read(*args, **kwargs)

    monkeypatch.setattr(chain_set, "read_run", swap)
    report = verify_base(directory, "proxy", (KEY,))
    assert not report["healthy"]
    assert all(not row["valid"] for row in report["chains"])
    assert "evidence changed" in report["findings"][0]["detail"]


@pytest.mark.skipif(os.name != "posix", reason="Unix symlinks are required")
def test_symlinked_shard_fails_closed(tmp_path):
    directory = tmp_path / "evidence"
    shutil.copytree(RUNS / "valid", directory)
    shard = next(directory.glob("evidence-*.jsonl"))
    shard.unlink()
    shard.symlink_to(RUNS / "valid" / shard.name)
    report = verify_base(directory, "proxy", (KEY,))
    assert not report["healthy"]
    assert any("symlink" in f["detail"] for f in report["findings"])


def test_group_directory_and_exclusion(tmp_path):
    from test_receipt_group import GROUP_ID, TRUSTED_KEYS, _extract_fixture

    root = _extract_fixture("group-valid", tmp_path)
    rows = verify_receipt_groups(root, TRUSTED_KEYS)
    assert [(r["group_id"], r["verdict"]) for r in rows] == [(GROUP_ID, "GROUP_VALID")]
    assert recorder_index(root)
    assert recorder_index(root, exclude_groups=True) == {}
    (root / f"receipt-group-{GROUP_ID}-close.json").unlink()
    assert verify_receipt_groups(root, TRUSTED_KEYS)[0]["verdict"] == "GROUP_INCOMPLETE"
    (root / f"receipt-group-{GROUP_ID}-open.json").unlink()
    orphaned = verify_receipt_groups(root, TRUSTED_KEYS)
    assert orphaned and all(r["verdict"] == "GROUP_INVALID" for r in orphaned)
    ordinary = next((RUNS / "valid").glob("evidence-*.jsonl"))
    shutil.copyfile(ordinary, root / ordinary.name)
    assert len(recorder_index(root, exclude_groups=True)) == 1
    assert verify_base(root, "proxy", (KEY,), exclude_groups=True)["healthy"]
    (root / "receipt-group-unknown.json").write_text("{}")
    with pytest.raises(ValueError, match="unknown receipt group artifact"):
        verify_receipt_groups(root, TRUSTED_KEYS)


def test_shared_in_chain_rotations(tmp_path):
    source = ROOT / "g1-rotated-twice-valid.jsonl"
    target = tmp_path / "evidence-conformance-session-0.jsonl"
    shutil.copyfile(source, target)
    endorsements = tuple(
        load_rotation_endorsement(ROOT / f"g1-rotation-endorsement{suffix}.json")
        for suffix in ("", "-2")
    )
    home = (endorsements[0]["prior_signer_key"],)
    assert verify_base(
        tmp_path, "conformance-session", home, endorsements=endorsements
    )["healthy"]
    assert not verify_base(
        tmp_path, "conformance-session", home, endorsements=endorsements[:1]
    )["healthy"]
    assert not verify_base(
        tmp_path,
        "conformance-session",
        home,
        endorsements=(*endorsements, endorsements[0]),
    )["healthy"]
    with pytest.raises(ValueError, match="pinned root"):
        verify_base(tmp_path, "conformance-session", endorsements=endorsements)
    with pytest.raises(ValueError, match="invalid trusted key"):
        verify_base(tmp_path, "conformance-session", ("invalid",))


@pytest.mark.parametrize(
    "kind", ["missing-predecessor", "missing-successor", "oversized-link"]
)
def test_run_link_claim_errors(tmp_path, kind):
    shutil.copytree(RUNS / "valid", tmp_path, dirs_exist_ok=True)
    (claim,) = tmp_path.glob("chain-link-*.json")
    link = json.loads(claim.read_bytes())
    if kind == "oversized-link":
        claim.write_bytes(b" " * (65536 + 1))
        expected = "invalid_link"
    else:
        name = (
            "predecessor_session"
            if kind == "missing-predecessor"
            else "successor_session"
        )
        (tmp_path / f"evidence-{link[name]}-0.jsonl").unlink()
        expected = "dangling_link"
    report = verify_base(tmp_path, "proxy", (KEY,))
    assert not report["healthy"]
    assert expected in {f["kind"] for f in report["findings"]}


def test_group_inventory_change_is_unavailable(tmp_path, monkeypatch):
    from pipelock_aarp_verify import legacy_directory
    from test_receipt_group import TRUSTED_KEYS, _extract_fixture

    root = _extract_fixture("group-valid", tmp_path)
    verify = legacy_directory.verify_receipt_group

    def mutate(*args):
        result = verify(*args)
        (root / "new-file").touch()
        return result

    monkeypatch.setattr(legacy_directory, "verify_receipt_group", mutate)
    with pytest.raises(OSError, match="changed during verification"):
        verify_receipt_groups(root, TRUSTED_KEYS)


def test_recorder_shard_order_and_discriminator(tmp_path):
    from pipelock_aarp_verify.legacy_directory import read_legacy_file, read_run
    from pipelock_aarp_verify.receipt import ReceiptError

    valid = next((RUNS / "valid").glob("evidence-*.jsonl"))
    first, _, rest = valid.read_bytes().partition(b"\n")
    session = json.loads(first)["session_id"]
    original = tmp_path / f"evidence-{session}-0.jsonl"
    later = tmp_path / f"evidence-{session}-1.jsonl"
    original.write_bytes(first + b"\n")
    later.write_bytes(rest)
    assert not read_run(session, [(0, original), (1, later)]).outer_error
    with pytest.raises(ReceiptError, match="ambiguous"):
        read_run(session, [(0, original), (0, later)])
    with pytest.raises(ReceiptError, match="session binding"):
        read_run("other", [(0, original)])
    wrong = tmp_path / "evidence-other-0.jsonl"
    wrong.write_bytes(first + b"\n")
    with pytest.raises(ReceiptError, match="file name"):
        read_legacy_file(wrong)
    broken = json.loads(first)
    broken["summary"] = "updated"
    original.write_bytes(json.dumps(broken).encode() + b"\n")
    with pytest.raises(ReceiptError, match="hash mismatch"):
        read_legacy_file(original)


@pytest.mark.parametrize(
    ("content", "finding"),
    [(b"\n{}\n", "UNRECOGNIZED_FILE"), (b"{\n", "LEGACY_INVALID")],
)
def test_legacy_unreadable_content_is_a_finding(tmp_path, content, finding):
    from pipelock_aarp_verify import verify_v3

    path = tmp_path / "receipt.jsonl"
    path.write_bytes(content)
    (v3,) = (ROOT / "v3" / "g08-pinned").glob("*.receipt-v3.jsonl")
    full, _ = verify_v3([path, v3])
    assert {f["code"] for f in full["findings"]} == {finding}


def test_recovery_refuses_a_nonfinal_damaged_shard(tmp_path):
    fixture = ROOT / "recovery-seals" / "valid"
    shutil.copytree(fixture / "evidence", tmp_path, dirs_exist_ok=True)
    keys = tuple((fixture / "signer.pub").read_text().split())
    seal = json.loads((fixture / "seal.json").read_bytes())
    additional = tmp_path / f"evidence-{seal['predecessor_session']}-999.jsonl"
    additional.write_bytes(b"\n")
    report = verify_base(tmp_path, "proxy", keys)
    assert any(
        f["kind"] == "invalid_recovery_seal"
        and "final predecessor shard" in f["detail"]
        for f in report["findings"]
    )


def test_recovery_wrong_name_does_not_attach(tmp_path):
    fixture = ROOT / "recovery-seals" / "valid"
    shutil.copytree(fixture / "evidence", tmp_path, dirs_exist_ok=True)
    keys = tuple((fixture / "signer.pub").read_text().split())
    (path,) = tmp_path.glob("chain-link-*.json")
    path.rename(tmp_path / "chain-link-proxy.json")
    report = verify_base(tmp_path, "proxy", keys)
    assert any(f["kind"] == "invalid_recovery_seal" for f in report["findings"])
    assert all(r["recovery_seal"] is None for r in report["chains"])


def test_missing_rotation_link_does_not_corrupt_predecessor(tmp_path):
    fixture = RUNS / "key-rotated"
    shutil.copytree(fixture, tmp_path, dirs_exist_ok=True)
    endorsement = load_rotation_endorsement(tmp_path / "rotation-endorsement.json")
    (path,) = tmp_path.glob("chain-link-*.json")
    path.unlink()
    report = verify_base(tmp_path, "proxy", (KEY,), endorsements=(endorsement,))
    predecessor = next(
        row for row in report["chains"] if row["session"] == endorsement["session_id"]
    )
    assert predecessor["valid"] and predecessor["session"] in report["unlinked"]
    assert len(report["unlinked"]) == 2


def test_ambiguous_genesis_shard_has_no_healthy_verdict(tmp_path):
    shutil.copytree(RUNS / "valid", tmp_path, dirs_exist_ok=True)
    shard = next(tmp_path.glob("evidence-*.jsonl"))
    shutil.copyfile(shard, shard.with_name(shard.name.replace("-0.jsonl", "-00.jsonl")))
    result = verify_base(tmp_path, "proxy", (KEY,))
    assert not result["healthy"]
    assert any("ambiguous" in f["detail"] for f in result["findings"])


def test_recovery_suffix_starts_at_zero(tmp_path):
    shard = tmp_path / "evidence-proxy-0.jsonl"
    shard.write_bytes(b"{}\n")
    seal = {
        "predecessor_session": "proxy",
        "successor_session": "other",
        "predecessor_signer_key": "key",
        "successor_signer_key": "key",
        "shard": shard.name,
        "damage_offset": 0,
    }
    with pytest.raises(ValueError, match="tail contains a complete line"):
        chain_set._recovery({"proxy": [(0, shard)]}, set(), seal, None)


def test_invalid_recovery_timestamp_is_a_finding(tmp_path):
    fixture = ROOT / "recovery-seals" / "valid"
    shutil.copytree(fixture / "evidence", tmp_path, dirs_exist_ok=True)
    path = next(tmp_path.glob("chain-link-*.json"))
    seal = json.loads(path.read_bytes())
    seal["observed_at"] = "2026-13-01T00:00:00Z"
    path.write_bytes(chain_set._go_json(seal) + b"\n")
    keys = tuple((fixture / "signer.pub").read_text().split())
    result = verify_base(tmp_path, "proxy", keys)
    assert "invalid_recovery_seal" in {row["kind"] for row in result["findings"]}


def test_excluded_optional_group_close_is_absent(tmp_path):
    from pipelock_aarp_verify.group import (
        GROUP_INCOMPLETE,
        _recorder_file_exclusions,
        verify_receipt_group,
    )
    from test_receipt_group import GROUP_ID, TRUSTED_KEYS, _extract_fixture

    root = _extract_fixture("group-valid", tmp_path)
    close = f"receipt-group-{GROUP_ID}-close.json"
    marker = _recorder_file_exclusions.set(frozenset({close}))
    try:
        result = verify_receipt_group(root, GROUP_ID, TRUSTED_KEYS)
    finally:
        _recorder_file_exclusions.reset(marker)
    assert result["verdict"] == GROUP_INCOMPLETE


def test_contested_opening_with_nonstring_lineage_is_unknown_membership():
    from types import SimpleNamespace

    from pipelock_aarp_verify.v3.legacy import _membership_known
    from pipelock_aarp_verify.v3.verify import _Stream

    root = _Stream(body={"legacy_cutover": {}})
    invalid = SimpleNamespace(kind="stream_open", unknown=False, body={
        "previous": {},
        "lineage": [],
    })
    state = SimpleNamespace(histories={"a": [root]}, streams={
        "contested": _Stream(limit=-1, fork=[invalid]),
    })
    assert _membership_known(state) is False


def test_direct_rotation_endorsement_requires_supported_version(tmp_path):
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    prior = Ed25519PrivateKey.generate()
    successor = Ed25519PrivateKey.generate()
    key = prior.public_key().public_bytes_raw().hex()
    fields = {
        "version": 1,
        "session_id": "example",
        "prior_signer_key": key,
        "new_signer_key": successor.public_key().public_bytes_raw().hex(),
        "prior_final_seq": 0,
        "prior_tail_hash": "0" * 64,
        "rotated_at": "2026-01-01T00:00:00Z",
    }

    def endorsement(version):
        value = {**fields, "version": version}
        raw = chain_set._go_json({k: value[k] for k in chain_set._ROTATION_FIELDS})
        message = hashlib.sha256(b"pipelock-rotation-endorsement-v1\0" + raw)
        return {**value, "endorsement": "ed25519:" + prior.sign(message.digest()).hex()}

    verify_base(tmp_path, "example", (key,), endorsements=(endorsement(1),))
    with pytest.raises(ValueError, match="version"):
        verify_base(tmp_path, "example", (key,), endorsements=(endorsement(2),))
