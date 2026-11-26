# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

"""Name-only old evidence detection and empty cutover validation."""

from ..group import _parse_evidence_filename
from ..input_file import _open_regular_input
from .wire import digest

_EMPTY_BYTES = b'{"chains":[],"v":1}'
EMPTY_INVENTORY = digest(_EMPTY_BYTES)


# Go discovery: internal/receipt/v3/legacy.go:43, internal/receipt/chain_set.go:358,
# internal/ael/emitter.go:138 and internal/receipt/group_inventory.go:83.
def legacy_candidate(name: str) -> bool:
    return bool(
        _parse_evidence_filename(name)
        or name == "ael"
        or name.startswith("chain-link-")
        and name.endswith(".json")
        or name.startswith("receipt-group-")
        and name.endswith(".json")
        or name
        in (
            "activation-receipts.jsonl",
            "redaction-receipts.jsonl",
            "ratification-receipts.jsonl",
        )
    )


def _empty_inventory(path):
    with _open_regular_input(path) as source:
        return source.read(len(_EMPTY_BYTES) + 1) == _EMPTY_BYTES


def verify_empty_cutover(v, inventories, claimed):
    if not claimed:
        return {}
    checked = set()
    for stream in v.streams.values():
        cutover = stream.body.get("legacy_cutover")
        opener = stream.opening
        if not cutover or opener is None:
            continue
        pin, count = cutover["inventory"], cutover["chains"]
        checked.add(pin)
        paths = inventories.get(pin, ())
        if paths:
            for path in paths:
                if count != 0 or not _empty_inventory(path):
                    v.add("CUTOVER_INVENTORY_MISMATCH", record=opener)
        elif count != 0:
            v.add("CUTOVER_INVENTORY_MISMATCH", record=opener)
    for pin in sorted(inventories.keys() - checked):
        for path in inventories[pin]:
            if not _empty_inventory(path):
                v.add("CUTOVER_INVENTORY_MISMATCH")
    return {}
