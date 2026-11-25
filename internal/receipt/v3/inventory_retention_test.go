// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"os"
	"path/filepath"
	"testing"
)

// An inventory no stream pins is validated without keeping its rows; a pinned
// one still returns them for the cutover comparison.
func TestUnreferencedInventoryIsValidatedWithoutRetainingRows(t *testing.T) {
	rows := []InventoryChain{
		{Chain: Digest([]byte("a")), Format: legacyAction, Record: Digest([]byte("x")), Seq: 1},
		{Chain: Digest([]byte("b")), Format: legacyAction, Record: Digest([]byte("y")), Seq: 2},
	}
	if compareLegacy(rows[0], rows[1]) > 0 {
		rows[0], rows[1] = rows[1], rows[0]
	}
	write := func(name string, chains []InventoryChain) (string, string) {
		raw, err := canonicalJSON(Inventory{V: 1, Chains: chains})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path, Digest(raw)
	}
	path, id := write("ordered.json", rows)
	pinned, code, err := readInventory(path, Cutover{Inventory: id, Chains: int64(len(rows))}, "")
	if err != nil || code != "" || len(pinned.Chains) != len(rows) {
		t.Fatalf("pinned inventory: %+v %q %v", pinned, code, err)
	}
	loose, code, err := readInventory(path, Cutover{Inventory: id, Chains: -1}, "")
	if err != nil || code != "" || loose.Chains == nil || len(loose.Chains) != 0 {
		t.Fatalf("unreferenced inventory kept its rows: %+v %q %v", loose, code, err)
	}
	path, id = write("unordered.json", []InventoryChain{rows[1], rows[0]})
	if _, code, err := readInventory(path, Cutover{Inventory: id, Chains: -1}, ""); err != nil || code != codeCutoverInventoryMismatch {
		t.Fatalf("unordered unreferenced inventory: %q %v", code, err)
	}
}
