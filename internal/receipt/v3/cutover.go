// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const emptyInventory = "{\"chains\":[],\"v\":1}"

// EmptyInventoryDigest is the pin used when neither legacy chains nor a
// deferred journal were present at cutover.
func EmptyInventoryDigest() string {
	return Digest([]byte(emptyInventory))
}

type InventoryChain struct {
	Chain  string `json:"chain"`
	Format string `json:"format"`
	Record string `json:"record"`
	Seq    int64  `json:"seq"`
}

type Inventory struct {
	Chains  []InventoryChain `json:"chains"`
	Journal string           `json:"journal,omitempty"`
	V       int              `json:"v"`
}

// InventoryFilename returns the content-addressed name for an inventory digest.
func InventoryFilename(id string) string {
	return "receipt-v3-cutover-" + strings.TrimPrefix(id, "sha256:") + ".json"
}

func inventoryID(name string) (string, bool) {
	tail, prefix := strings.CutPrefix(name, "receipt-v3-cutover-")
	hash, suffix := strings.CutSuffix(tail, ".json")
	return "sha256:" + hash, prefix && suffix && isLowerHex(hash, 64)
}

type legacyIdentity struct {
	format string
	chain  string
}

type legacyPresentation struct {
	InventoryChain
	verdict string
	cliHead string
	forked  bool
}

func (v *verification) verifyCutover(oldFiles []string, inventories map[string][]string, claimed bool) (map[string]stagedRecord, error) {
	old, err := v.verifyLegacy(oldFiles)
	if err != nil {
		return nil, err
	}
	if len(old) != 0 && claimed && !v.opts.Directory {
		return nil, fmt.Errorf("old-format and v3 evidence require directory scope; verify the directory")
	}
	unproven := map[string]stagedRecord{}
	if !claimed {
		return unproven, nil
	}
	checkedInventories := map[string]bool{}
	known := v.cutoverMembershipKnown()
	listed := map[legacyIdentity]bool{}
	for _, id := range sortedKeys(v.streams) {
		stream := v.streams[id]
		cutover := stream.body.LegacyCutover
		if cutover == nil {
			continue
		}
		checkedInventories[cutover.Inventory] = true
		paths := inventories[cutover.Inventory]
		if len(paths) == 0 {
			paths = []string{""}
		}
		var inventory Inventory
		for _, path := range paths {
			candidate, code, err := readInventory(path, *cutover, v.skip)
			if err != nil {
				return nil, err
			}
			if code != "" {
				v.add(stream.open.finding(code))
				continue
			}
			inventory = candidate
		}
		if inventory.Chains == nil {
			known = false
			continue
		}
		for _, row := range inventory.Chains {
			key := legacyIdentity{row.Format, row.Chain}
			listed[key] = true
			actual, presented := old[key]
			switch {
			case v.skip != codeLegacyChainNotPresented && !presented:
				v.add(stream.open.finding(codeLegacyChainNotPresented))
			case v.skip != codeLegacyExtendedAfterCutover && actual.Seq > row.Seq:
				v.add(stream.open.finding(codeLegacyExtendedAfterCutover))
			case v.skip != codeLegacyChainTruncated && actual.Seq < row.Seq:
				v.add(stream.open.finding(codeLegacyChainTruncated))
			case v.skip != codeLegacyChainHeadMismatch && (actual.forked || actual.Record != row.Record):
				v.add(stream.open.finding(codeLegacyChainHeadMismatch))
			case v.skip != codeLegacyEndUnproven && actual.verdict == prefixVerdict:
				unproven[stream.open.id] = stream.open
			}
		}
	}
	for _, id := range sortedKeys(inventories) {
		if checkedInventories[id] {
			continue
		}
		for _, path := range inventories[id] {
			_, code, err := readInventory(path, Cutover{Inventory: id, Chains: -1}, v.skip)
			if err != nil {
				return nil, err
			}
			if code != "" {
				v.addCode(code, "")
			}
		}
	}
	for key := range old {
		if listed[key] || known && v.skip == codeLegacyChainUnlisted || !known && v.skip == codeLegacyMembershipUnknown {
			continue
		}
		if known {
			v.addCode(codeLegacyChainUnlisted, "")
		} else {
			v.addCode(codeLegacyMembershipUnknown, "")
		}
	}
	return unproven, nil
}

func (v *verification) cutoverMembershipKnown() bool {
	if len(v.histories) == 0 {
		return false
	}
	roots := map[string]bool{}
	for lineage, members := range v.histories {
		for _, stream := range members {
			if stream.body.Previous == nil && stream.body.LegacyCutover != nil {
				roots[lineage] = true
			}
		}
		if !roots[lineage] {
			return false
		}
	}
	for _, candidates := range v.contested {
		for _, candidate := range candidates {
			if candidate.Kind != kindStreamOpen {
				continue
			}
			body, err := unmarshalBody[StreamOpen](candidate)
			if err != nil || candidate.unknown || body.Previous == nil || !roots[body.Lineage] {
				return false
			}
		}
	}
	return true
}

func readInventory(path string, pin Cutover, skip string) (Inventory, string, error) {
	data := []byte(emptyInventory)
	if path != "" {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return Inventory{}, "", fmt.Errorf("resolve cutover inventory: %w", err)
		}
		data, err = os.ReadFile(filepath.Clean(resolved))
		if err != nil {
			return Inventory{}, "", fmt.Errorf("read cutover inventory: %w", err)
		}
	} else if skip != codeCutoverInventoryNotPresented && pin.Inventory != EmptyInventoryDigest() {
		return Inventory{}, codeCutoverInventoryNotPresented, nil
	}
	if skip != codeCutoverInventoryMismatch && Digest(data) != pin.Inventory {
		return Inventory{}, codeCutoverInventoryMismatch, nil
	}
	var inventory Inventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		return Inventory{}, codeCutoverInventoryMismatch, nil
	}
	if !inventory.valid(pin.Chains) {
		return Inventory{}, codeCutoverInventoryMismatch, nil
	}
	canonical, err := canonicalJSON(inventory)
	if err != nil || skip != codeCutoverInventoryMismatch && !bytes.Equal(data, canonical) {
		return Inventory{}, codeCutoverInventoryMismatch, nil
	}
	return inventory, "", nil
}

func (i Inventory) valid(chains int64) bool {
	if i.V != 1 || i.Chains == nil || chains >= 0 && int64(len(i.Chains)) != chains ||
		i.Journal != "" && !isDigest(i.Journal) {
		return false
	}
	for index, row := range i.Chains {
		if !validLegacyRow(row) || index > 0 && compareLegacy(i.Chains[index-1], row) >= 0 {
			return false
		}
	}
	return true
}

func compareLegacy(a, b InventoryChain) int {
	return cmp.Or(cmp.Compare(a.Format, b.Format), cmp.Compare(a.Chain, b.Chain))
}

func validLegacyRow(row InventoryChain) bool {
	if row.Seq < 0 || row.Seq > maxInteger || !isDigest(row.Record) {
		return false
	}
	switch row.Format {
	case "action_v1":
		return isDigest(row.Chain) || isLowerHex(row.Chain, 32)
	case "evidence_v2":
		return isDigest(row.Chain)
	case "receipt_group":
		return isLowerHex(row.Chain, 32)
	}
	return false
}

func sortLegacy(rows []LegacyResult) {
	slices.SortFunc(rows, func(a, b LegacyResult) int {
		return cmp.Or(cmp.Compare(a.Format, b.Format), cmp.Compare(a.Chain, b.Chain), cmp.Compare(a.Verdict, b.Verdict), cmp.Compare(a.Class, b.Class))
	})
}
