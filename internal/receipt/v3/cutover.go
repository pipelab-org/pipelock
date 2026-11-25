// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	verdict   string
	cliHead   string
	cliSeq    uint64
	session   string
	forked    bool
	rotated   bool
	position  int64
	positions map[int64]string
}

func (p legacyPresentation) compareCutoverPosition(row InventoryChain) int {
	if p.Record != row.Record && !p.forked {
		for position, observed := range p.positions {
			if position >= 0 && position < p.position && legacyHash(observed) == row.Record {
				return 1
			}
		}
		// A key rotation resets the signed sequence within the same chain, so
		// once the presented chain crosses one, a missing action digest cannot
		// be ordered by it. Without a rotation the order is reliable: a pin
		// beyond the presented tail is truncation, and a pin at or before it
		// that the chain never recorded is a different head.
		if p.Format == legacyAction && (p.rotated || p.Seq >= row.Seq) {
			return 0
		}
	}
	return cmp.Compare(p.Seq, row.Seq)
}

func (v *verification) verifyCutover(oldFiles []string, inventories map[string][]string, files []inputFile) (map[string]stagedRecord, error) {
	claimed := len(files) != 0
	var excluded map[string]bool
	if claimed && v.opts.Directory {
		excluded = make(map[string]bool, len(files))
		for _, file := range files {
			excluded[filepath.Base(file.path)] = true
		}
	}
	old, err := v.verifyLegacy(oldFiles, excluded)
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
			position := actual.compareCutoverPosition(row)
			switch {
			case v.skip != codeLegacyChainNotPresented && !presented:
				v.add(stream.open.finding(codeLegacyChainNotPresented))
			case v.skip != codeLegacyExtendedAfterCutover && position > 0:
				v.add(stream.open.finding(codeLegacyExtendedAfterCutover))
			case v.skip != codeLegacyChainTruncated && position < 0:
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
	if path == "" {
		switch {
		case pin.Inventory != EmptyInventoryDigest():
			if skip == codeCutoverInventoryNotPresented {
				return Inventory{}, codeCutoverInventoryMismatch, nil
			}
			return Inventory{}, codeCutoverInventoryNotPresented, nil
		case pin.Chains > 0:
			return Inventory{}, codeCutoverInventoryMismatch, nil
		default:
			return Inventory{Chains: []InventoryChain{}, V: 1}, "", nil
		}
	}
	file, err := openEvidence(path)
	if err != nil {
		return Inventory{}, "", fmt.Errorf("open cutover inventory: %w", err)
	}
	defer func() { _ = file.Close() }()
	return readInventoryFile(file, pin, skip)
}

func readInventoryFile(file io.ReadSeeker, pin Cutover, skip string) (Inventory, string, error) {
	checkDigest := skip != codeCutoverInventoryMismatch
	digest := sha256.New()
	if checkDigest {
		if _, err := io.Copy(digest, file); err != nil {
			return Inventory{}, "", fmt.Errorf("hash cutover inventory: %w", err)
		}
		if "sha256:"+hex.EncodeToString(digest.Sum(nil)) != pin.Inventory {
			return Inventory{}, codeCutoverInventoryMismatch, nil
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return Inventory{}, "", fmt.Errorf("rewind cutover inventory: %w", err)
		}
		digest.Reset()
	}
	inventory, canonical, valid := decodeInventory(io.TeeReader(file, digest), pin.Chains)
	// Bind both the parsed bytes and their canonical encoding to the pin.
	// The second hash catches edits between hashing and decoding.
	if !valid || checkDigest && (canonical != pin.Inventory || "sha256:"+hex.EncodeToString(digest.Sum(nil)) != pin.Inventory) {
		return Inventory{}, codeCutoverInventoryMismatch, nil
	}
	return inventory, "", nil
}

func decodeInventory(input io.Reader, chains int64) (Inventory, string, bool) {
	var inventory Inventory
	d := json.NewDecoder(input)
	h := sha256.New()
	token := func(want any) bool {
		got, err := d.Token()
		return err == nil && got == want
	}
	if !token(json.Delim('{')) || !token("chains") || !token(json.Delim('[')) {
		return Inventory{}, "", false
	}
	_, _ = io.WriteString(h, "{\"chains\":[")
	inventory.Chains = []InventoryChain{}
	// Only an inventory a stream pins is compared row by row. An unreferenced
	// one (chains < 0) is validated in constant memory: the ordering check needs
	// the previous row and the pin check needs the count.
	retain := chains >= 0
	var previous InventoryChain
	var n int64
	for d.More() {
		var row InventoryChain
		if err := d.Decode(&row); err != nil || !validLegacyRow(row) {
			return Inventory{}, "", false
		}
		if chains >= 0 && n >= chains || n > 0 && compareLegacy(previous, row) >= 0 {
			return Inventory{}, "", false
		}
		if n > 0 {
			_, _ = io.WriteString(h, ",")
		}
		// The row's fields appear in canonical order and valid values
		// contain only ASCII characters that need no escaping.
		_, _ = fmt.Fprintf(h, "{\"chain\":%q,\"format\":%q,\"record\":%q,\"seq\":%d}", row.Chain, row.Format, row.Record, row.Seq)
		previous = row
		n++
		if retain {
			inventory.Chains = append(inventory.Chains, row)
		}
	}
	if !token(json.Delim(']')) || chains >= 0 && n != chains {
		return Inventory{}, "", false
	}
	_, _ = io.WriteString(h, "]")
	key, err := d.Token()
	if err == nil && key == "journal" {
		if err := d.Decode(&inventory.Journal); err != nil || !isDigest(inventory.Journal) {
			return Inventory{}, "", false
		}
		_, _ = fmt.Fprintf(h, ",\"journal\":%q", inventory.Journal)
		key, err = d.Token()
	}
	if err != nil || key != "v" || d.Decode(&inventory.V) != nil || inventory.V != 1 || !token(json.Delim('}')) {
		return Inventory{}, "", false
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return Inventory{}, "", false
	}
	_, _ = io.WriteString(h, ",\"v\":1}")
	return inventory, "sha256:" + hex.EncodeToString(h.Sum(nil)), true
}

func compareLegacy(a, b InventoryChain) int {
	return cmp.Or(cmp.Compare(a.Format, b.Format), cmp.Compare(a.Chain, b.Chain))
}

func validLegacyRow(row InventoryChain) bool {
	if row.Seq < 0 || row.Seq > maxInteger || !isDigest(row.Record) {
		return false
	}
	switch row.Format {
	case legacyAction:
		return isDigest(row.Chain) || isLowerHex(row.Chain, 32)
	case legacyEvidence:
		return isDigest(row.Chain)
	case legacyGroup:
		return isLowerHex(row.Chain, 32)
	}
	return false
}

func sortLegacy(rows []LegacyResult) {
	slices.SortFunc(rows, func(a, b LegacyResult) int {
		return cmp.Or(cmp.Compare(a.Format, b.Format), cmp.Compare(a.Chain, b.Chain), cmp.Compare(a.Verdict, b.Verdict), cmp.Compare(a.Class, b.Class))
	})
}
