// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const legacyJournalName = "deferred-actions.jsonl"

func (w *StreamWriter) prepareCutover(ctx context.Context, keys []ed25519.PublicKey, entries []os.DirEntry) error {
	inventory, err := w.buildCutoverInventory(ctx, keys, entries)
	if err != nil {
		return err
	}
	body, err := canonicalJSON(inventory)
	if err != nil {
		return fmt.Errorf("encode legacy receipt inventory: %w", err)
	}
	pin := Cutover{Inventory: Digest(body), Chains: int64(len(inventory.Chains))}
	if err := w.storage.cleanup(w.dir, entries); err != nil {
		return err
	}
	if err := w.publishInventory(pin, body, entries); err != nil {
		return err
	}
	lineage, err := w.newStreamID()
	if err != nil {
		return err
	}
	w.open.Lineage = lineage
	w.open.LegacyCutover = &pin
	return nil
}

func (w *StreamWriter) buildCutoverInventory(ctx context.Context, keys []ed25519.PublicKey, entries []os.DirEntry) (Inventory, error) {
	journal, err := w.cutoverJournal()
	if err != nil {
		return Inventory{}, err
	}
	opts := Options{Directory: true, Keys: keys, AllowPrefix: true}
	files, paths, _, _, err := discover([]string{w.dir}, opts, "")
	if err != nil {
		return Inventory{}, err
	}
	if len(files) != 0 {
		return Inventory{}, errors.New("cannot switch evidence directory with an unexpected receipt profile")
	}
	// Discover the whole directory under the writer lock. Use the legacy
	// verifier's chain identities instead of the per-session inventory.
	v := verification{ctx: ctx, opts: opts, result: newResult(opts), used: map[string]bool{}}
	old, err := v.verifyLegacy(paths, nil)
	if err != nil {
		return Inventory{}, fmt.Errorf("verify legacy receipts before cutover: %w", err)
	}
	for _, finding := range v.result.Findings {
		if finding.Class == invalid || finding.Class == unsupported || finding.Class == incomplete {
			return Inventory{}, fmt.Errorf("receipt cutover refused %s while verifying legacy evidence", finding.Code)
		}
	}
	inventory := Inventory{Chains: make([]InventoryChain, 0, len(old)), Journal: journal, V: 1}
	for _, chain := range old {
		if chain.forked {
			return Inventory{}, errors.New("receipt cutover refused a forked legacy chain")
		}
		if !validLegacyRow(chain.InventoryChain) {
			return Inventory{}, errors.New("receipt cutover could not identify every legacy chain")
		}
		inventory.Chains = append(inventory.Chains, chain.InventoryChain)
	}
	// Legacy continuity and group verification read chain links separately.
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, receipt.ChainLinkFilePrefix) && strings.HasSuffix(name, receipt.ChainLinkFileSuffix) &&
			len(name) > len(receipt.ChainLinkFilePrefix)+len(receipt.ChainLinkFileSuffix) {
			paths = append(paths, filepath.Join(w.dir, name))
		}
	}
	// Flush legacy artifacts before a durable inventory can refer to them.
	for _, path := range paths {
		if err := w.storage.syncFile(path); err != nil {
			return Inventory{}, fmt.Errorf("flush legacy receipt artifact: %w", err)
		}
	}
	slices.SortFunc(inventory.Chains, compareLegacy)
	return inventory, nil
}

func (w *StreamWriter) publishInventory(pin Cutover, body []byte, entries []os.DirEntry) error {
	var existing bool
	for _, entry := range entries {
		id, ok := inventoryID(entry.Name())
		if !ok {
			continue
		}
		if !entry.Type().IsRegular() {
			return errors.New("receipt cutover inventory path is not a regular file")
		}
		path := filepath.Join(w.dir, entry.Name())
		if id == pin.Inventory && id != EmptyInventoryDigest() {
			_, code, err := readInventory(path, pin, "")
			if err != nil {
				return err
			}
			if code != "" {
				return fmt.Errorf("existing receipt cutover inventory failed verification (%s)", code)
			}
			existing = true
			continue
		}
		if err := w.storage.remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove stale receipt cutover inventory: %w", err)
		}
	}
	if pin.Inventory == EmptyInventoryDigest() {
		return nil
	}
	if existing {
		if err := w.storage.syncFile(filepath.Join(w.dir, InventoryFilename(pin.Inventory))); err != nil {
			return fmt.Errorf("re-flush cutover inventory: %w", err)
		}
		if err := w.storage.syncDir(w.dir); err != nil {
			return fmt.Errorf("re-flush cutover inventory directory: %w", err)
		}
		return nil
	}
	file, _, err := w.storage.publish(w.dir, InventoryFilename(pin.Inventory), body)
	if err != nil {
		return fmt.Errorf("publish receipt cutover inventory: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close receipt cutover inventory: %w", err)
	}
	return nil
}

func (w *StreamWriter) cutoverJournal() (string, error) {
	path := filepath.Join(w.dir, legacyJournalName)
	file, _, err := recorder.OpenEvidenceFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("open legacy defer journal: %w", err)
	}
	defer func() { _ = file.Close() }()
	journal, err := deferred.InspectJournalCutover(file)
	if err != nil {
		return "", err
	}
	if journal.Torn || journal.NeedsDelimiter {
		var prefix io.Reader = io.NewSectionReader(file, 0, journal.KeepBytes)
		if journal.NeedsDelimiter {
			prefix = io.MultiReader(prefix, strings.NewReader("\n"))
		}
		if err := w.repairJournal(path, prefix); err != nil {
			return "", err
		}
	}
	if journal.Pending != 0 {
		return "", fmt.Errorf("receipt cutover requires settling %d unresolved legacy holds", journal.Pending)
	}
	if !journal.Torn && !journal.NeedsDelimiter {
		if err := w.storage.syncFile(path); err != nil {
			return "", fmt.Errorf("flush legacy defer journal: %w", err)
		}
	}
	return journal.Digest, nil
}

func (w *StreamWriter) repairJournal(path string, prefix io.Reader) error {
	temp, err := w.storage.createTemp(w.dir, writerTempPrefix)
	if err != nil {
		return fmt.Errorf("create repaired defer journal: %w", err)
	}
	defer func() { _ = w.storage.remove(temp.Name()) }()
	if _, err := io.Copy(temp, prefix); err != nil {
		return errors.Join(fmt.Errorf("copy retained defer journal: %w", err), temp.Close())
	}
	if err := errors.Join(temp.Sync(), temp.Close()); err != nil {
		return fmt.Errorf("flush repaired defer journal: %w", err)
	}
	if err := w.storage.rename(temp.Name(), path); err != nil {
		return fmt.Errorf("replace torn defer journal: %w", err)
	}
	if err := w.storage.syncDir(w.dir); err != nil {
		return fmt.Errorf("flush repaired defer journal directory: %w", err)
	}
	return nil
}
