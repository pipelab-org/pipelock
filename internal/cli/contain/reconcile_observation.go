// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// backupAndWrite preserves the previous rules in .bak before promoting a new
// identity. A crash before nft apply leaves that previous legacy block live.
// Headers only select candidate identities: nft(8) rule expressions must still
// match a complete ordered previous-renderer block before deletion is allowed.
// Missing or invalid backups confer no ownership and cannot block healthy runs.
func priorNFTRulesHeaders(read func(string) ([]byte, error), path string, persisted []byte) []nftRulesHeaderUIDs {
	bodies := [][]byte{persisted}
	if backup, err := read(path + ".bak"); err == nil {
		bodies = append(bodies, backup)
	}
	var prior []nftRulesHeaderUIDs
	for _, body := range bodies {
		if header, ok, err := parseNFTRulesHeaderUIDs(body); ok && err == nil && !slices.Contains(prior, header) {
			prior = append(prior, header)
		}
	}
	return prior
}

// Each observation retains a file's bytes and its read error. Unknown bytes
// never count as equality with desired state. Executors retain their existing
// backup, permission and error handling when applying a planned replacement.
type reconcileObservedFile struct {
	data []byte
	err  error
}

// snapshotReconcileReads belongs to observation, not planning. Inventory
// decoding, unit ownership checks and file comparisons share these same bytes
// before any write. The real reader remains available for post-apply checks.
func snapshotReconcileReads(read func(string) ([]byte, error)) (func(string) ([]byte, error), map[string]reconcileObservedFile) {
	files := make(map[string]reconcileObservedFile)
	return func(path string) ([]byte, error) {
		if file, ok := files[path]; ok {
			return file.data, file.err
		}
		data, err := read(path)
		data = append([]byte(nil), data...)
		files[path] = reconcileObservedFile{data, err}
		return data, err
	}, files
}

func observeManagedFilePlan(read func(string) ([]byte, error), files []reconcileManagedFile) error {
	var errs []error
	for _, file := range files {
		data, err := read(file.path)
		if err != nil {
			errs = append(errs, fmt.Errorf("post-apply managed file %s: %w", file.path, err))
			continue
		}
		if string(data) != file.body {
			errs = append(errs, fmt.Errorf("post-apply managed file %s does not match the reconciliation plan", file.path))
		}
	}
	return errors.Join(errs...)
}

// An install captures policy after promotion, when its first policy consumer
// runs. Copies of installEnv share this snapshot; backup/rollback reads retain
// the real reader. Expiry decisions use one instant for the whole install.
type containmentPolicySnapshot struct {
	data []byte
	err  error
	now  time.Time
	read bool
}

func observeInstallPolicy(env *installEnv) ([]byte, time.Time, error) {
	snapshot := env.policySnapshot
	if snapshot == nil {
		data, err := env.readFile(managedPipelockConfigPath(env))
		return data, time.Now(), err
	}
	if !snapshot.read {
		snapshot.data, snapshot.err = env.readFile(managedPipelockConfigPath(env))
		snapshot.data = append([]byte(nil), snapshot.data...)
		snapshot.now, snapshot.read = time.Now(), true
	}
	return snapshot.data, snapshot.now, snapshot.err
}

// observeNFTManagedChain shares the live observation contract for mutating
// reconciliation paths. nft(8) list chain prints the requested chain; a
// successful command with no content is unknown, not confirmed absence.
func observeNFTManagedChain(ctx context.Context, run runCommand, nftPath, table, chain string) (string, error) {
	live, code, err := run(ctx, nftPath, "-n", "-a", "list", "chain", "inet", table, chain)
	if err != nil {
		return "", fmt.Errorf("list nft managed chain: %w", err)
	}
	if code != 0 {
		if !nftOutputConfirmsAbsent(live) {
			return "", fmt.Errorf("list nft managed chain exit=%d: %s", code, oneLine(live))
		}
		return "", nil
	}
	if strings.TrimSpace(live) == "" {
		return "", errors.New("list nft managed chain returned an empty observation")
	}
	return live, nil
}
