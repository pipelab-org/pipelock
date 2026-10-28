// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"errors"
	"fmt"
	"time"
)

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
