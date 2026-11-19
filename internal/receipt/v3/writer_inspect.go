// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// InspectStartup checks whether a stopped v3 history is eligible for a
// restart. It takes the writer lock and verifies evidence without mutating it.
func InspectStartup(ctx context.Context, dir string, keys []ed25519.PublicKey) (_ Result, err error) {
	if len(keys) == 0 {
		return Result{}, errors.New("receipt startup inspection requires pinned public keys")
	}
	lock, err := recorder.AcquireEvidenceCeremonyLock(dir)
	if err != nil {
		return Result{}, fmt.Errorf("acquire exclusive receipt writer lock: %w", err)
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	present, err := DirectoryHasV3(dir)
	if err != nil {
		return Result{}, err
	}
	if !present {
		return Result{}, errors.New("directory has no v3 receipt stream")
	}
	var refusal error
	result, err := verifyPathsInspect(ctx, []string{dir}, Options{Directory: true, DiskIndex: true, Keys: keys}, "", func(v *verification) error {
		_, _, refusal = startupHead(v.result, v.actionVersionNeeded)
		return nil
	})
	return result, errors.Join(err, refusal)
}
