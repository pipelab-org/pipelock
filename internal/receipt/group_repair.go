// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

// RepairReceiptGroupTransition completes a missing incoming transition for a
// stopped, terminal group. The opening must already bind every successor shard
// and those shards must have verifiable session opens and native logs.
func RepairReceiptGroupTransition(dir, groupID string, key ed25519.PrivateKey, priorSignerKeys []string, options verification.Options) (string, error) {
	return RepairReceiptGroupTransitionWithGuard(dir, groupID, key, priorSignerKeys, options, nil)
}

// RepairReceiptGroupTransitionWithGuard runs beforeAct under the exclusive
// ceremony lock before inspecting or mutating the evidence directory.
func RepairReceiptGroupTransitionWithGuard(dir, groupID string, key ed25519.PrivateKey, priorSignerKeys []string, options verification.Options, beforeAct func(string) error) (string, error) {
	trusted, err := TrustedGroupSignerKeys(EmitterConfig{PrivKey: key, PriorSignerKeys: priorSignerKeys})
	if err != nil {
		return "", err
	}
	openName, err := ReceiptGroupFileName(groupID, "open")
	if err != nil {
		return "", err
	}
	lock, err := recorder.AcquireEvidenceCeremonyLock(dir)
	if err != nil {
		return "", err
	}
	defer func() { _ = lock.Close() }()
	if beforeAct != nil {
		if err := beforeAct(dir); err != nil {
			return "", err
		}
	}

	open, openHash, err := readTopologicalGroupOpen(dir, openName, trusted)
	if err != nil {
		return "", err
	}
	if open.SignerKey != trusted[0] || open.PreviousGroupID == "" {
		return "", errors.New("transition repair requires a successor group and its opening private key")
	}
	terminal, found, err := FindTerminalReceiptGroup(dir, open.BaseSession, trusted)
	if err != nil {
		return "", err
	}
	if !found || terminal != groupID {
		return "", errors.New("transition repair requires the terminal receipt group")
	}
	name, _ := ReceiptGroupFileName(groupID, "transition")
	if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
		return "", errors.New("receipt group transition already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	previous, err := loadClosedGroupPredecessorWithOptions(dir, open.PreviousGroupID, trusted, options)
	if err != nil {
		return "", err
	}
	if previous.openHash != open.PreviousOpenManifestSHA256 {
		return "", errors.New("receipt group predecessor opening digest differs")
	}
	c := previous.ceremony
	for i := range open.Shards {
		if _, err := verifyGroupShardPrefixUsing(dir, open, openHash, i, c); err != nil {
			return "", fmt.Errorf("verify successor shard %d before transition repair: %w", i, err)
		}
	}
	if err := c.check(); err != nil {
		return "", err
	}
	set := &ReceiptShardSet{open: open, openHash: openHash, emitters: make([]*Emitter, len(open.Shards)), signer: key, previous: previous}
	c.successor = set
	if err := c.pinPublicationDirectories(previous); err != nil {
		return "", err
	}
	c.publicationInputs, err = fingerprintPublicationInputs(dir, set, false)
	if err != nil {
		return "", err
	}
	c.publicationArtifacts, err = fingerprintPublicationInputs(dir, set, true)
	if err != nil {
		return "", err
	}
	if err := options.Check(); err != nil {
		return "", err
	}
	c.published = true
	return set.writeTransition(dir)
}
