// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestInventoryGateRequiresPinnedOpening(t *testing.T) {
	_, ownerKey := generateTestKey(t)
	trustedPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	shards, err := OpenInitialReceiptShardSet(EmitterConfig{
		Recorder: rec, PrivKey: ownerKey, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor,
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, openHash := shards.Opening()
	gate := groupBinding(open, openHash, 0)
	if err := verifyInventoryGate(dir, open.Shards[0].SessionID, gate, []string{open.SignerKey}); err != nil {
		t.Fatalf("signed opening rejected with its pinned key: %v", err)
	}
	if err := verifyInventoryGate(dir, open.Shards[0].SessionID, gate, []string{fmt.Sprintf("%x", trustedPublic)}); err == nil {
		t.Fatal("opening signed by a foreign key was accepted")
	}
}

func TestGroupInventoryDoesNotClassifyUnterminatedFirstEntry(t *testing.T) {
	dir, groupID, signer, _ := writeRotatedRecoverySource(t)
	if result := VerifyReceiptGroup(dir, groupID, []string{signer}); result.Verdict != GroupValid {
		t.Fatalf("positive control: %+v", result)
	}
	name, err := ReceiptGroupFileName(groupID, "open")
	if err != nil {
		t.Fatal(err)
	}
	openBytes, err := readBoundedGroupFile(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	open, err := UnmarshalReceiptGroupOpen(openBytes, []string{signer})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+open.Shards[0].SessionID+"-*.jsonl"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("source shards=%v err=%v", paths, err)
	}
	entries, err := recorder.ReadEntries(paths[0])
	if err != nil || len(entries) == 0 {
		t.Fatalf("source entries=%v err=%v", entries, err)
	}
	session, err := recorder.NewRunSessionID(open.BaseSession)
	if err != nil {
		t.Fatal(err)
	}
	entry := entries[0]
	entry.Type = "request"
	entry.SessionID = session
	entry.Hash = recorder.ComputeHash(entry)
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "evidence-"+session+"-0.jsonl")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyGroupSessionInventory(dir, open); err == nil || !strings.Contains(err.Error(), "cannot be classified") {
		t.Fatalf("unterminated first entry used for classification: %v", err)
	}
	if result := VerifyReceiptGroup(dir, groupID, []string{signer}); result.Verdict == GroupValid {
		t.Fatalf("group authenticated an unterminated first entry: %+v", result)
	}
}

func TestReceiptGroupEvidencePresentDetectsGateWithoutManifest(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	set, err := OpenInitialReceiptShardSet(EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor,
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := set.Opening()
	if present, err := ReceiptGroupEvidencePresent(dir, 0); err != nil || !present {
		t.Fatalf("published group undetected: present=%v err=%v", present, err)
	}
	name, _ := ReceiptGroupFileName(open.GroupID, "open")
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	if present, err := ReceiptGroupEvidencePresent(dir, 0); err != nil || !present {
		t.Fatalf("gated shards without manifest undetected: present=%v err=%v", present, err)
	}
}

func TestReceiptGroupEvidencePresentBoundsLegacyDirectory(t *testing.T) {
	dir := t.TempDir()
	if present, err := ReceiptGroupEvidencePresent(dir, 1); err != nil || present {
		t.Fatalf("empty directory: present=%v err=%v", present, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "legacy-a"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if present, err := ReceiptGroupEvidencePresent(dir, 1); err != nil || present {
		t.Fatalf("directory at limit: present=%v err=%v", present, err)
	}
	for _, name := range []string{"legacy-a", "legacy-b"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ReceiptGroupEvidencePresent(dir, 1); !errors.Is(err, recorder.ErrEvidenceReadLimitExceeded) {
		t.Fatalf("unbounded directory accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stream.receipt-v3.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReceiptGroupEvidencePresent(dir, 1); !errors.Is(err, recorder.ErrEvidenceReadLimitExceeded) {
		t.Fatalf("unbounded refusal scan: %v", err)
	}
}

func TestVerifyBaseRefusesProfileAddedDuringVerification(t *testing.T) {
	src := filepath.Join(walkConformanceTestdata, "run-chains", "valid")
	dir := copyShardDir(t, src)
	previous := betweenVerificationReads
	betweenVerificationReads = func(string) {
		if err := os.WriteFile(filepath.Join(dir, "stream.receipt-v3.jsonl"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { betweenVerificationReads = previous })
	_, err := VerifyBase(dir, "proxy", BaseVerifyOptions{TrustedKeys: corpusKeys(src)})
	if !errors.Is(err, recorder.ErrLegacyEvidenceFormat) {
		t.Fatalf("VerifyBase error = %v", err)
	}
}

// A receipt v3 file and a growing legacy shard in the same verification
// window: the inventory change must not clear the receipt-format refusal.
func TestVerifyBaseKeepsProfileRefusalWhenShardAlsoChanges(t *testing.T) {
	src := filepath.Join(walkConformanceTestdata, "run-chains", "valid")
	dir := copyShardDir(t, src)
	shards, err := filepath.Glob(filepath.Join(dir, "evidence-proxy.run.*.jsonl"))
	if err != nil || len(shards) == 0 {
		t.Fatalf("legacy shards: %v %v", shards, err)
	}
	previous := betweenVerificationReads
	betweenVerificationReads = func(string) {
		if err := os.WriteFile(filepath.Join(dir, "stream.receipt-v3.jsonl"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(filepath.Clean(shards[0]), os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := f.WriteString("\n")
		if closeErr := f.Close(); writeErr != nil || closeErr != nil {
			t.Fatalf("append: %v %v", writeErr, closeErr)
		}
	}
	t.Cleanup(func() { betweenVerificationReads = previous })
	report, err := VerifyBase(dir, "proxy", BaseVerifyOptions{TrustedKeys: corpusKeys(src)})
	if !errors.Is(err, recorder.ErrLegacyEvidenceFormat) {
		t.Fatalf("VerifyBase error = %v", err)
	}
	if report.Healthy() {
		t.Fatal("changed inventory reported healthy")
	}
}
