// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/replaycapture"
)

// replayKitsCanary builds the synthetic canary at runtime to satisfy gosec G101.
const replayKitsCanary = "AKIA" + "IOSFODNN7EXAMPLE"

func replayKitsKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func writeReplayKitsJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// buildEndProvenReplayBundle captures a fresh scenario, whose audit packet ends
// with a session close, seals it as a delegated run, and archives it under a
// test root key. It returns the bundle and that root's public key.
func buildEndProvenReplayBundle(t *testing.T) ([]byte, string) {
	t.Helper()
	orchPub, orchPriv := replayKitsKey(t)
	colPub, colPriv := replayKitsKey(t)
	sessionPub, sessionPriv := replayKitsKey(t)

	engine, err := replaycapture.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var scenario replaycapture.Scenario
	for _, s := range replaycapture.DefaultScenarios() {
		if s.ID == "secret-exfil-url-blocked" {
			scenario = s
			break
		}
	}
	if scenario.ID == "" {
		t.Fatal("secret-exfil-url-blocked scenario not found")
	}
	captured, err := engine.Capture(scenario)
	if err != nil {
		t.Fatal(err)
	}

	runDir := t.TempDir()
	result, err := playground.AssembleFromEvidence(captured.EvidenceFile, engine.PublicKeyHex(), t.TempDir(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(result.PacketDir, filepath.Join(runDir, "packet")); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	lm := playground.LaunchManifest{
		RunNonce:        "replay-kits-nonce",
		ScenarioID:      scenario.ID,
		CanaryID:        "aws_canary",
		PipelockPubKey:  engine.PublicKeyHex(),
		CollectorPubKey: hex.EncodeToString(colPub),
		PolicyHash:      captured.PolicyHash,
		TargetHost:      "intake.lab.test",
		StartedAt:       now,
		DelegationID:    strings.Repeat("a", 64),
		ImageDigest:     "sha256:" + strings.Repeat("b", 64),
	}
	delegation, err := playground.SignOrchestratorDelegation(orchPriv, playground.OrchestratorDelegation{
		Format:           playground.OrchestratorDelegationFormat,
		RootKeyID:        playground.RootKeyID(orchPub),
		DelegationID:     lm.DelegationID,
		RunNonce:         lm.RunNonce,
		SessionPublicKey: hex.EncodeToString(sessionPub),
		ImageDigest:      lm.ImageDigest,
		IssuedAtUnix:     now.Unix(),
		NotBeforeUnix:    now.Add(-time.Minute).Unix(),
		ExpiresAtUnix:    now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	lm = playground.SignLaunchManifest(sessionPriv, lm)

	redCase, redWitness, err := playground.RunRedCaseCalibrationWithWitness(context.Background(), colPriv, "aws_canary", replayKitsCanary)
	if err != nil {
		t.Fatal(err)
	}
	collector := playground.NewCollector("aws_canary", replayKitsCanary)
	if err := collector.OpenRun(lm.RunNonce, lm.Hash()); err != nil {
		t.Fatal(err)
	}
	if err := collector.AttachRedCase(lm.RunNonce, redCase); err != nil {
		t.Fatal(err)
	}
	witness, err := collector.SealAndSign(lm.RunNonce, colPriv, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	writeReplayKitsJSON(t, filepath.Join(runDir, "launch-manifest.json"), lm)
	writeReplayKitsJSON(t, filepath.Join(runDir, "orchestrator-delegation.json"), delegation)
	writeReplayKitsJSON(t, filepath.Join(runDir, "witness.json"), witness)
	writeReplayKitsJSON(t, filepath.Join(runDir, "red-witness.json"), redWitness)

	bundle, err := playground.ArchiveRunForPublishedReplay(runDir, orchPriv)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, hex.EncodeToString(orchPub)
}
