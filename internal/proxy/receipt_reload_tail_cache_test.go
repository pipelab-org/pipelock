// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestReceiptReloadRejectsTamperInPreviouslyVerifiedShard covers a long-lived
// run: reload remembers the shards it validated, and a later reload must still
// refuse a change to any of them, even one that keeps the file's size.
func TestReceiptReloadRejectsTamperInPreviouslyVerifiedShard(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000, MaxEntriesPerFile: 2}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, Session: session, ConfigHash: "baseline", Principal: "local", Actor: "pipelock"})
	if err := e.InitError(); err != nil {
		t.Fatal(err)
	}
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "receipt.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FlightRecorder.SigningKeyPath = keyPath
	cfg.FlightRecorder.RequireReceipts = true
	p, err := New(cfg, audit.NewNop(), scanner.MustNew(cfg), metrics.New(), WithRecorder(rec), WithReceiptEmitter(e), WithReceiptKeyPath(keyPath), WithSession(session))
	if err != nil {
		t.Fatal(err)
	}
	for range 4 {
		p.recordDecision("allow", "test", "", "fetch", "request")
	}
	if !p.Reload(cfg, scanner.MustNew(cfg)) {
		t.Fatal("positive control reload rejected")
	}
	// A second reload over the unchanged run is served from the cache.
	if !p.Reload(cfg, scanner.MustNew(cfg)) {
		t.Fatal("unchanged run reload rejected")
	}
	files, err := filepath.Glob(filepath.Join(dir, "evidence-"+session+"-*.jsonl"))
	if err != nil || len(files) < 3 {
		t.Fatalf("want a multi-shard run, files=%v err=%v", files, err)
	}
	target := files[0]
	data, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte(`"hash":"`)
	at := bytes.Index(data, marker)
	if at < 0 {
		t.Fatal("no stored hash in the first shard")
	}
	at += len(marker)
	tampered := bytes.Clone(data)
	if tampered[at] == '0' {
		tampered[at] = '1'
	} else {
		tampered[at] = '0'
	}
	if err := os.WriteFile(target, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	old := p.receiptEmitterPtr.Load()
	for attempt := range 2 {
		if p.Reload(cfg, scanner.MustNew(cfg)) {
			t.Fatalf("reload %d accepted a tampered shard it had verified before", attempt)
		}
	}
	if p.receiptEmitterPtr.Load() != old || old.HealthError() == nil {
		t.Fatal("tamper left receipt admission healthy")
	}
}
