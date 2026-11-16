// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestCheckSessionTailCachedRefusesSplicedV2Chain(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir()}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	const session = "proxy"
	newEmitter := func() *proxydecision.Emitter {
		return proxydecision.NewEmitter(proxydecision.EmitterConfig{Recorder: rec, Signer: proxydecision.NewKeyedSigner(key), Principal: "local", Actor: "pipelock", Session: session})
	}
	emit := func(e *proxydecision.Emitter) {
		t.Helper()
		if err := e.Emit(proxydecision.Decision{ActionType: "http_request", Transport: "forward", Target: "https://api.vendor.example/resource", Verdict: "allow", WinningSource: proxydecision.SourceScanner, PolicySources: []string{proxydecision.SourceScanner}, PolicyHash: "sha256:" + strings.Repeat("0", 64)}); err != nil {
			t.Fatal(err)
		}
	}
	keys := []string{fmt.Sprintf("%x", key.Public())}
	var cache receipt.TailCheckCache

	first := newEmitter()
	emit(first)
	emit(first)
	if err := receipt.CheckSessionTailCached(rec, session, keys, &cache); err != nil {
		t.Fatalf("intact v2 chain refused: %v", err)
	}

	// A second producer starts its own chain in the same run. Each of its
	// receipts is validly signed and the recorder chain still links; only the
	// v2 receipt chain shows the splice.
	emit(newEmitter())
	err = receipt.CheckSessionTailCached(rec, session, keys, &cache)
	if err == nil || !strings.Contains(err.Error(), "v2 receipt chain mismatch") {
		t.Fatalf("spliced v2 chain: %v, want a v2 chain mismatch", err)
	}
}
