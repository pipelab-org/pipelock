// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestWatchOnlySignedReceipt(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, verdict := range []string{config.ActionAllow, config.ActionWarn, config.ActionBlock} {
			dir := t.TempDir()
			pub, priv := generateTestKey(t)
			rec := newTestRecorder(t, dir, priv)
			t.Cleanup(func() { _ = rec.Close() })
			e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
			opts := WithWatchOnly(EmitOpts{ActionID: NewActionID(), Target: testTarget, Verdict: verdict, Transport: testTransport}, enabled)
			opts = WithWatchOnly(opts, !enabled)
			opts.Pattern = "final decision"
			if err := e.Emit(opts); err != nil {
				t.Fatal(err)
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			signed := readReceiptFromDir(t, dir, pub)
			if signed.ActionRecord.Verdict != verdict {
				t.Fatalf("observation changed real verdict: %s", signed.ActionRecord.Verdict)
			}
			pattern := signed.ActionRecord.Pattern
			if strings.Contains(pattern, "watch_only:") != enabled {
				t.Fatalf("mode missing or reload relabeled receipt: %q", pattern)
			}
			if enabled && (strings.Contains(pattern, "enforced in watch-only") != (verdict == config.ActionBlock)) {
				t.Fatalf("incorrect enforcement claim: %q", pattern)
			}
			if !enabled && pattern != opts.Pattern {
				t.Fatalf("unset mode changed signed record: %q", pattern)
			}
		}
	}
}

func TestWatchOnlyPatternComposesWithWordingPolicy(t *testing.T) {
	opts := WithWatchOnly(WithPromptInjectionMode(EmitOpts{}, config.ActionWarn), true)
	pattern := opts.PromptInjectionPattern("")
	if !strings.Contains(pattern, "watch_only: observation") || !strings.Contains(pattern, "wording warn-only") {
		t.Fatal(pattern)
	}
}
