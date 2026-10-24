// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestPromptInjectionDetectionSignedReceipt(t *testing.T) {
	for _, mode := range []string{config.ActionBlock, config.ActionWarn, config.ActionAllow} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			pub, priv := generateTestKey(t)
			rec := newTestRecorder(t, dir, priv)
			t.Cleanup(func() { _ = rec.Close() })
			e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
			opts := WithPromptInjectionMode(EmitOpts{ActionID: NewActionID(), Target: testTarget, Verdict: config.ActionAllow, Transport: testTransport}, mode)
			// An outcome can replace Pattern after binding; a later reload must not
			// relabel either the policy or the final outcome reason.
			opts.Pattern = "outcome complete"
			opts = WithPromptInjectionMode(opts, config.ActionBlock)
			if err := e.Emit(opts); err != nil {
				t.Fatal(err)
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			signed := readReceiptFromDir(t, dir, pub) // verifies signature
			pattern := signed.ActionRecord.Pattern
			if !strings.HasPrefix(pattern, "outcome complete") {
				t.Fatalf("lost outcome: %q", pattern)
			}
			if strings.Contains(pattern, "prompt_injection_detection") != (mode != config.ActionBlock) {
				t.Fatalf("policy missing or default changed: %q", pattern)
			}
			if mode == config.ActionAllow && !strings.Contains(pattern, "wording disabled") {
				t.Fatal(pattern)
			}
			if mode == config.ActionWarn && !strings.Contains(pattern, "wording warn-only") {
				t.Fatal(pattern)
			}
		})
	}
}
