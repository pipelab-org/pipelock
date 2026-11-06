// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestDLPKeywordsReceiptRedactionObligation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "account identifier", Regex: `[0-9]{16}`, Keywords: []string{"account"}}}
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
	rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	em := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: cfg.CanonicalPolicyHash(), Principal: testPrincipal, Actor: testActor})
	tmpl := Receipt{Version: ReceiptVersion, ActionRecord: em.contentRecord(baseOpts(), ActionRead, SideEffectNone, ReversibilityFull, cfg.CanonicalPolicyHash())}
	// The label is in the path and disappears when a URL is reduced to authority.
	// The already-detected hostname value must stay redacted after that reduction.
	tmpl.ActionRecord.Target = "https://3333333333333333.vendor.example/account"
	next, cs, err := em.scanActionContent(tmpl)
	if err != nil || cs == nil {
		t.Fatalf("receipt scan: %v", err)
	}
	if strings.Contains(next.ActionRecord.Target, "3333333333333333") {
		t.Fatal("context removal erased a redaction obligation")
	}
}

func TestDLPKeywordsEmitRedactionObligation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "account identifier", Regex: `serial[0-9]{6}`, Keywords: []string{"account"}}}
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
	for _, tc := range []struct {
		name, target string
		redacted     bool
	}{
		{"hostname label in path", "https://serial333333.vendor.example/account", true},
		{"unlabeled hostname", "https://serial333333.vendor.example/reference", false},
		{"ordinary target", "https://api.vendor.example/account/private?query=value", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: dir, Redact: true}, sc, key)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = rec.Close() })
			em := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: cfg.CanonicalPolicyHash(), Principal: testPrincipal, Actor: testActor})
			opts := baseOpts()
			opts.Target = tc.target
			opts.Method = http.MethodGet
			opts.RecentTaintSources = []session.TaintSourceRef{{URL: tc.target}}
			if err := em.Emit(opts); err != nil {
				t.Fatal(err)
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			recorded := readReceiptFromDir(t, dir, key.Public().(ed25519.PublicKey))
			if tc.redacted && strings.Contains(recorded.ActionRecord.Target, "serial333333") {
				t.Fatal("signed receipt retained a keyword-qualified hostname")
			}
			if tc.redacted && strings.Contains(recorded.ActionRecord.RecentTaintSources[0].URL, "serial333333") {
				t.Fatal("signed receipt retained a keyword-qualified source URL")
			}
			if !tc.redacted && recorded.ActionRecord.Target != sanitizeSignedTarget(tc.target, nil) {
				t.Fatalf("clean target reduction changed: %q", recorded.ActionRecord.Target)
			}
		})
	}
}
