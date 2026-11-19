// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const sourceHistoryLeft, sourceHistoryRight = "Xk9mQ2vL7pR4", "Bn6Yc3Zd5Qa8"

type sourceHistoryContent struct {
	left, middle, right string
	overBudget          bool
}

// The pair-only search cannot assemble these fixtures across three fields.
// Each pair with the configured principal is shorter than a matching window.
// The v1 projection also omits standard HTTP methods.
func TestReceiptContentPairOnlyKnownLimitsWithFullSourceHistory(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		for _, middle := range []string{"local", http.MethodGet} {
			t.Run(version+"/"+middle, func(t *testing.T) {
				fixture := sourceHistoryContent{sourceHistoryLeft[:10], middle, sourceHistoryRight[:10], false}
				if err := emitReceiptWithFullSourceHistory(t, version, fixture); err != nil {
					t.Fatalf("pair-only scan refused the receipt: %v", err)
				}
			})
		}
	}
}

func TestReceiptContentRejectsPairMatchWithFullSourceHistory(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			fixture := sourceHistoryContent{sourceHistoryLeft, "local", sourceHistoryRight, false}
			err := emitReceiptWithFullSourceHistory(t, version, fixture)
			var rejection *receiptcontent.RejectionError
			if !errors.As(err, &rejection) || rejection.View != receiptcontent.ViewFragments || rejection.Pattern != "Environment Variable Leak" {
				t.Fatalf("receipt result = %v, want a fixed-value pair match", err)
			}
		})
	}
}

func TestReceiptContentRefusesOverBudgetWithFullSourceHistory(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			fixture := sourceHistoryContent{sourceHistoryLeft, "local", sourceHistoryRight, true}
			err := emitReceiptWithFullSourceHistory(t, version, fixture)
			var rejection *receiptcontent.RejectionError
			if !errors.As(err, &rejection) || rejection.View != receiptcontent.ViewBudget {
				t.Fatalf("receipt result = %v, want incomplete reconstruction", err)
			}
		})
	}
}

func emitReceiptWithFullSourceHistory(t *testing.T, version string, fixture sourceHistoryContent) error {
	t.Helper()
	whole := fixture.left + fixture.middle + fixture.right
	t.Setenv("PIPELOCK_TEST_RECEIPT_CONTENT_VALUE", whole)
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	if res := sc.ScanTextForDLPQuiet(t.Context(), whole); res.Err() != nil || res.Clean {
		t.Fatal("complete fixture must match")
	}
	r, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	policyHash := cfg.CanonicalPolicyHash()
	opts := receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: "forward",
		Method: http.MethodGet, Target: "https://api.vendor.example/data", PolicyHash: policyHash,
	}
	if version == "v1" {
		em := receipt.NewEmitter(receipt.EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: policyHash, Principal: "local", Actor: "pipelock"})
		for i := range 10 {
			opts.RecentTaintSources = append(opts.RecentTaintSources, session.TaintSourceRef{
				URL: fmt.Sprintf("https://api.vendor.example/source/%d", i), Kind: "fetch",
				Level: session.TaintExternalUntrusted, Timestamp: time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC), MatchReason: "external",
			})
		}
		if fixture.overBudget {
			for i := range opts.RecentTaintSources {
				opts.RecentTaintSources[i].MatchReason = strings.Repeat("ordinary text ", 2000)
			}
		} else {
			opts.SessionTaskLabel, opts.Agent = fixture.left, fixture.right
		}
		err = em.Emit(opts)
	} else {
		// V2 records policy sources rather than taint history, and has no
		// method field. Use the middle value as its configured principal.
		em := proxydecision.NewEmitter(proxydecision.EmitterConfig{
			Recorder: r, Signer: proxydecision.NewKeyedSigner(key), Principal: fixture.middle, Actor: "pipelock",
		})
		decision, ok := v2DecisionFromOpts(opts)
		if !ok {
			t.Fatal("decision fixture is invalid")
		}
		for i := range 10 {
			decision.PolicySources = append(decision.PolicySources, fmt.Sprintf("source-%d", i))
		}
		if fixture.overBudget {
			for i := range decision.PolicySources {
				decision.PolicySources[i] += strings.Repeat(" ordinary text", 2000)
			}
		} else {
			decision.Target = fixture.left
			decision.PolicySources[1] = fixture.right
		}
		err = em.Emit(decision)
	}
	return err
}

func TestReceiptWritersRefuseInterruptedContentScan(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			r, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, func(_ context.Context, text string) scanner.TextDLPResult {
				if strings.Contains(text, "interrupted-projection") {
					return scanner.TextDLPResult{Clean: true, Incomplete: true}
				}
				return scanner.TextDLPResult{Clean: true}
			}, key)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close() })
			hash := config.Defaults().CanonicalPolicyHash()
			opts := receipt.EmitOpts{
				ActionID: receipt.NewActionID(), Target: "https://api.vendor.example/interrupted-projection",
				Method: http.MethodGet, Transport: "forward", Verdict: config.ActionAllow, PolicyHash: hash,
			}
			if version == "v1" {
				em := receipt.NewEmitter(receipt.EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: hash, Principal: "local", Actor: "pipelock"})
				err = em.Emit(opts)
			} else {
				em := proxydecision.NewEmitter(proxydecision.EmitterConfig{Recorder: r, Signer: proxydecision.NewKeyedSigner(key), Principal: "local", Actor: "pipelock"})
				d, ok := v2DecisionFromOpts(opts)
				if !ok {
					t.Fatal("invalid decision fixture")
				}
				d.PolicySources = append(d.PolicySources, "interrupted-projection")
				err = em.Emit(d)
			}
			if !errors.Is(err, scanner.ErrTextDLPIncomplete) {
				t.Fatalf("%s receipt write accepted a partial scan: %v", version, err)
			}
		})
	}
}
