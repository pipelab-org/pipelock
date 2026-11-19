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

func TestReceiptContentWithFullSourceHistory(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		for _, bridge := range []string{"local", http.MethodGet} {
			t.Run(version+"/"+bridge, func(t *testing.T) {
				testReceiptContentWithSources(t, version, bridge, false)
			})
		}
		t.Run(version+"/incomplete", func(t *testing.T) {
			testReceiptContentWithSources(t, version, "local", true)
		})
	}
}

func testReceiptContentWithSources(t *testing.T, version, bridge string, incomplete bool) {
	t.Helper()
	const left, right = "Xk9mQ2vL7pR4", "Bn6Yc3Zd5Qa8"
	t.Setenv("PIPELOCK_TEST_RECEIPT_CONTENT_VALUE", left+bridge+right)
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
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
		if incomplete {
			for i := range opts.RecentTaintSources {
				opts.RecentTaintSources[i].MatchReason = strings.Repeat("ordinary text ", 2000)
			}
		} else {
			opts.SessionTaskLabel, opts.Agent = left, right
		}
		err = em.Emit(opts)
	} else {
		// V2 records policy sources rather than taint history, and has no
		// method field. Bind the bridge value as retained producer content.
		em := proxydecision.NewEmitter(proxydecision.EmitterConfig{
			Recorder: r, Signer: proxydecision.NewKeyedSigner(key), Principal: bridge, Actor: "pipelock",
		})
		decision, ok := v2DecisionFromOpts(opts)
		if !ok {
			t.Fatal("decision fixture is invalid")
		}
		for i := range 10 {
			decision.PolicySources = append(decision.PolicySources, fmt.Sprintf("source-%d", i))
		}
		if incomplete {
			for i := range decision.PolicySources {
				decision.PolicySources[i] += strings.Repeat(" ordinary text", 2000)
			}
		} else {
			decision.Target = left
			decision.PolicySources[1] = right
		}
		err = em.Emit(decision)
	}
	var rejection *receiptcontent.RejectionError
	if !errors.As(err, &rejection) {
		t.Fatalf("receipt result = %v, want content refusal", err)
	}
	if incomplete && rejection.View != receiptcontent.ViewBudget {
		t.Fatalf("receipt result = %v, want incomplete reconstruction", err)
	}
	if !incomplete && rejection.Pattern != "Environment Variable Leak" && rejection.View != receiptcontent.ViewBudget {
		t.Fatalf("receipt result = %v, want detection or incomplete reconstruction", err)
	}
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
