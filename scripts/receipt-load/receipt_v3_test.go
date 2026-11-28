// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestLoadExpectedReceiptFormat(t *testing.T) {
	if err := checkReceiptFormat(filepath.Join(t.TempDir(), "missing"), config.ReceiptFormatV3); !os.IsNotExist(err) {
		t.Fatalf("missing recorder evidence: %v", err)
	}
	legacyDir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Dir: legacyDir, Enabled: true}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Record(recorder.Entry{SessionID: "proxy", Type: "action_receipt"}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if err := checkReceiptFormat(legacyDir, config.ReceiptFormatLegacy); err != nil {
		t.Fatal(err)
	}
	if err := checkReceiptFormat(legacyDir, config.ReceiptFormatV3); err == nil || !strings.Contains(err.Error(), "--receipt-format v3") {
		t.Fatalf("legacy evidence was accepted for v3: %v", err)
	}
	dir := t.TempDir()
	_, pub := testreceipt.V3(t, dir, false, blockedLoadAction())
	if _, err := readLoadV3(t.Context(), legacyDir, pub, new(v3LoadCounts)); err == nil || !strings.Contains(err.Error(), "--receipt-format v3") {
		t.Fatalf("legacy fallback was accepted: %v", err)
	}
	if err := checkReceiptFormat(dir, config.ReceiptFormatLegacy); err == nil || !strings.Contains(err.Error(), "--receipt-format legacy") {
		t.Fatalf("v3 evidence was accepted for legacy: %v", err)
	}
	var counts v3LoadCounts
	res, err := readLoadV3(t.Context(), dir, pub, &counts)
	if err != nil || res.Verdict != "VALID" || counts.actions != 1 || counts.blockDecisions != 1 {
		t.Fatalf("v3 verification: %+v, counts %+v: %v", res, counts, err)
	}
	visitErr := errors.New("action consumer stopped")
	_, err = v3.VerifyPathsWithActions(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: []ed25519.PublicKey{pub}}, func(v3.Action) error {
		return visitErr
	})
	if !errors.Is(err, visitErr) {
		t.Fatalf("verifier discarded action visitor error: %v", err)
	}
	if _, err := readLoadV3(t.Context(), dir, nil, new(v3LoadCounts)); err == nil {
		t.Fatal("unusable pin accepted")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readLoadV3(canceled, dir, pub, new(v3LoadCounts)); err == nil {
		t.Fatal("verified with a canceled context")
	}
	damaged := t.TempDir()
	_, pub = testreceipt.V3(t, damaged, true)
	counts = v3LoadCounts{}
	if _, err := readLoadV3(t.Context(), damaged, pub, &counts); err == nil || counts.actions != 0 {
		t.Fatalf("damaged evidence was counted: %+v: %v", counts, err)
	}
}

func blockedLoadAction() v3.Action {
	// A blocked request is one authenticated action decision with no attempt.
	return v3.Action{
		ActionID: "fixture-action", Phase: "decision", Verdict: "block",
		EffectBoundary: "upstream_send", EffectRelation: "not_attempted",
		Actor: "fixture", Principal: "local", Caller: v3.Caller{Authn: "none"},
		Transport: "forward", Target: "http://api.vendor.example/", Method: http.MethodGet,
		ActionType: "read", Data: v3.Data{SideEffectClass: "none", Reversibility: "not_applicable"},
	}
}

func TestV3LoadVerificationReport(t *testing.T) {
	dirs := newRunDirs(filepath.Join(t.TempDir(), "run"))
	if err := dirs.create(); err != nil {
		t.Fatal(err)
	}
	counts := new(v3LoadCounts)
	if report, _ := verifyLoadV3(t.Context(), dirs, counts); !report.Ran || report.Exit == 0 {
		t.Fatalf("missing signer key: %+v", report)
	}

	if err := os.Mkdir(dirs.keys, 0o750); err != nil {
		t.Fatal(err)
	}
	_, pub := testreceipt.V3(t, dirs.recorder, false, blockedLoadAction())
	if err := signing.SavePublicKey(pub, filepath.Join(dirs.keys, "flight-recorder-signing.key.pub")); err != nil {
		t.Fatal(err)
	}
	report, result := verifyLoadV3(t.Context(), dirs, counts)
	if !report.Ran || report.Exit != 0 || result.Verdict != "VALID" || !strings.Contains(report.Output, `"verdict":"VALID"`) {
		t.Fatalf("verification report: %+v", report)
	}
	plan := newWorkload(1, 0, 1)
	plan.blockOffset = 0
	receiver := &sink{plan: plan, seen: make([]atomic.Int32, plan.total())}
	integrity := finishV3Integrity(t.Context(), v3IntegrityRun{opt: options{}, dirs: dirs, plan: plan, sink: receiver, outcomes: []requestOutcome{{ran: true}}, shutdown: shutdownReport{Clean: true}})
	if integrity.Verdict != verdictPass || integrity.Kinds["v3_block_decision"].Observed != 1 {
		t.Fatalf("integrity: %+v", integrity)
	}
	for _, tc := range []struct {
		name           string
		warm, measured phaseResult
	}{
		{"warmup transport error", phaseResult{outcomes: []requestOutcome{{ran: true, transportErr: true}}}, phaseResult{}},
		{"warmup unexpected response", phaseResult{outcomes: []requestOutcome{{ran: true, bodyMismatch: true}}}, phaseResult{}},
		{"measured transport error", phaseResult{}, phaseResult{outcomes: []requestOutcome{{ran: true, transportErr: true}}}},
		{"measured unexpected response", phaseResult{}, phaseResult{outcomes: []requestOutcome{{ran: true, bodyMismatch: true}}}},
		{"body read error", phaseResult{}, phaseResult{outcomes: []requestOutcome{{ran: true, bodyReadErr: true}}}},
		{"not run", phaseResult{}, phaseResult{outcomes: []requestOutcome{{}}}},
		{"missing outcome", phaseResult{}, phaseResult{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := finishIntegrity(t.Context(), options{receiptFormat: config.ReceiptFormatV3}, modeBest, dirs, nil, plan, receiver, tc.warm, tc.measured, time.Time{}, shutdownReport{Clean: true}, nil)
			if got.Verdict != verdictFail {
				t.Fatalf("unexpected response accepted: %+v", got)
			}
		})
	}
	plan.blockOffset = 1
	integrity = finishV3Integrity(t.Context(), v3IntegrityRun{opt: options{restartAfter: 1}, dirs: dirs, plan: plan, sink: receiver, outcomes: []requestOutcome{{ran: true}}, shutdown: shutdownReport{Error: "stop failed"}})
	if integrity.Verdict != verdictFail || integrity.ReceiptMissing != 4 || len(integrity.Reasons) < 3 {
		t.Fatalf("integrity missed failed effects, sink or restart: %+v", integrity)
	}
	if err := os.MkdirAll(filepath.Join(dirs.recorder, "ael", "run"), 0o750); err != nil {
		t.Fatal(err)
	}
	integrity = finishV3Integrity(t.Context(), v3IntegrityRun{opt: options{}, dirs: dirs, plan: plan, sink: receiver, outcomes: []requestOutcome{{ran: true}}, shutdown: shutdownReport{Clean: true}})
	if integrity.Verdict != verdictFail || !strings.Contains(integrity.Verify.Output, "legacy agent event log") {
		t.Fatalf("unexpected mixed format result: %+v", integrity)
	}
	verifyPath := filepath.Join(dirs.root, "verify.txt")
	if err := os.Remove(verifyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(verifyPath, 0o750); err != nil {
		t.Fatal(err)
	}
	if report, _ := verifyLoadV3(t.Context(), dirs, counts); report.Exit == 0 || !strings.Contains(report.Output, "writing verify.txt") {
		t.Fatalf("missing report write failure: %+v", report)
	}
}

func TestV3LoadCountsAndRestartTip(t *testing.T) {
	var counts v3LoadCounts
	for _, boundary := range []string{"upstream_send", "downstream_delivery"} {
		for _, phase := range []string{"intent", "outcome"} {
			action := v3.Action{Transport: "forward", Method: http.MethodGet, EffectBoundary: boundary, Phase: phase, OutcomeClass: "completed"}
			if err := counts.add(action); err != nil {
				t.Fatal(err)
			}
		}
	}
	if counts.actions != 4 || counts.upstreamIntents != 1 || counts.upstreamEnds != 1 || counts.deliveryIntents != 1 || counts.deliveryEnds != 1 {
		t.Fatalf("counts: %+v", counts)
	}
	for _, action := range []v3.Action{
		{Transport: "forward", Method: http.MethodPost},
		{Transport: "forward", Method: http.MethodGet, Phase: "outcome", OutcomeClass: "attempt_unknown"},
	} {
		if err := counts.add(action); err == nil {
			t.Fatalf("unexpected action was accepted: %+v", action)
		}
	}

	before := v3.StreamResult{Stream: "stream-z", Last: &v3.Position{Record: "record", Seq: 13}}
	after := v3.StreamResult{Stream: "stream-a", Previous: before.Stream, Last: &v3.Position{Record: "next", Seq: 14}}
	streams := []v3.StreamResult{after, before}
	if tip := v3LoadTip(streams); tip == nil || tip.Stream != after.Stream {
		t.Fatalf("expected successor as history tip, got %+v", tip)
	}
	if v3LoadTip(nil) != nil || v3LoadContinues(nil, &before) || v3LoadContinues(streams[:1], &before) ||
		v3LoadContinues(streams[1:], &before) || v3LoadContinues(streams, nil) || !v3LoadContinues(streams, &before) {
		t.Fatal("restart tip was accepted without a verified successor, or was lost")
	}
	before.Last = &v3.Position{Record: "different", Seq: 13}
	if v3LoadContinues(streams, &before) {
		t.Fatal("changed pre-restart tip accepted")
	}
}

func TestLoadV3RequiresSingleHistory(t *testing.T) {
	dir := t.TempDir()
	_, pub := testreceipt.V3(t, dir, false)
	file, _ := testreceipt.V3(t, t.TempDir(), false)
	if err := os.Rename(file, filepath.Join(dir, filepath.Base(file))); err != nil {
		t.Fatal(err)
	}
	if _, err := readLoadV3(t.Context(), dir, pub, new(v3LoadCounts)); err == nil || !strings.Contains(err.Error(), "one verified history") {
		t.Fatalf("unrelated histories were accepted: %v", err)
	}
}
