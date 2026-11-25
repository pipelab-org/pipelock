// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestLoadExpectedReceiptFormat(t *testing.T) {
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
	if err := checkReceiptFormat(dir, config.ReceiptFormatLegacy); err == nil || !strings.Contains(err.Error(), "--receipt-format legacy") {
		t.Fatalf("v3 evidence was accepted for legacy: %v", err)
	}
	var counts v3LoadCounts
	res, err := readLoadV3(t.Context(), dir, pub, &counts)
	if err != nil || res.Verdict != "VALID" || counts.actions != 1 || counts.blockDecisions != 1 {
		t.Fatalf("v3 verification: %+v, counts %+v: %v", res, counts, err)
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
	integrity := finishV3Integrity(t.Context(), options{}, dirs, plan, receiver, shutdownReport{Clean: true})
	if integrity.Verdict != verdictPass || integrity.Kinds["v3_block_decision"].Observed != 1 {
		t.Fatalf("integrity: %+v", integrity)
	}
	plan.blockOffset = 1
	integrity = finishV3Integrity(t.Context(), options{restartAfter: 1}, dirs, plan, receiver, shutdownReport{Error: "stop failed"})
	if integrity.Verdict != verdictFail || integrity.ReceiptMissing != 4 || len(integrity.Reasons) < 3 {
		t.Fatalf("integrity missed failed effects, sink or restart: %+v", integrity)
	}
	if err := os.MkdirAll(filepath.Join(dirs.recorder, "ael", "run"), 0o750); err != nil {
		t.Fatal(err)
	}
	integrity = finishV3Integrity(t.Context(), options{}, dirs, plan, receiver, shutdownReport{Clean: true})
	if integrity.Verdict != verdictFail || !strings.Contains(integrity.Verify.Output, "legacy agent event log") {
		t.Fatalf("unexpected mixed format result: %+v", integrity)
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

	tip := v3.Position{Record: "record", Seq: 13}
	streams := []v3.StreamResult{{Last: &tip}, {Last: &v3.Position{Record: "next", Seq: 14}}}
	if v3LoadContinues(nil, &tip) || v3LoadContinues(streams[:1], &tip) || v3LoadContinues(streams, nil) ||
		v3LoadContinues(streams, &v3.Position{Record: "different", Seq: 13}) || !v3LoadContinues(streams, &tip) {
		t.Fatal("restart tip was accepted without a verified successor, or was lost")
	}
}
