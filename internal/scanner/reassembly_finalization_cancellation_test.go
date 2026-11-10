// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyFinalizationCancellation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Marker", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	defer sc.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sc.dlpPatterns[0].validate = func(string) bool { cancel(); return false }
	body := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("x", 5000) + "MARK1234")))
	result := sc.ScanTextForDLP(ctx, body)
	if ctx.Err() == nil {
		t.Fatal("terminal validator was not reached")
	}
	if !result.Incomplete || result.Clean {
		t.Fatalf("finalization cancellation returned verified: %+v", result)
	}
}

// The late marker sits more than one context stride past the early marker.
// A canceled terminal may finish the stride already in progress. It must not
// screen the later marker, and it must not report that stop as an inspection limit.
func TestReassemblyFinalizationCancellationStops(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{
		{Name: "Early", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh},
		{Name: "Late", Regex: `LATE[0-9]{4}`, Severity: config.SeverityHigh},
	}
	sc := MustNew(cfg)
	defer sc.Close()
	payload := "MARK1234" + strings.Repeat("x", responseBodyContextCheckBytes) + "LATE5678"
	body := reassemblyBang(hex.EncodeToString([]byte(payload)))
	live := sc.ScanTextForDLP(t.Context(), body)
	if live.Incomplete || !hasPattern(live, "Early") || !hasPattern(live, "Late") {
		t.Fatalf("complete terminal missed a marker: %+v", live)
	}

	for _, tc := range []struct {
		name   string
		scan   func(context.Context, string) TextDLPResult
		shared bool
	}{
		{name: "outbound", scan: sc.ScanTextForDLP},
		{name: "inbound", scan: sc.ScanTextForDLPInbound},
		{name: "shared", scan: sc.ScanTextForDLP, shared: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			scanCtx := ctx
			release := func() {}
			if tc.shared {
				scanCtx, release = WithSharedDecodes(ctx)
			}
			lateCalls := 0
			var lateSeen []string
			for i := range sc.dlpPatterns {
				pattern := sc.dlpPatterns[i]
				switch pattern.name {
				case "Early":
					pattern.validate = func(string) bool { cancel(); return false }
				case "Late":
					pattern.validate = func(candidate string) bool {
						lateSeen = append(lateSeen, candidate)
						if candidate == "LATE5678" {
							lateCalls++
						}
						return false
					}
				}
			}
			t.Cleanup(func() {
				for i := range sc.dlpPatterns {
					sc.dlpPatterns[i].validate = nil
				}
			})
			result := tc.scan(scanCtx, body)
			release()
			if ctx.Err() == nil {
				t.Fatal("early terminal validator was not reached")
			}
			if lateCalls != 0 {
				t.Fatalf("terminal work continued after cancel: late validators=%d seen=%q", lateCalls, lateSeen)
			}
			if !result.Incomplete || result.Clean {
				t.Fatalf("cancellation returned verified: %+v", result)
			}
			for _, match := range append(result.Matches, result.InformationalMatches...) {
				if match.PatternName == PartialEncodedContentPattern || match.PatternName == UninspectableEncodedContentPattern {
					t.Fatalf("cancellation became an inspection-limit finding: %+v", result)
				}
			}
		})
	}

	again := sc.ScanTextForDLP(t.Context(), body)
	if again.Incomplete || !hasPattern(again, "Early") || !hasPattern(again, "Late") {
		t.Fatalf("canceled terminal cached as a verified negative: %+v", again)
	}
}

func TestReassemblyDrainStopsBeforeLaterView(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{
		{Name: "Early", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh},
		{Name: "Late", Regex: `LATE[0-9]{4}`, Severity: config.SeverityHigh},
	}
	sc := MustNew(cfg)
	defer sc.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	memo := &decodingMemo{reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true, scanCtx: ctx}
	memo.reassemblyObserve(reassemblyBang(hex.EncodeToString([]byte("MARK1234"))))
	memo.reassemblyObserve(reassemblyBang(hex.EncodeToString([]byte("LATE5678"))))
	lateCalls := 0
	for i := range sc.dlpPatterns {
		pattern := sc.dlpPatterns[i]
		switch pattern.name {
		case "Early":
			pattern.validate = func(string) bool { cancel(); return false }
		case "Late":
			pattern.validate = func(string) bool { lateCalls++; return false }
		}
	}
	memo.reassemblyDeferred = false
	memo.reassemblyDrain()
	if ctx.Err() == nil {
		t.Fatal("early view validator was not reached")
	}
	if lateCalls != 0 {
		t.Fatalf("later pending view was screened after cancel: validators=%d", lateCalls)
	}
	if memo.reassemblyIncomplete || memo.incomplete {
		t.Fatal("view stop was recorded as an inspection limit")
	}
}

// A repeated scan of ordinary text must take the same number of context
// checks. Terminal admission is cached after the first scan; a check inside
// that cached work would make cancellation checkpoints unreachable.
func TestRepeatedDLPScanContextChecksStayStable(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	defer sc.Close()
	for _, text := range []string{"ordinary message", "ordinary", "another", "ordinary%20mode"} {
		t.Run(text, func(t *testing.T) {
			first := &errCount{Context: t.Context()}
			second := &errCount{Context: t.Context()}
			if got := sc.ScanTextForDLP(first, text); !got.Clean || got.Incomplete {
				t.Fatalf("first scan = %+v", got)
			}
			if got := sc.ScanTextForDLP(second, text); !got.Clean || got.Incomplete {
				t.Fatalf("second scan = %+v", got)
			}
			if first.n != second.n {
				t.Fatalf("context checks changed after admission cache: first=%d second=%d", first.n, second.n)
			}
		})
	}
}

type errCount struct {
	context.Context
	n int
}

func (c *errCount) Err() error {
	c.n++
	return c.Context.Err()
}

func hasPattern(result TextDLPResult, name string) bool {
	for _, match := range result.Matches {
		if match.PatternName == name {
			return true
		}
	}
	return false
}
