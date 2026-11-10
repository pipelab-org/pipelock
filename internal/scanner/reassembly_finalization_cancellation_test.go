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

func TestReassemblyFinalizationCancellationStops(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Marker", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	defer sc.Close()
	const marks = 30
	payload := strings.Repeat("x", 64) + strings.Repeat("MARK1234"+strings.Repeat("y", 32), marks)
	body := reassemblyBang(hex.EncodeToString([]byte(payload)))
	var cancel context.CancelFunc
	calls := 0
	sc.dlpPatterns[0].validate = func(string) bool {
		calls++
		cancel()
		return false
	}
	// A message that shares decoded views across its scans uses the other
	// matcher entry. Both have to stop on the same cancellation.
	for _, useShared := range []bool{false, true} {
		calls = 0
		ctx, cancelFn := context.WithCancel(t.Context())
		cancel = cancelFn
		scanCtx := ctx
		release := func() {}
		if useShared {
			scanCtx, release = WithSharedDecodes(ctx)
		}
		result := sc.ScanTextForDLP(scanCtx, body)
		release()
		cancel()
		if !result.Incomplete || result.Clean {
			t.Fatalf("shared=%v cancellation returned verified: %+v", useShared, result)
		}
		// One validator reaching cancel is enough. Later candidates are more
		// terminal replay, and they must not keep running after the context ends.
		if calls != 1 {
			t.Fatalf("shared=%v terminal replay continued after cancel: validators=%d", useShared, calls)
		}
	}
}
