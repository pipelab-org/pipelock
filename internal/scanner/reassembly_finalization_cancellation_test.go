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
