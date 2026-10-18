// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestScanA2ABody_OverSizeCapFailsClosed(t *testing.T) {
	sc := scanner.MustNew(config.Defaults())
	defer sc.Close()
	cfg := &config.A2AScanning{Enabled: true, Action: config.ActionWarn}
	prefix := `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","messageId":"m","parts":[{"kind":"text","text":"`
	suffix := `"}]}}}`
	filler := strings.Repeat("hello world ", (a2aMaxScanBytes-len(prefix)-len(suffix))/12+1)
	body := []byte(prefix + filler + suffix)
	if len(body) <= a2aMaxScanBytes {
		t.Fatalf("test body %d bytes does not exceed cap %d", len(body), a2aMaxScanBytes)
	}
	r := scanA2ABody(context.Background(), body, sc, cfg, nil)
	if r.Clean || r.Action != config.ActionBlock || !r.InspectionIncomplete {
		t.Fatalf("over-cap body must block as incomplete under warn: clean=%v action=%q incomplete=%v reason=%q", r.Clean, r.Action, r.InspectionIncomplete, r.Reason)
	}
}
