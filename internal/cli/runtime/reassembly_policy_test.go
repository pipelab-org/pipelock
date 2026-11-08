// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestReassemblyPolicyPartialAuditReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("large allowance witness")
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := rec.Close(); err != nil {
			t.Error(err)
		}
	})
	emitter := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: runtimeTestPolicyHash, Actor: "test-agent"})
	var log bytes.Buffer
	logger, err := audit.NewWithStream("json", "custom", "", true, true, &log)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = nil
	for _, pattern := range config.DefaultDLPPatterns() {
		if pattern.Name == "AWS Access ID" {
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, pattern)
		}
	}
	if len(cfg.DLP.Patterns) != 1 {
		t.Fatal("AWS control absent")
	}
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	sc.SetDLPWarnHook(func(ctx context.Context, name, severity string) {
		emitDLPWarn(logger, nil, emitter, ctx, name, severity)
	})
	body := strings.Repeat("30", 1<<22) + strings.Repeat("!0", 80)
	ctx := scanner.WithDLPWarnContext(t.Context(), scanner.DLPWarnContext{Transport: "mcp_http", Resource: "tools/call", RequestID: "partial-scan", Agent: "test-agent", PolicyHash: runtimeTestPolicyHash})
	r := sc.ScanTextForDLPInbound(ctx, body)
	if !r.Clean || r.Incomplete || !scanner.OnlyInformational(r.Matches) || scanner.HasInspectionLimit(r.Matches) {
		t.Fatal("partial inbound became refusal or silent success", r)
	}
	entries, err := recorder.QuerySession(dir, "proxy", &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries.Entries) == 0 {
		t.Fatal("partial signal lost receipt")
	}
	for _, entry := range entries.Entries {
		b, err := json.Marshal(entry.Detail)
		if err != nil {
			t.Fatal(err)
		}
		r, err := receipt.Unmarshal(b)
		if err != nil {
			t.Fatal(err)
		}
		if r.ActionRecord.Pattern != scanner.PartialEncodedContentPattern || r.ActionRecord.Verdict != config.ActionWarn {
			t.Fatal("partial signal receipt misclassified", r.ActionRecord)
		}
		if err := receipt.VerifyWithKey(r, hex.EncodeToString(pub)); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(log.String(), scanner.PartialEncodedContentPattern) || !strings.Contains(log.String(), `"event":"dlp_warn"`) {
		t.Fatal("partial signal audit event absent", log.String())
	}
}
